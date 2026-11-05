"""SIMK read and programming operations shared by the CLI and GUI."""

from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from gkbus.exceptions import GkbusException, TimeoutException
from gkbus.protocol import kwp2000

from ecu_definitions import AccessLevel, ReprogrammingStatus, Routine
from .ecu import ECU, read_ecu_identification
from .memory import dynamic_find_end, read_memory, write_memory
from .utils import byte_progress, log, strip_identifier


@dataclass(frozen=True)
class FlashBlock:
    name: str
    address: int
    data: bytes
    erase_routine: Routine


class SimkOperations:
    """Own SIMK operation logic; the caller owns the connection and user prompts."""

    def __init__(self, ecu: ECU, log_callback=None, progress_factory=None, phase_callback=None):
        self.ecu = ecu
        self.log_callback = log_callback
        self.progress_factory = progress_factory
        self.phase_callback = phase_callback

    def _log(self, message):
        log(message, self.log_callback)

    def _progress(self, total, title):
        callback = self.progress_factory(total) if self.progress_factory else None
        return byte_progress(total, title, callback)

    def _phase(self, name, active):
        if self.phase_callback:
            self.phase_callback(name, active)

    def _read_filename(self, start, stop):
        try:
            hardware = [strip_identifier(read_ecu_identification(self.ecu.bus, identifier).decode('ascii'))
                        for identifier in (0x8C, 0x8D)]
            return '{}_{}_{}_{}_{}.bin'.format(
                self.ecu.get_calibration_description(), self.ecu.get_calibration(), *hardware,
                datetime.now().strftime('%Y-%m-%d_%H%M'))
        except (kwp2000.Kwp2000Exception, GkbusException, ValueError, RuntimeError):
            return 'output_{}_to_{}.bin'.format(hex(start), hex(stop))

    def read(self, address_start=None, address_stop=None, escalate_privileges=False, filename=None) -> Path:
        size = self.ecu.get_eeprom_size_bytes()
        start = abs(self.ecu.bin_offset) if address_start is None else address_start
        stop = abs(self.ecu.bin_offset) + size if address_stop is None else address_stop
        if escalate_privileges:
            self._log('[*] Attempting privilege escalation with the IOCLID patch')
            if self.ecu.security_access(AccessLevel.SIEMENS_0xFD):
                self._log('[*] Success!')
            else:
                self._log('[!] Patch likely not present, failed to escalate privileges.')
                self._log('    Read will only include the calibration and program zones.')
                start = max(start, self.ecu.get_region('calibration').read.address)
        offset = self.ecu.calculate_bin_offset(start)
        if not 0 <= offset < offset + stop - start <= size:
            raise ValueError('Requested read range is outside ECU memory')
        self._log('[*] Reading from {} to {}'.format(hex(start), hex(stop)))
        with self._progress(stop - start, 'Reading SIMK') as progress:
            data = read_memory(self.ecu, start, stop, progress_callback=progress)
        image = bytearray(b'\xFF' * size)
        image[offset:offset + len(data)] = data
        path = Path(filename or self._read_filename(start, stop)).resolve()
        path.write_bytes(image)
        self._log('[*] saved to {}'.format(path))
        self._log('[*] Done!')
        return path

    def plan_flash(self, image: bytes, calibration=True, program=True) -> list[FlashBlock]:
        """Validate all payloads before the first erase, preserving protected flags."""
        if len(image) != self.ecu.get_eeprom_size_bytes():
            raise ValueError('SIMK flashing requires a complete {}-byte BIN'.format(self.ecu.get_eeprom_size_bytes()))
        blocks = []
        for name, enabled, routine in (
            ('program', program, Routine.ERASE_PROGRAM),
            ('calibration', calibration, Routine.ERASE_CALIBRATION),
        ):
            if not enabled:
                continue
            region = self.ecu.get_region(name).write
            skip = 16 if name == 'program' else 0
            offset = self.ecu.calculate_bin_offset(region.address) + skip
            payload = bytes(image[offset:offset + region.size - 16])
            payload = payload[:min(dynamic_find_end(payload), len(payload))]
            if not payload:
                raise ValueError('{} region is empty; no flash was erased'.format(name.capitalize()))
            address = region.address + skip if name == 'program' else self.ecu.calculate_memory_write_offset(region.address)
            blocks.append(FlashBlock(name, address, payload, routine))
        if not blocks:
            raise ValueError('Select a region to flash')
        return blocks

    def flash(self, image: bytes, calibration=True, program=True) -> None:
        blocks = self.plan_flash(image, calibration, program)
        bus = self.ecu.bus
        for block in blocks:
            self._log('[*] Erasing {} region'.format(block.name))
            self._phase('erase', True)
            try:
                bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(block.erase_routine.value))
            finally:
                self._phase('erase', False)
            self._log('[*] Uploading data to the ECU')
            with self._progress(len(block.data), 'Flashing SIMK') as progress:
                write_memory(self.ecu, block.data, block.address, len(block.data), progress_callback=progress)

        timeout = bus.transport.get_timeout()
        self._log('[*] Verifying blocks and marking as ready to execute')
        self._phase('verify', True)
        try:
            bus.transport.set_timeout(300)
            bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(Routine.VERIFY_BLOCKS.value))
        except kwp2000.Kwp2000NegativeResponseException as exc:
            self._log('[!] Verification failed. Check the BIN checksums before retrying.')
            try:
                status = bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(
                    Routine.CHECK_REPROGRAMMING_STATUS.value)).get_data()[1:]
                self._log(str(ReprogrammingStatus(int.from_bytes(status, 'big'))))
            except (kwp2000.Kwp2000Exception, TimeoutException):
                pass
            raise RuntimeError('SIMK flash verification failed; ECU was not reset') from exc
        finally:
            bus.transport.set_timeout(timeout)
            self._phase('verify', False)
        self._log('[*] ECU reset')
        try:
            bus.execute(kwp2000.commands.ECUReset(kwp2000.enums.ResetMode.POWER_ON_RESET))
        except TimeoutException:
            pass  # Some ECUs reset before acknowledging the request.
        self._log('[*] Done!')
