"""Shared family-independent workflows and SIMK protocol behavior."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
from types import SimpleNamespace
import tempfile
import unittest
from unittest.mock import Mock, patch

from gkbus.protocol import kwp2000
from gkbus.exceptions import GkbusException
from ecu_definitions import ECU_IDENTIFICATION_TABLE, ReprogrammingStatus, Routine
from flasher.connection import close_connection
from flasher.checksum import prepare_checksum_correction
from flasher.ecu import ECU, fetch_dtcs
from flasher.memory import dynamic_find_end, read_memory
from flasher.simk import SimkOperations
from flasher.utils import WordBitfield
from tests.test_m797_checksums import m797_checksum_image, simk_checksum_image


class SharedChecksumTests(unittest.TestCase):
    def test_both_families_refuse_to_overwrite_changes_after_preview(self):
        for source in (simk_checksum_image(), m797_checksum_image()):
            with self.subTest(size=len(source)), tempfile.TemporaryDirectory() as directory:
                path = Path(directory) / 'image.bin'
                path.write_bytes(source)
                result = prepare_checksum_correction(source, lambda message: None)
                self.assertTrue(result.changes)
                changed = source[:-1] + bytes([source[-1] ^ 1])
                path.write_bytes(changed)
                with self.assertRaisesRegex(ValueError, 'changed after checksum preview'):
                    result.save(path)
                self.assertEqual(path.read_bytes(), changed)
                self.assertEqual(list(path.parent.glob('*.tmp')), [])

    def test_simk_invalid_descriptors_do_not_produce_a_correction(self):
        source = bytearray(simk_checksum_image())
        source[0x17EE4:0x17EE7] = b'\xFF' * 3
        with self.assertRaisesRegex(ValueError, 'checksum range'):
            prepare_checksum_correction(source, lambda message: None)


class SharedDiagnosticTests(unittest.TestCase):
    def test_reprogramming_status_uses_the_subclass_bit_layout(self):
        status = ReprogrammingStatus(1)
        self.assertEqual(status._to_dict()['checksum_of_calibration_data_is_correct'], 1)
        self.assertIn('checksum_of_calibration_data_is_correct=1', str(status))
        self.assertEqual(WordBitfield()._to_dict(), {})

    def test_device_is_closed_even_if_closing_the_protocol_fails(self):
        bus, device, log = Mock(), Mock(), Mock()
        bus.close.side_effect = RuntimeError('close failed')
        self.assertFalse(close_connection(bus, device, log))
        device.close.assert_called_once()
        self.assertIn('close failed', log.emit.call_args.args[0])

    def test_both_groups_decode_the_same_records_without_changing_session(self):
        for group in (kwp2000.enums.DtcGroup.ALL, kwp2000.enums.DtcGroup.POWERTRAIN):
            bus = Mock()
            bus.execute.return_value.get_data.return_value = bytes.fromhex('02 01 23 80 04 56 20')
            self.assertEqual(fetch_dtcs(bus, group), [(0x0123, 0x80), (0x0456, 0x20)])
            bus.execute.assert_called_once()
            self.assertEqual(bus.execute.call_args.args[0].get_service_identifier(), 0x18)

    def test_truncated_dtc_response_is_rejected(self):
        bus = Mock()
        bus.execute.return_value.get_data.return_value = bytes.fromhex('02 01 23 80')
        with self.assertRaisesRegex(ValueError, 'shorter than expected'):
            fetch_dtcs(bus)


class SimkOperationTests(unittest.TestCase):
    def setUp(self):
        self.bus = Mock()
        self.bus.transport.get_timeout.return_value = 12
        self.ecu = ECU(**ECU_IDENTIFICATION_TABLE[2]['ecu']).set_bus(self.bus)

    def image(self):
        image = bytearray(b'\xFF' * self.ecu.get_eeprom_size_bytes())
        for name in ('program', 'calibration'):
            region = self.ecu.get_region(name).write
            start = self.ecu.calculate_bin_offset(region.address)
            image[start:start + 32] = bytes(32)
        return image

    def test_partial_page_reads_stop_at_the_v6_calibration_boundary(self):
        progress = Mock()
        self.ecu.read_memory_by_address = Mock(side_effect=lambda offset, size: bytes(size))
        result = read_memory(self.ecu, 0x88000, 0x8DF40, progress)
        self.assertEqual(len(result), 24384)
        self.assertEqual(sum(call.args[0] for call in progress.call_args_list), 24384)
        self.assertEqual(progress.title.call_args.args[0], 'Page 2/2, offset 0x8c000')
        self.assertTrue(all(call.kwargs['offset'] + call.kwargs['size'] <= 0x8DF40
                            for call in self.ecu.read_memory_by_address.call_args_list))

    def test_empty_read_sends_no_requests(self):
        self.assertEqual(read_memory(self.ecu, 0x88000, 0x88000), b'')
        self.bus.execute.assert_not_called()

    def test_oversized_positive_read_response_is_rejected(self):
        self.ecu.read_memory_by_address = Mock(return_value=bytes(33))
        with self.assertRaisesRegex(RuntimeError, 'more memory bytes'):
            read_memory(self.ecu, 0x88000, 0x88020)

    def test_metadata_failure_does_not_discard_a_completed_read(self):
        self.ecu.read_memory_by_address = Mock(side_effect=lambda offset, size: bytes(size))
        self.bus.execute.side_effect = GkbusException('metadata unavailable')
        with tempfile.TemporaryDirectory() as directory:
            operations = SimkOperations(self.ecu, Mock(), lambda total: Mock())
            expected = Path(directory) / 'output_0x88000_to_0x88020.bin'
            with patch('flasher.simk.Path', side_effect=lambda name: Path(directory) / name):
                saved = operations.read(0x88000, 0x88020)
            self.assertEqual(saved, expected)
            self.assertEqual(len(saved.read_bytes()), self.ecu.get_eeprom_size_bytes())

    def test_successful_privilege_escalation_preserves_an_explicit_range(self):
        self.ecu.security_access = Mock(return_value=True)
        with tempfile.TemporaryDirectory() as directory, \
             patch('flasher.simk.read_memory', return_value=bytes(32)) as read:
            SimkOperations(self.ecu, Mock(), lambda total: Mock()).read(
                0x88000, 0x88020, True, Path(directory) / 'image.bin')
        self.assertEqual(read.call_args.args[1:], (0x88000, 0x88020))

    def test_failed_privilege_escalation_reads_only_application_regions(self):
        self.ecu.security_access = Mock(return_value=False)
        with tempfile.TemporaryDirectory() as directory, \
             patch('flasher.simk.read_memory', return_value=bytes(32)) as read:
            SimkOperations(self.ecu, Mock(), lambda total: Mock()).read(
                filename=Path(directory) / 'image.bin', escalate_privileges=True)
        self.assertEqual(read.call_args.args[1:], (0x88000, 0x100000))

    def test_transfer_rounding_does_not_drop_the_last_nonblank_byte(self):
        self.assertEqual(dynamic_find_end(bytes(255) + b'\xFF' * 300), 508)
        self.assertEqual(dynamic_find_end(b'\xFF' * 100), 0)

    def test_flash_plan_preserves_program_header_and_calibration_tail(self):
        image = self.image()
        program = self.ecu.get_region('program').write
        calibration = self.ecu.get_region('calibration').write
        tail = self.ecu.calculate_bin_offset(calibration.address) + calibration.size - 16
        image[tail:tail + 16] = b'\xAA' * 16
        blocks = SimkOperations(self.ecu).plan_flash(image)
        self.assertEqual(blocks[0].address, program.address + 16)
        self.assertEqual(blocks[0].data[:16], bytes(16))
        self.assertLessEqual(len(blocks[1].data), calibration.size - 16)
        self.assertNotIn(b'\xAA', blocks[1].data)

    def test_every_selected_region_is_validated_before_erase(self):
        image = self.image()
        region = self.ecu.get_region('calibration').write
        start = self.ecu.calculate_bin_offset(region.address)
        image[start:start + region.size] = b'\xFF' * region.size
        with self.assertRaisesRegex(ValueError, 'empty'):
            SimkOperations(self.ecu).flash(image)
        self.bus.execute.assert_not_called()

    def test_cli_and_callback_paths_send_identical_programming_commands(self):
        transcripts = []
        for callbacks in (False, True):
            self.bus.reset_mock()
            progress = Mock()
            phase = Mock()
            operations = SimkOperations(self.ecu, Mock(), (lambda total: progress) if callbacks else None,
                                        phase if callbacks else None)
            with redirect_stdout(StringIO()):
                operations.flash(self.image())
            transcripts.append([(call.args[0].get_service_identifier(), bytes(call.args[0].get_data()))
                                for call in self.bus.execute.call_args_list])
            self.bus.transport.set_timeout.assert_called_with(12)
            self.bus.close.assert_not_called()
            if callbacks:
                phase.assert_any_call('verify', False)
        self.assertEqual(transcripts[0], transcripts[1])
        self.assertEqual(transcripts[0][-1][0], 0x11)

    def test_failed_verification_never_resets_and_restores_timeout(self):
        calls = []
        def execute(command):
            calls.append(command)
            if command.get_service_identifier() == 0x31 and command.get_data() == bytes([Routine.VERIFY_BLOCKS.value]):
                raise kwp2000.Kwp2000NegativeResponseException(SimpleNamespace(identifier=0x22))
            return SimpleNamespace(get_data=lambda: b'\x03\x00\x00')
        self.bus.execute.side_effect = execute
        phase = Mock()
        with self.assertRaisesRegex(RuntimeError, 'verification failed'):
            SimkOperations(self.ecu, Mock(), lambda total: Mock(), phase).flash(self.image())
        self.assertFalse(any(command.get_service_identifier() == 0x11 for command in calls))
        self.bus.transport.set_timeout.assert_called_with(12)
        phase.assert_called_with('verify', False)
