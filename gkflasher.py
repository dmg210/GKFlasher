import argparse, time, yaml, logging, sys, os, traceback, re
from datetime import datetime
from alive_progress import alive_bar
from gkbus.hardware import KLineHardware, CanHardware, OpeningPortException, TimeoutException
from gkbus.transport import Kwp2000OverKLineTransport, Kwp2000OverCanTransport, RawPacket, PacketDirection
from gkbus.protocol import kwp2000
from flasher.memory import read_memory, write_memory, dynamic_find_end
from flasher.ecu import ECU, identify_ecu, fetch_ecu_identification, enable_security_access, ECUIdentificationException, DesiredBaudrate
from flasher.checksum import correct_checksum
from ecu_definitions import ECU_IDENTIFICATION_TABLE, BAUDRATES, Routine, ReprogrammingStatus, AccessLevel
from flasher.logging import logger, logger_raw
from flasher.immo import cli_immo, cli_immo_info
from flasher.lineswap import generate_sie, generate_bin
from flasher.rsw import rsw_handler
from flasher.mtos import mtos_handler
from flasher.m797 import m797_flash, m797_read_flash, M797_IMAGE_SIZE
from _version import __version__

def strip (string):
	return ''.join(x for x in string if x.isalnum())

def cli_read_eeprom (ecu: ECU, eeprom_size: int, address_start: int = None, address_stop: int = None, escalate_privileges: bool = False, output_filename: str = None):
	if escalate_privileges:
		print('[*] Attempting privilege escalation with the IOCLID patch')
		if (ecu.security_access(AccessLevel.SIEMENS_0xFD)):
			print('[*] Success!')
		else:
			print('[!] Patch likely not present, failed to escalate privileges.')
			print('    Read will only include the calibration and program zones.')
			print('    If you\'re running ca663056, feel encouraged to apply the IOCLID patch.')
			print('    It will allow you to read the whole memory over OBD2, just like BSL.')
			print('    You can find it at https://github.com/OpenGK-org/opengk-simk')

	if (address_start == None):
		address_start = abs(ecu.bin_offset)
	if (address_stop == None):
		address_stop = address_start+eeprom_size

	print('[*] Reading from {} to {}'.format(hex(address_start), hex(address_stop)))

	requested_size = address_stop-address_start
	eeprom = bytearray([0xFF]*eeprom_size)

	with alive_bar(requested_size, unit='B') as bar:
		fetched = read_memory(ecu, address_start=address_start, address_stop=address_stop, progress_callback=bar)

	eeprom_start = ecu.calculate_bin_offset(address_start)
	eeprom_end = eeprom_start + len(fetched)
	eeprom[eeprom_start:eeprom_end] = fetched

	if (output_filename == None):
		try:
			calibration = ecu.get_calibration()
			description = ecu.get_calibration_description()
			hw_rev_c = strip(''.join([chr(x) for x in list(ecu.bus.execute(kwp2000.commands.ReadEcuIdentification(0x8c)).get_data())[1:]]))
			hw_rev_d = strip(''.join([chr(x) for x in list(ecu.bus.execute(kwp2000.commands.ReadEcuIdentification(0x8d)).get_data())[1:]]))
			output_filename = "{}_{}_{}_{}_{}.bin".format(description, calibration, hw_rev_c, hw_rev_d, datetime.now().strftime('%Y-%m-%d_%H%M'))
		except: # dirty
			output_filename = "output_{}_to_{}.bin".format(hex(address_start), hex(address_stop))

	with open (output_filename, "wb") as file:
		file.write(bytes(eeprom))

	print('[*] saved to {}'.format(output_filename))

	print('[*] Done!')

def cli_flash_eeprom (ecu, input_filename, flash_calibration=True, flash_program=True):
	print('\n[*] Loading up {}'.format(input_filename))

	with open(input_filename, 'rb') as file:
		eeprom = file.read()

	print('[*] Loaded {} bytes'.format(len(eeprom)))

	if (input('[?] Ready to flash! Do you wish to continue? [y/n]: ') != 'y'):
		print('[!] Aborting!')
		return

	if flash_program:
		print('[*] start routine 0x00 (erase program code section)')
		ecu.bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(Routine.ERASE_PROGRAM.value))


		# we need to start 16 bytes later as the program section starts with a flag that we can't write
		payload_start = ecu.calculate_bin_offset(ecu.get_region('program').write.address) + 16
		payload_stop = payload_start + dynamic_find_end(eeprom[payload_start:(payload_start+ecu.get_region('program').write.size-16)])
		payload = eeprom[payload_start:payload_stop]

		flash_start = ecu.get_region('program').write.size + 16
		flash_size = payload_stop-payload_start

		with alive_bar(flash_size, unit='B') as bar:
			write_memory(ecu, payload, flash_start, flash_size, progress_callback=bar)

	if flash_calibration:
		print('[*] start routine 0x01 (erase calibration section)')
		ecu.bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(Routine.ERASE_CALIBRATION.value))

		payload_start = ecu.calculate_bin_offset(ecu.get_region('calibration').write.address)
		# we need to shave 16 bytes off the top as this is where a flag that we can't write is located
		payload_stop = payload_start + dynamic_find_end(eeprom[payload_start:(payload_start+ecu.get_region('calibration').write.size-16)])
		payload = eeprom[payload_start:payload_stop]

		flash_start = ecu.calculate_memory_write_offset(ecu.get_region('calibration').write.address)
		flash_size = payload_stop-payload_start

		with alive_bar(flash_size, unit='B') as bar:
			write_memory(ecu, payload, flash_start, flash_size, progress_callback=bar)

	ecu.bus.transport.hardware.set_timeout(300)

	print('[*] start routine 0x02 (verify blocks and mark as ready to execute)')
	try:
		ecu.bus.execute(kwp2000.commands.StartRoutineByLocalIdentifier(Routine.VERIFY_BLOCKS.value))
	except kwp2000.Kwp2000NegativeResponseException as e:
		print('[*] Verifying blocks failed! Did you forget to correct the checksum?')
		print('[*] Fetching detailed reprogramming status..')
		reprogramming_status_response = ecu.bus.execute(
			kwp2000.commands.StartRoutineByLocalIdentifier(
				Routine.CHECK_REPROGRAMMING_STATUS.value
			)
		).get_data()[1:]

		reprogramming_status = ReprogrammingStatus(int.from_bytes(reprogramming_status_response, 'big'))

		print(str(reprogramming_status))

		print('[!] Your ECU is now soft-bricked. There\'s no need to panic, all you need to do is flash a valid file.')

	ecu.bus.transport.hardware.set_timeout(12)

	print('[*] ecu reset')
	print('[*] done!')
	ecu.bus.execute(kwp2000.commands.ECUReset(kwp2000.enums.ResetMode.POWER_ON_RESET)).get_data()
	ecu.bus.close()
	
def cli_clear_adaptive_values (ecu):
	print('[*] Clearing adaptive values.. ', end='')
	ecu.clear_adaptive_values()
	print('Done! Turn off ignition for 10 seconds to apply changes.')

def cli_read_dtcs (ecu):
	print('[*] Reading diagnostic trouble codes')
	ecu.bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.DEFAULT, ecu.get_desired_baudrate().index))

	dtcs_raw = ecu.bus.execute(
		kwp2000.commands.ReadDTCsByStatus(
			kwp2000.enums.DtcStatus.REQUEST_IDENTIFIED_DTC_AND_STATUS,
			kwp2000.enums.DtcGroup.POWERTRAIN
		)
	).get_data()

	dtc_amount = dtcs_raw[0]
	print('[*] Amount of DTCs: {}'.format(dtc_amount))
	dtcs = {}
	for x in range(dtc_amount):
		dtc = int.from_bytes(dtcs_raw[1:][(x * 3):(x * 3) + 2])
		dtc_status = dtcs_raw[1:][(x * 3) + 2]
		dtcs[dtc] = dtc_status

	for dtc, status in dtcs.items():
		print('[*] DTC: P{} ({})'.format(f"{dtc:04x}", bin(status)))


# ============================================================================
# Kefico/Bosch M7.9.7 support
#
# Everything above this block is the stock SIMK implementation.  M7.9.7 is
# routed out before the stock SIMK diagnostic-session/security/identification
# path starts.
# ============================================================================

ECU_FAMILY_SIMK = 'simk'
ECU_FAMILY_M797 = 'm797'
ECU_FAMILY_UNKNOWN = 'unknown'

M797_ECU_IDENTIFICATION_PARAMETERS = [
	{'value': 0x90, 'name': 'Calibration Identifier'},
	{'value': 0x91, 'name': 'vehicleManufacturerECUHardwareNumber'},
	{'value': 0x92, 'name': 'systemSupplierECUHardwareNumber'},
	{'value': 0x93, 'name': 'systemSupplierECUHardwareVersionNumber'},
	{'value': 0x94, 'name': 'systemSupplierECUSoftwareNumber'},
	{'value': 0x95, 'name': 'systemSupplierECUSoftwareVersionNumber'},
	{'value': 0x96, 'name': 'exhaustRegulationOrTypeApprovalNumber'},
	{'value': 0x97, 'name': 'systemNameOrEngineType'},
	{'value': 0x98, 'name': 'repairShopCodeOrTesterSerialNumber'},
	{'value': 0x99, 'name': 'programmingDate'},
	{'value': 0x9A, 'name': 'calibrationRepairShopCodeOrCalibrationEquipment'},
	{'value': 0x9B, 'name': 'calibrationDate'},
	{'value': 0x9C, 'name': 'calibrationEquipmentSoftwareNumber'},
	{'value': 0x9D, 'name': 'ECUInstallationDate'},
]


def _m797_meaningful_identification_payload(response, identifier: int) -> bool:
	"""Reject filler/blank positive responses such as SIMK's all-FF IDs."""
	data = bytes(response)

	if data and data[0] == identifier:
		data = data[1:]

	if not data:
		return False

	# Erased/unimplemented local identifiers observed on SIMK answer with
	# positive SID but contain only 00/FF (occasionally spaces).
	meaningful = bytes(
		value for value in data
		if value not in (0x00, 0x20, 0xFF)
	)

	return len(meaningful) >= 2


def detect_ecu_family(bus: kwp2000.Kwp2000Protocol) -> str:
	"""
	Non-destructive early family detection before any SIMK-specific setup.

	M7.9.7 is identified by multiple positive supplier/hardware/software ID
	records.  Do not silently classify communication failure as SIMK: return
	UNKNOWN so programming operations cannot accidentally enter the SIMK path.
	"""
	positive_ids = 0

	for identifier in (0x91, 0x92, 0x93, 0x94, 0x95):
		try:
			response = bus.execute(
				kwp2000.commands.ReadEcuIdentification(identifier)
			).get_data()

			if _m797_meaningful_identification_payload(response, identifier):
				positive_ids += 1
				if positive_ids >= 2:
					return ECU_FAMILY_M797
		except (kwp2000.Kwp2000NegativeResponseException, TimeoutException):
			continue

	return ECU_FAMILY_UNKNOWN


def cli_choose_ecu_family() -> str | None:
	print('[!] Unable to identify ECU family automatically.')
	print('[*] This can happen when an ECU is soft-bricked but its programming bootloader is still alive.')
	print('    [0] SIMK')
	print('    [1] Kefico/Bosch M7.9.7')

	try:
		choice = input('ECU family or any other key to abort: ').strip()
	except (EOFError, KeyboardInterrupt):
		return None

	if choice == '0':
		return ECU_FAMILY_SIMK
	if choice == '1':
		return ECU_FAMILY_M797

	print('[!] Aborting..')
	return None


def fetch_m797_ecu_identification(bus):
	values = {}

	for parameter in M797_ECU_IDENTIFICATION_PARAMETERS:
		try:
			value = bus.execute(
				kwp2000.commands.ReadEcuIdentification(parameter['value'])
			).get_data()
		except kwp2000.Kwp2000NegativeResponseException:
			continue

		values[parameter['value']] = {
			'name': parameter['name'],
			'value': bytes(value[1:])
		}

	return values


def cli_m797_id(bus: kwp2000.Kwp2000Protocol):
	print('[*] Reading Kefico/Bosch M7.9.7 ECU Identification')

	for parameter_key, parameter in fetch_m797_ecu_identification(bus).items():
		value = parameter['value']
		value_hex = ' '.join('{:02X}'.format(x) for x in value)
		value_ascii = ''.join(
			chr(x) if 0x20 <= x <= 0x7E else '.'
			for x in value
		).rstrip()

		print('')
		print('    [*] [0x{:02X}] {}:'.format(
			parameter_key,
			parameter['name']
		))
		print('            [HEX]: {}'.format(value_hex))
		print('            [ASCII]: {}'.format(value_ascii))

	print('')


def cli_m797_read_dtcs(bus: kwp2000.Kwp2000Protocol):
	print('[*] Reading Kefico/Bosch M7.9.7 diagnostic trouble codes')

	dtcs_raw = bus.execute(
		kwp2000.commands.ReadDTCsByStatus(
			kwp2000.enums.DtcStatus.REQUEST_IDENTIFIED_DTC_AND_STATUS,
			kwp2000.enums.DtcGroup.ALL
		)
	).get_data()

	if not dtcs_raw:
		print('[!] ECU returned an empty DTC response')
		return

	dtc_amount = dtcs_raw[0]
	print('[*] Amount of DTCs: {}'.format(dtc_amount))

	for x in range(dtc_amount):
		offset = 1 + (x * 3)

		if offset + 3 > len(dtcs_raw):
			print('[!] DTC response is shorter than expected')
			break

		dtc = int.from_bytes(
			dtcs_raw[offset:offset + 2],
			byteorder='big'
		)
		status = dtcs_raw[offset + 2]

		print('[*] DTC: P{:04X}, Status: 0x{:02X}'.format(
			dtc,
			status
		))


def _sanitize_m797_filename_component(value: str) -> str:
	value = value.strip().strip('\x00')
	value = re.sub(r'[<>:"/\\|?*\x00-\x1F]', '_', value)
	value = re.sub(r'\s+', '_', value)
	return value.strip(' ._')


def get_m797_calibration_id(bus: kwp2000.Kwp2000Protocol) -> str:
	response = bus.execute(
		kwp2000.commands.ReadEcuIdentification(0x90)
	).get_data()

	data = bytes(response)
	if data and data[0] == 0x90:
		data = data[1:]

	calibration = data.decode('ascii', errors='ignore').strip().strip('\x00')

	if not calibration:
		raise RuntimeError('M7.9.7 calibration ID 0x90 was blank')

	return calibration


def get_m797_engine_id(bus: kwp2000.Kwp2000Protocol) -> str:
	response = bus.execute(
		kwp2000.commands.ReadEcuIdentification(0x97)
	).get_data()

	data = bytes(response)
	if data and data[0] == 0x97:
		data = data[1:]

	engine_id = data.decode('ascii', errors='ignore').strip().strip('\x00')

	if not engine_id:
		raise RuntimeError('M7.9.7 engine ID 0x97 was blank')

	return engine_id.title()


def make_m797_read_filename(
		calibration_id: str,
		engine_id: str | None = None
	) -> str:
	calibration = _sanitize_m797_filename_component(
		calibration_id
	) or 'M797'

	if engine_id:
		engine = _sanitize_m797_filename_component(engine_id)
		if engine:
			return '{}_{}.bin'.format(calibration, engine)

	return '{}.bin'.format(calibration)


def handle_m797(bus: kwp2000.Kwp2000Protocol, args):
	"""
	M7.9.7-only command dispatcher.

	This function returns to main() before any of the stock SIMK
	StartDiagnosticSession / SecurityAccess / identify_ecu logic executes.
	"""
	print('[*] Found! Kefico/Bosch M7.9.7')

	if args.id:
		cli_m797_id(bus)

	if args.read_dtcs:
		cli_m797_read_dtcs(bus)

	if args.read:
		calibration_id = 'UNKNOWN'

		try:
			print('[*] Reading M7.9.7 calibration identifier (0x90)')
			calibration_id = get_m797_calibration_id(bus)
			print('[+] Detected calibration: {}'.format(calibration_id))
		except Exception as exc:
			print('[!] Calibration identifier 0x90 unavailable: {}'.format(exc))
			print('[*] Continuing with calibration-agnostic read probing.')

		engine_id = None

		try:
			print('[*] Reading M7.9.7 engine identifier (0x97)')
			engine_id = get_m797_engine_id(bus)
			print('[+] Detected engine: {}'.format(engine_id))
		except Exception as exc:
			print('[!] Engine identifier 0x97 unavailable: {}'.format(exc))

		output_filename = (
			args.output
			if args.output
			else make_m797_read_filename(calibration_id, engine_id)
		)

		print('[*] Output file: {}'.format(output_filename))

		read_progress = None
		if getattr(args, 'gui_progress', False):
			progress_state = {'done': 0, 'percent': -1}

			def read_progress(delta):
				progress_state['done'] += int(delta)
				percent = min(100, int(
					(progress_state['done'] * 100) / M797_IMAGE_SIZE
				))
				if percent != progress_state['percent']:
					progress_state['percent'] = percent
					print('@@M797_PROGRESS {}@@'.format(percent), flush=True)

		m797_read_flash(
			bus,
			calibration_id=calibration_id,
			output_filename=output_filename,
			progress_callback=read_progress,
			read_profile=getattr(args, 'm797_read_profile', None)
		)

	if args.flash:
		flash_progress = None
		if getattr(args, 'gui_progress', False):
			progress_state = {'done': 0, 'percent': -1}

			def flash_progress(delta):
				progress_state['done'] += int(delta)
				percent = min(100, int(
					(progress_state['done'] * 100) / M797_IMAGE_SIZE
				))
				if percent != progress_state['percent']:
					progress_state['percent'] = percent
					print('@@M797_PROGRESS {}@@'.format(percent), flush=True)

		m797_flash(
			bus,
			args.flash,
			programming_profile=getattr(args, 'm797_programming_profile', None),
			confirm=not getattr(args, 'm797_gui_confirmed', False),
			progress_callback=flash_progress
		)

	unsupported = []

	if args.flash_calibration:
		unsupported.append('--flash-calibration')
	if args.flash_program:
		unsupported.append('--flash-program')
	if args.read_calibration:
		unsupported.append('--read-calibration')
	if args.read_program:
		unsupported.append('--read-program')
	if args.immo:
		unsupported.append('--immo')
	if args.clear_adaptive_values:
		unsupported.append('--clear-adaptive-values')
	if args.logger:
		unsupported.append('--logger')

	if unsupported:
		print('[!] Not yet supported on M7.9.7: {}'.format(
			', '.join(unsupported)
		))


def load_config (config_filename):
	return yaml.safe_load(open('gkflasher.yml'))

def load_arguments ():
	parser = argparse.ArgumentParser(prog='GKFlasher v{}'.format(__version__))
	parser.add_argument('-p', '--protocol', help='Protocol to use. canbus or kline')
	parser.add_argument('-i', '--interface')
	parser.add_argument('-b', '--baudrate', type=int)
	parser.add_argument('--desired-baudrate', type=lambda x: int(x,0))
	parser.add_argument('--ecu-family', choices=['auto', ECU_FAMILY_SIMK, ECU_FAMILY_M797], default='auto', help='Force ECU family detection. Useful for M7.9.7 recovery.')
	parser.add_argument('-f', '--flash', help='Filename to full flash')
	parser.add_argument('--flash-calibration', help='Filename to flash calibration zone from')
	parser.add_argument('--flash-program', help='Filename to flash program zone from')
	parser.add_argument('-r', '--read', action='store_true')
	parser.add_argument('--gui-progress', action='store_true', help=argparse.SUPPRESS)
	parser.add_argument('--m797-read-profile', choices=['standard', 'fast'], default=None, help='M7.9.7 bulk read speed profile.')
	parser.add_argument('--m797-programming-profile', choices=['standard', 'fast'], default=None, help='M7.9.7 full-flash programming speed profile.')
	parser.add_argument('--m797-gui-confirmed', action='store_true', help=argparse.SUPPRESS)
	parser.add_argument('--read-calibration', action='store_true')
	parser.add_argument('--read-program', action='store_true')
	parser.add_argument('--read-dtcs', action='store_true')
	parser.add_argument('--id', action='store_true')
	parser.add_argument('--correct-checksum')
	parser.add_argument('--bin-to-sie')
	parser.add_argument('--sie-to-bin')	
	parser.add_argument('--clear-adaptive-values', action='store_true')
	parser.add_argument('-l', '--logger', action='store_true')
	parser.add_argument('-o', '--output', help='Filename to save the EEPROM dump')
	parser.add_argument('-s', '--address-start', help='Offset to start reading/flashing from.', type=lambda x: int(x,0))
	parser.add_argument('-e', '--address-stop', help='Offset to stop reading/flashing at.', type=lambda x: int(x,0))
	parser.add_argument('-c', '--config', help='Config filename', default='gkflasher.yml')
	parser.add_argument('-v', '--verbose', action='count', default=0)
	parser.add_argument('--immo', action='store_true')
	parser.add_argument('--rsw-boot1', help='Flash Boot1 using RSW bootstrap')
	parser.add_argument('--rsw-boot2', help='Flash Boot2 using RSW bootstrap')
	parser.add_argument('--rsw-asw', help='Flash ASW using RSW bootstrap')
	parser.add_argument('--rsw-cal', help='Flash CAL using RSW bootstrap')
	parser.add_argument('--rsw-full', help='Flash full image set using RSW bootstrap')
	parser.add_argument('--rsw-virginize', help='Virginize ECU using RSW bootstrap')
	parser.add_argument('--mtos',  help='Mini Test Operating System', action='store_true')
	parser.add_argument('--mtos-payload', help='BIN file to use for MTOS (full dump)')
	parser.add_argument('--mtos-key', help='Key to use for Siemens access level', type=lambda x: int(x,0))
	args = parser.parse_args()

	logging_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
	logging.basicConfig(level=logging_levels[min(args.verbose, len(logging_levels) -1)])

	GKFlasher_config = load_config(args.config)
	
	if (args.protocol):
		GKFlasher_config['protocol'] = args.protocol
	if (args.interface):
		GKFlasher_config[GKFlasher_config['protocol']]['interface'] = args.interface
	if (args.baudrate):
		GKFlasher_config[GKFlasher_config['protocol']]['baudrate'] = args.baudrate

	return GKFlasher_config, args

def initialize_bus (protocol: str, protocol_config: dict) -> kwp2000.Kwp2000Protocol:
	if protocol == 'canbus':
		hardware = CanHardware(protocol_config['interface'])
		transport = Kwp2000OverCanTransport(hardware, tx_id=protocol_config['tx_id'], rx_id=protocol_config['rx_id'])
	elif protocol == 'kline':
		hardware = KLineHardware(protocol_config['interface'])
		transport = Kwp2000OverKLineTransport(hardware, tx_id=protocol_config['tx_id'], rx_id=protocol_config['rx_id'])

	bus = kwp2000.Kwp2000Protocol(transport)

	return bus


# Known Hyundai/Kia/Kefico K-Line application target addresses.
# Keep the configured address first so normal SIMK setups connect immediately.
M797_KLINE_TARGET_ADDRESSES = (
	0x11,
	0x17,
	0x0E,
	0x0F,
)
M797_KLINE_PROBE_TIMEOUT = 0.30
M797_KLINE_NORMAL_TIMEOUT = 12
M797_KLINE_PROBE_RETRY_DELAY = 0.10
M797_KLINE_SCAN_PASSES = 2
M797_KLINE_KEEPALIVE_DELAY = 1.5


def _unique_kline_targets(configured_target: int):
	targets = []
	for target in (configured_target, *M797_KLINE_TARGET_ADDRESSES):
		if target not in targets:
			targets.append(target)
	return targets


def _start_communication(bus: kwp2000.Kwp2000Protocol, probe: bool = False):
	"""Start KWP communication; probe mode deliberately has no keepalive."""
	if probe:
		result = bus.init(kwp2000.commands.StartCommunication())
	else:
		result = bus.init(
			kwp2000.commands.StartCommunication(),
			keepalive_command=kwp2000.commands.TesterPresent(
				kwp2000.enums.ResponseType.REQUIRED
			),
			keepalive_delay=M797_KLINE_KEEPALIVE_DELAY
		)
	bus.transport.set_buffer_size(20)
	return result


def _set_kline_target(bus: kwp2000.Kwp2000Protocol, target: int) -> None:
	transport = bus.transport
	updated = False
	for attribute in ('tx_id', '_tx_id'):
		if hasattr(transport, attribute):
			setattr(transport, attribute, target)
			updated = True
	if not updated:
		raise AttributeError('Kwp2000OverKLineTransport does not expose a mutable tx_id')


def _prepare_next_kline_probe(bus) -> None:
	if hasattr(bus, '_stop_keepalive'):
		try:
			bus._stop_keepalive()
		except Exception:
			pass

	socket = getattr(bus.transport.hardware, 'socket', None)
	if socket is not None:
		try:
			socket.reset_input_buffer()
		except Exception:
			pass
		try:
			socket.reset_output_buffer()
		except Exception:
			pass


def initialize_connected_bus(protocol: str, protocol_config: dict) -> kwp2000.Kwp2000Protocol:
	"""
	Open communication and validate the physical K-Line target with a real KWP
	response before family detection.  bus.init() alone is not sufficient proof
	of a valid target with the GKBus K-Line fast-init implementation.
	"""
	if protocol != 'kline':
		bus = initialize_bus(protocol, protocol_config)
		_start_communication(bus)
		return bus

	configured_target = protocol_config['tx_id']
	targets = _unique_kline_targets(configured_target)
	last_exception = None

	print('[*] Probing K-Line ECU target address')

	initial_config = dict(protocol_config)
	initial_config['tx_id'] = targets[0]
	bus = initialize_bus('kline', initial_config)

	for scan in range(M797_KLINE_SCAN_PASSES):
		if scan:
			print('[*] Retrying K-Line target scan')

		for target in targets:
			print('[*] Trying K-Line target 0x{:02X}'.format(target))
			try:
				_prepare_next_kline_probe(bus)
				_set_kline_target(bus, target)

				# Physical fast-init + StartCommunication, but no background keepalive
				# until the address has been validated.
				_start_communication(bus, probe=True)
				bus.transport.hardware.set_timeout(M797_KLINE_PROBE_TIMEOUT)

				# Require an actual ECU response. A wrong address can otherwise look
				# like a successful fast-init in GKBus.
				bus.execute(
					kwp2000.commands.TesterPresent(
						kwp2000.enums.ResponseType.REQUIRED
					)
				)
				bus.transport.hardware.set_timeout(M797_KLINE_NORMAL_TIMEOUT)

				# Restart once in normal mode to install the standard keepalive.
				_prepare_next_kline_probe(bus)
				_set_kline_target(bus, target)
				_start_communication(bus, probe=False)

				print('[+] K-Line ECU responded at target address 0x{:02X}'.format(target))
				return bus

			except Exception as exc:
				last_exception = exc
				try:
					if getattr(bus.transport.hardware, 'socket', None) is not None:
						bus.transport.hardware.set_timeout(M797_KLINE_PROBE_TIMEOUT)
				except Exception:
					pass
				time.sleep(M797_KLINE_PROBE_RETRY_DELAY)

	try:
		bus.close()
	except Exception:
		pass

	raise RuntimeError(
		'K-Line StartCommunication failed at all target addresses: {}'
		.format(', '.join('0x{:02X}'.format(target) for target in targets))
	) from last_exception

def cli_choose_ecu ():
	print('[!] Failed to identify your ECU!')
	print('[*] If you know what you\'re doing (like trying to revive a soft bricked ECU), you can choose your ECU from the list below:')

	for index, ecu in enumerate(ECU_IDENTIFICATION_TABLE):
		print('    [{}] {}'.format(index, ecu['ecu']['name']))

	try:
		choice = int(input('ECU or any other char to abort: '))
	except ValueError:
		print('[!] Aborting..')
		return

	try:
		ECU_IDENTIFICATION_TABLE[choice]
	except IndexError:
		print('[!] Invalid value!')
		return cli_choose_ecu()

	return ECU_IDENTIFICATION_TABLE[choice]

def cli_identify_ecu (bus: kwp2000.Kwp2000Protocol):
	print('[*] Trying to identify ECU automatically.. ')
	
	try:
		ecu = identify_ecu(bus)
	except ECUIdentificationException:
		choice = cli_choose_ecu()
		if not choice:
			return None
		ecu = ECU(**choice['ecu'])
		ecu.set_bus(bus)

	print('[*] Found! {}'.format(ecu.get_name()))
	return ecu

def main(bus: kwp2000.Kwp2000Protocol, args):
	# StartCommunication and K-Line target validation are completed before main().
	if isinstance(bus.transport, Kwp2000OverKLineTransport):
		if args.ecu_family != 'auto':
			ecu_family = args.ecu_family
			print('[*] ECU family forced to {}'.format(ecu_family))
		else:
			print('[*] Detecting ECU family...')
			ecu_family = detect_ecu_family(bus)

			if ecu_family == ECU_FAMILY_UNKNOWN:
				# Never silently route an unidentified full-flash request into the
				# SIMK programming path. Non-programming commands preserve the old
				# fallback behavior.
				if args.flash or args.flash_calibration or args.flash_program:
					ecu_family = cli_choose_ecu_family()
					if ecu_family is None:
						return
				else:
					ecu_family = ECU_FAMILY_SIMK

		if ecu_family == ECU_FAMILY_M797:
			handle_m797(bus, args)
			return

	if args.desired_baudrate:
		try:
			desired_baudrate = DesiredBaudrate(index=args.desired_baudrate, baudrate=BAUDRATES[args.desired_baudrate])
		except KeyError:
			print('[!] Selected baudrate is invalid! Available baudrates:')
			for key, baudrate in BAUDRATES.items():
				print('{} - {}'.format(hex(key), baudrate))
			return

		print('[*] Trying to start diagnostic session with baudrate {}'.format(desired_baudrate.baudrate))
		try:
			bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING, desired_baudrate.index))
			bus.transport.hardware.set_baudrate(desired_baudrate.baudrate)
		except TimeoutException:
			# it's possible that the bus is already running at the desired baudrate - let's check
			bus.transport.hardware.socket.reset_input_buffer() # @todo: expose this in public gkbus api
			bus.transport.hardware.socket.reset_output_buffer()
			bus.transport.hardware.set_baudrate(desired_baudrate.baudrate)
			bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING, desired_baudrate.index))
	else:
		# @todo: not ideal, but its a bridge towards moving this completely to the ECU class. it was a mess
		desired_baudrate = DesiredBaudrate(index=None, baudrate=10400)
		print('[*] Trying to start diagnostic session')
		bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING))
		
	bus.transport.hardware.set_timeout(12)

	print('[*] Set timing parameters to maximum')
	try:
		available_timing = bus.execute(
			kwp2000.commands.AccessTimingParameters().read_limits_of_possible_timing_parameters()
		).get_data()

		bus.execute(
			kwp2000.commands.AccessTimingParameters().set_timing_parameters_to_given_values(
				*available_timing[1:]
			)
		)
	except kwp2000.Kwp2000NegativeResponseException:
		print('[!] Not supported on this ECU!')

	# this stays for now instead of the method built in the ECU class
	# @todo - after moving ecu definitions to classes, either start 
	# with an empty ECU object that'll implement security access (and then fill the object upon identification),
	# or better, come up with an identification way that doesn't require memory reading access
	print('[*] Security Access')
	enable_security_access(bus)

	ecu = cli_identify_ecu(bus)
	if not ecu:
		return

	ecu.set_desired_baudrate(desired_baudrate)
	ecu.diagnostic_session_type = kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING
	ecu.access_level = AccessLevel.HYUNDAI_0x1

	print('[*] Trying to find calibration..')
	
	try:
		description, calibration = ecu.get_calibration_description(), ecu.get_calibration()
		print('[*] Found! Description: {}, calibration: {}'.format(description, calibration))
	except kwp2000.Kwp2000NegativeResponseException:
		if (input('[!] Failed! Do you want to continue? [y/n]: ') != 'y'):
			return

	if (args.immo):
		return cli_immo(ecu)

	if (args.id):
		print('[*] Reading ECU Identification..',end='')
		for parameter_key, parameter in fetch_ecu_identification(bus).items():
			value_dec = list(parameter['value'])
			value_hex = ' '.join([hex(x) for x in value_dec])
			value_ascii = strip(''.join([chr(x) for x in value_dec]))

			print('')
			print('    [*] [{}] {}:'.format(hex(parameter_key), parameter['name']))
			print('            [HEX]: {}'.format(value_hex))
			print('            [ASCII]: {}'.format(value_ascii))
			print('')

		cli_immo_info(ecu)

	eeprom_size = ecu.get_eeprom_size_bytes()

	if (args.read):
		cli_read_eeprom(ecu, eeprom_size, address_start=args.address_start, address_stop=args.address_stop, escalate_privileges=True, output_filename=args.output)
	if (args.read_calibration):
		cli_read_eeprom(ecu, eeprom_size, address_start=ecu.get_region('calibration').read.address, address_stop=ecu.get_region('calibration').read.address+ecu.get_region('calibration').read.size, output_filename=args.output)
	if (args.read_program):
		address_start = ecu.get_region('program').read.address
		address_stop = address_start+ecu.get_region('program').read.size
		cli_read_eeprom(ecu, eeprom_size, address_start=address_start, address_stop=address_stop, output_filename=args.output)
	if (args.read_dtcs):
		cli_read_dtcs(ecu)

	if (args.flash):
		cli_flash_eeprom(ecu, input_filename=args.flash)
	if (args.flash_calibration):
		cli_flash_eeprom(ecu, input_filename=args.flash_calibration, flash_calibration=True, flash_program=False)
	if (args.flash_program):
		cli_flash_eeprom(ecu, input_filename=args.flash_program, flash_program=True, flash_calibration=False)

	if (args.clear_adaptive_values):
		cli_clear_adaptive_values(ecu)

	if (args.logger):
		logger(ecu)

	if (args.rsw_boot1):
		rsw_handler(ecu, mode='boot1', bin_file=args.rsw_boot1)

	if (args.rsw_boot2):
		rsw_handler(ecu, mode='boot2', bin_file=args.rsw_boot2)

	if (args.rsw_asw):
		rsw_handler(ecu, mode='asw', bin_file=args.rsw_asw)

	if (args.rsw_cal):
		rsw_handler(ecu, mode='cal', bin_file=args.rsw_cal)

	if (args.rsw_full):
		rsw_handler(ecu, mode='full', bin_file=args.rsw_full)

	if (args.rsw_virginize):
		rsw_handler(ecu, mode='virginize', bin_file=args.rsw_virginize)

	if (args.mtos):
		mtos_handler(ecu, args.mtos_payload, args.mtos_key)
	bus.close()

def packet2hex (packet: RawPacket) -> str:
	direction = 'Incoming' if packet.direction == PacketDirection.INCOMING else 'Outgoing'
	data = ' '.join([hex(x)[2:].zfill(2) for x in packet.data])
	parsed = 'RawPacket({}, ts={}, data={})'.format(direction, packet.timestamp, data)
	return parsed

if __name__ == '__main__':
	GKFlasher_config, args = load_arguments()

	print('[*] GKFlasher v{}'.format(__version__))

	if (args.correct_checksum):
		correct_checksum(filename=args.correct_checksum)

	if (args.bin_to_sie):
		generate_sie(filename=args.bin_to_sie)
		sys.exit()

	if (args.sie_to_bin):
		generate_bin(filename=args.sie_to_bin)
		sys.exit()
	
	print('[*] Selected protocol: {}. Initializing..'.format(GKFlasher_config['protocol']))
	bus = None
	exit_code = 0

	try:
		bus = initialize_connected_bus(
			GKFlasher_config['protocol'],
			GKFlasher_config[GKFlasher_config['protocol']]
		)
		main(bus, args)
	except KeyboardInterrupt:
		exit_code = 130
	except Exception:
		exit_code = 1
		print('\n\n[!] Exception in main thread!')
		print(traceback.format_exc())
		if bus is not None:
			try:
				print('[*] Dumping buffer:\n')
				print('\n'.join([packet2hex(packet) for packet in bus.transport.buffer_dump()]))
			except Exception:
				pass
		print('\n[!] Shutting down due to an exception in the main thread. For exception details, see above')
	finally:
		if bus is not None:
			try:
				bus.close()
			except Exception:
				pass
	os._exit(exit_code)
