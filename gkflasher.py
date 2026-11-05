import argparse, yaml, logging, sys, traceback
from gkbus.device import Bus, DeviceABC, discover, find_device
from gkbus.exceptions import DeviceException, GkbusException, TimeoutException
from gkbus.transport import Kwp2000OverKLineTransport, RawPacket, PacketDirection
from gkbus.protocol import kwp2000
from flasher.simk import SimkOperations
from flasher.connection import open_connection, close_connection
from flasher.ecu import (
    ECU,
    identify_ecu,
    display_identification,
    display_dtcs,
    enable_security_access,
    negotiate_timing,
    release_timing,
    ECUIdentificationException,
    DesiredBaudrate,
    detect_ecu_family,
    display_m797_identification as cli_m797_id,
    display_m797_dtcs as cli_m797_read_dtcs,
    get_m797_calibration_id,
    get_m797_engine_id,
    make_m797_read_filename,
)
from flasher.checksum import correct_checksum
from flasher.m797 import m797_read, m797_flash, m797_profile_from_selector
from ecu_definitions import (
    ECU_IDENTIFICATION_TABLE,
    KEFICO_LAYOUT,
    BAUDRATES,
    AccessLevel,
    ECU_FAMILY_SIMK,
    ECU_FAMILY_M797,
    ECU_FAMILY_UNKNOWN,
    M797_FLASH_START,
    M797_FLASH_END,
)
from flasher.logging import logger
from flasher.immo import cli_immo, cli_immo_info
from flasher.lineswap import generate_sie, generate_bin
from flasher.rsw import rsw_handler
from flasher.mtos import mtos_handler, attach_session, KERNEL_MODES
from flasher import bsl
from flasher.kernel import KERNEL_TIMING
from _version import __version__

def cli_read_eeprom(ecu, address_start=None, address_stop=None,
                    escalate_privileges=False, output_filename=None):
    return SimkOperations(ecu).read(address_start, address_stop, escalate_privileges, output_filename)


def cli_flash_eeprom(ecu, input_filename, flash_calibration=True, flash_program=True):
    print('[*] Loading up {}'.format(input_filename))
    with open(input_filename, 'rb') as source:
        image = source.read()
    print('[*] Loaded {} bytes'.format(len(image)))
    operations = SimkOperations(ecu)
    operations.plan_flash(image, flash_calibration, flash_program)
    if input('[?] Ready to flash! Do you wish to continue? [y/n]: ') != 'y':
        print('[!] Aborting!')
        return
    operations.flash(image, flash_calibration, flash_program)


def cli_clear_adaptive_values (ecu):
	print('[*] Clearing adaptive values.. ', end='')
	ecu.clear_adaptive_values()
	print('Done! Turn off ignition for 10 seconds to apply changes.')

def cli_read_dtcs (ecu):
	ecu.bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.DEFAULT, ecu.get_desired_baudrate().index))

	display_dtcs(ecu.bus)

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

def handle_m797(bus: kwp2000.Kwp2000Protocol, args):
    """Route Kefico operations before entering the SIMK session/security path."""
    unsupported = [
        '--' + name.replace('_', '-')
        for name in (
            'flash_program', 'immo', 'clear_adaptive_values', 'logger',
            'rsw_boot1', 'rsw_boot2', 'rsw_asw', 'rsw_cal', 'rsw_full',
            'rsw_virginize', 'mtos',
        )
        if getattr(args, name, False)
    ]
    if unsupported:
        raise ValueError('Not yet supported on M7.9.7: ' + ', '.join(unsupported))

    read_region = None
    profile = None
    if args.read or args.read_calibration or args.read_program:
        if sum(bool(value) for value in (args.read, args.read_calibration, args.read_program)) > 1:
            raise ValueError('Select only one read operation')
        if args.read_calibration or args.read_program:
            if args.address_start is not None or args.address_stop is not None:
                raise ValueError('Custom addresses require --read')
            name = 'calibration' if args.read_calibration else 'program'
            read_region = KEFICO_LAYOUT['regions'][name]['read']
        else:
            start = M797_FLASH_START if args.address_start is None else args.address_start
            stop = M797_FLASH_END + 1 if args.address_stop is None else args.address_stop
            if not M797_FLASH_START <= start < stop <= M797_FLASH_END + 1:
                raise ValueError('Requested read range is outside M7.9.7 external flash')
            read_region = {'address': start, 'size': stop - start}

    if read_region or args.flash or args.flash_calibration:
        profile = m797_profile_from_selector(args.desired_baudrate)
    if args.flash and args.flash_calibration:
        raise ValueError('Select either --flash or --flash-calibration')

    if (args.flash or args.flash_calibration) and (args.address_start is not None or args.address_stop is not None):
        raise ValueError('Custom flash addresses are not supported on M7.9.7; use --flash-calibration')

    if args.id:
        cli_m797_id(bus)
    if args.read_dtcs:
        cli_m797_read_dtcs(bus)

    if read_region:
        calibration_id, engine_id = 'UNKNOWN', None
        try:
            calibration_id = get_m797_calibration_id(bus)
            print('[+] Detected calibration: {}'.format(calibration_id))
        except (kwp2000.Kwp2000NegativeResponseException, TimeoutException, RuntimeError) as exc:
            print('[!] Calibration identifier 0x90 unavailable: {}'.format(exc))
            print('[*] Continuing with calibration-agnostic read probing.')
        try:
            engine_id = get_m797_engine_id(bus)
            print('[+] Detected engine: {}'.format(engine_id))
        except (kwp2000.Kwp2000NegativeResponseException, TimeoutException, RuntimeError) as exc:
            print('[!] Engine identifier 0x97 unavailable: {}'.format(exc))
        output_filename = args.output or make_m797_read_filename(calibration_id, engine_id, bus)
        m797_read(
            bus, calibration_id, output_filename, read_profile=profile,
            address_start=read_region['address'], size=read_region['size'],
        )

    if args.flash or args.flash_calibration:
        m797_flash(
            bus, args.flash_calibration or args.flash, programming_profile=profile,
            calibration_only=bool(args.flash_calibration),
        )

def load_config (config_filename):
	with open(config_filename, 'r') as source:
		return yaml.safe_load(source)

def load_arguments ():
	parser = argparse.ArgumentParser(prog='GKFlasher v{}'.format(__version__))
	parser.add_argument('-p', '--protocol', help='Protocol to use. canbus or kline')
	parser.add_argument('-i', '--interface', help='Linux: can0 for socketCAN. | Windows: gs_usb:0, slcan:COM69, pcan:PCAN_USBBUS1, vector:0 | J2534: j2534, j2534:openport')
	parser.add_argument('-b', '--baudrate', type=int)
	parser.add_argument('--desired-baudrate', type=lambda x: int(x,0), help='Desired KWP baudrate selector/index. SIMK: 0x91=10400, 0x92=20000, 0x03=40000, 0x04=60000, 0x05=125000  | M7.9.7: 0x64=57600, 0x82=108800.')
	parser.add_argument('--ecu-family', choices=['auto', ECU_FAMILY_SIMK, ECU_FAMILY_M797], default='auto', help='Force ECU family selection (auto/simk/m797). Useful for recovery or bypassing family auto-detection.')
	parser.add_argument('-f', '--flash', help='Filename to full flash')
	parser.add_argument('--flash-calibration', help='Filename to flash calibration zone from')
	parser.add_argument('--flash-program', help='Filename to flash program zone from')
	parser.add_argument('-r', '--read', action='store_true')
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
	parser.add_argument('--mtos-mode', help='MTOS mode: hello (safe self-test), dump, payload, loader, '
		'probe/read/fullflash (BSL kernel: dry run, whole flash read, whole flash write incl. boot sectors)',
		default='hello', choices=['hello', 'dump', 'payload', 'loader', 'probe', 'read', 'fullflash'])
	parser.add_argument('--mtos-payload', help='BIN file with payload body (payload mode), second stage (loader mode) or full 512 KB image (fullflash mode)')
	parser.add_argument('--mtos-key', help='Key to use for Siemens access level', type=lambda x: int(x,0))
	parser.add_argument('--mtos-attach', help='Pick up the BSL kernel a failed probe/read/fullflash left running (ECU still powered). '
		'Use the same --desired-baudrate as that session', action='store_true')
	parser.add_argument('--bsl', help='Bootstrap loader: ECU in boot mode, on the K-line interface', action='store_true')
	parser.add_argument('--bsl-mode', help='BSL mode: hwinfo (CPU and flash chip), read (external flash), readint (internal ROM), '
		'write (whole external flash incl. boot sectors, changed sectors only)', default='hwinfo', choices=bsl.MODES)
	parser.add_argument('--bsl-image', help='Whole flash image to write (write mode)')
	parser.add_argument('--bsl-baudrate', help='Baudrate (default: {})'.format(bsl.DEFAULT_BAUDRATE), type=int, default=bsl.DEFAULT_BAUDRATE)
	parser.add_argument('--bsl-driver', help='Flash driver: i4 (SIMK43 2.0) or v6. Default: detect it', default='auto', choices=bsl.DRIVER_CHOICES)
	parser.add_argument('--bsl-rom-size', help='Internal ROM size to read (readint mode, default: 0x{:X})'.format(bsl.INTERNAL_ROM_SIZE),
		type=lambda x: int(x,0), default=bsl.INTERNAL_ROM_SIZE)
	args = parser.parse_args()

	logging_levels = [logging.WARNING, logging.INFO, logging.DEBUG]
	logging.basicConfig(level=logging_levels[min(args.verbose, len(logging_levels) -1)])
	logging.getLogger("can").setLevel(logging.CRITICAL)

	GKFlasher_config = load_config(args.config)

	if args.protocol:
			GKFlasher_config['protocol'] = args.protocol

	if args.interface:
		GKFlasher_config[GKFlasher_config['protocol']]['interface'] = args.interface

	return GKFlasher_config, args

def select_device (interface: str, bus_type: Bus) -> DeviceABC:
	try:
		return find_device(interface, {bus_type})
	except DeviceException:
		print('[!] Interface not found: {}'.format(interface))

	devices = discover({bus_type})
	if not devices:
		print('[!] No interfaces found.')
		raise SystemExit(1)

	print('[*] Available interfaces:')
	for index, device in enumerate(devices, start=1):
		print('    {}. {}'.format(index, device.description()))

	while True:
		try:
			index = int(input('Select interface [1]: ').strip() or '1')
		except ValueError:
			print('Please enter a valid number.')
			continue
		if 1 <= index <= len(devices):
			return devices[index - 1]
		print('Enter a number from 1 to {}.'.format(len(devices)))

def initialize_bus (protocol: str, protocol_config: dict) -> tuple[DeviceABC, kwp2000.Kwp2000Protocol]:
	bus_type = Bus(protocol)
	device = select_device(protocol_config['interface'], bus_type)
	print('[*] Interface: {}'.format(device.description()))

	return device, open_connection(device, bus_type, protocol_config)

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
	if args.ecu_family == ECU_FAMILY_M797 and not isinstance(bus.transport, Kwp2000OverKLineTransport):
		raise ValueError('Kefico/Bosch M7.9.7 requires a K-Line interface')
	bus.init(kwp2000.commands.StartCommunication(), keepalive_command=kwp2000.commands.TesterPresent(kwp2000.enums.ResponseType.REQUIRED), keepalive_delay=1.5)
	bus.transport.set_buffer_size(20)

	# Detect the family before issuing ECU-specific session or security commands.
	if isinstance(bus.transport, Kwp2000OverKLineTransport):
		if args.ecu_family != 'auto':
			ecu_family = args.ecu_family
			print('[*] ECU family forced to {}'.format(ecu_family))

		else:
			print('[*] Detecting ECU family...')

			ecu_family = detect_ecu_family(bus)

			if ecu_family == ECU_FAMILY_UNKNOWN:
				# Shared programming operations require a known or explicitly selected family.
				if args.flash or args.flash_calibration or args.flash_program:
					ecu_family = cli_choose_ecu_family()
					if ecu_family is None:
						return
				else:
					print('[!] Unable to identify ECU family. Check the ECU connection and ignition.')
					return

		if ecu_family == ECU_FAMILY_M797:
			print('[*] Found! Kefico/Bosch M7.9.7')
		elif ecu_family == ECU_FAMILY_SIMK:
			print('[*] Found! Siemens/Continental')

		if ecu_family == ECU_FAMILY_M797:
			handle_m797(bus, args)
			return


	if args.desired_baudrate and BAUDRATES.get(args.desired_baudrate) != 10400:
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
			bus.transport.channel.set_baudrate(desired_baudrate.baudrate)
		except TimeoutException:
			# it's possible that the bus is already running at the desired baudrate - let's check
			bus.transport.channel.reset_buffers()
			bus.transport.channel.set_baudrate(desired_baudrate.baudrate)
			bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING, desired_baudrate.index))
	else:
		# @todo: not ideal, but its a bridge towards moving this completely to the ECU class. it was a mess
		desired_baudrate = DesiredBaudrate(index=None, baudrate=10400)
		print('[*] Trying to start diagnostic session')
		bus.execute(kwp2000.commands.StartDiagnosticSession(kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING))
		
	bus.transport.set_timeout(12)

	print('[*] Set timing parameters to maximum')
	if not negotiate_timing(bus):
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
		display_identification(bus)
		cli_immo_info(ecu)


	if (args.read):
		cli_read_eeprom(ecu, address_start=args.address_start, address_stop=args.address_stop, escalate_privileges=True, output_filename=args.output)
	if (args.read_calibration):
		cli_read_eeprom(ecu, address_start=ecu.get_region('calibration').read.address, address_stop=ecu.get_region('calibration').read.address+ecu.get_region('calibration').read.size, output_filename=args.output)
	if (args.read_program):
		address_start = ecu.get_region('program').read.address
		address_stop = address_start+ecu.get_region('program').read.size
		cli_read_eeprom(ecu, address_start=address_start, address_stop=address_stop, output_filename=args.output)
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
		mtos_address = args.address_start if args.address_start is not None else 0x000000
		if args.address_stop is not None and args.address_start is not None:
			mtos_length = args.address_stop - args.address_start
		else:
			mtos_length = 0x40
		mtos_handler(ecu, args.mtos_key, mode=args.mtos_mode,
			payload_filename=args.mtos_payload, address=mtos_address, length=mtos_length,
			output_filename=args.output, attach_hint=mtos_attach_hint(args))

def mtos_attach_hint (args) -> str:
	'''
	The command that picks a kernel left running by this session back up
	'''
	command = 'python gkflasher.py -p {} -i {} --mtos --mtos-mode {} --mtos-attach'.format(
		GKFlasher_config['protocol'], GKFlasher_config[GKFlasher_config['protocol']]['interface'], args.mtos_mode)
	if args.mtos_payload:
		command += ' --mtos-payload {}'.format(args.mtos_payload)
	if args.desired_baudrate:
		command += ' --desired-baudrate 0x{:02X}'.format(args.desired_baudrate)
	return command

def mtos_attach (bus, args) -> None:
	if args.mtos_mode not in KERNEL_MODES:
		print('[!] --mtos-attach works with --mtos-mode {}'.format(', '.join(KERNEL_MODES)))
		return
	if args.mtos_mode == 'fullflash' and not args.mtos_payload:
		print('[!] fullflash mode requires --mtos-payload (the full 512 KB image)')
		return
	baudrate = BAUDRATES.get(args.desired_baudrate, 10400) if args.desired_baudrate else 10400
	attach_session(bus, args.mtos_mode, image_filename=args.mtos_payload, output_filename=args.output,
		baudrate=baudrate, attach_hint=mtos_attach_hint(args))

def bsl_main (args) -> int:
	'''
	BSL over the bare K-line, no KWP2000 session

	:return: exit code
	'''
	interface = args.interface or GKFlasher_config['kline']['interface']
	device = select_device(interface, Bus.KLINE)
	print('[*] Interface: {}'.format(device.description()))
	channel = None
	try:
		channel = device.kline(baudrate=args.bsl_baudrate, timing=KERNEL_TIMING)
		channel.open()
		finished = bsl.bsl_handler(channel, args.bsl_mode, image_filename=args.bsl_image, output_filename=args.output,
			driver=args.bsl_driver, rom_size=args.bsl_rom_size)
		return 0 if finished else 1
	except GkbusException as e:
		print('[!] K-line interface: {}'.format(e))
		return 1
	except KeyboardInterrupt:
		print('\n[!] Interrupted')
		return 1
	finally:
		try:
			if channel is not None:
				channel.close()
			device.close()
		except GkbusException as e:
			print('[!] Couldn\'t close the interface: {}'.format(e))

def packet2hex (packet: RawPacket) -> str:
	direction = 'Incoming' if packet.direction == PacketDirection.INCOMING else 'Outgoing'
	data = ' '.join([hex(x)[2:].zfill(2) for x in packet.data])
	parsed = 'RawPacket({}, ts={}, data={})'.format(direction, packet.timestamp, data)
	return parsed

def cli():
	global GKFlasher_config
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

	if args.bsl:
		code = bsl_main(args)
		return code
	
	print('[*] Selected protocol: {}. Initializing..'.format(GKFlasher_config['protocol']))
	try:
		device, bus = initialize_bus(GKFlasher_config['protocol'], GKFlasher_config[GKFlasher_config['protocol']])
	except GkbusException as e:
		print('[!] Failed to open the interface: {}'.format(e))
		sys.exit(1)

	exit_code = 0
	try:
		if args.mtos and args.mtos_attach:
			mtos_attach(bus, args)
		else:
			main(bus, args)
	except KeyboardInterrupt:
		exit_code = 130
	except Exception:
		exit_code = 1
		print('[!] Exception in main thread!')
		print(traceback.format_exc())
		print('[*] Dumping buffer:')
		print('\n'.join(packet2hex(packet) for packet in bus.transport.buffer_dump()))
	finally:
		try:
			if not args.mtos:
				release_timing(bus)
		finally:
			if not close_connection(bus, device):
				exit_code = 1
	return exit_code


if __name__ == '__main__':
	sys.exit(cli())
