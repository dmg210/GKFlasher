import argparse, time, yaml, logging, sys
from alive_progress import alive_bar
from gkbus.kwp.commands import *
from gkbus.kwp.enums import *
from gkbus.kwp import KWPNegativeResponseException
import gkbus
from memory import read_memory, write_memory
from ecu import identify_ecu, print_ecu_identification, enable_security_access, ECUIdentificationException, ECU_IDENTIFICATION_TABLE
from checksum import fix_checksum

def read_vin(bus):
	vin_hex = bus.execute(ReadEcuIdentification(0x90)).get_data()[1:]
	return ''.join([chr(x) for x in vin_hex])

def read_eeprom (bus, ecu, eeprom_size, address_start=0x000000, address_stop=None, output_filename=None):
	if (address_stop == None):
		address_stop = eeprom_size

	print('[*] Reading from {} to {}'.format(hex(address_start), hex(address_stop)))

	requested_size = address_stop-address_start
	print('[*] Requested area\'s size: {} bytes. initializing a table filled with {} 0xFF\'s.'.format(requested_size, eeprom_size))
	eeprom = [0xFF]*eeprom_size

	with alive_bar(requested_size+1, unit='B') as bar:
		fetched = read_memory(ecu, address_start=address_start, address_stop=address_stop, progress_callback=bar)

	eeprom_start = ecu.calculate_bin_offset(address_start)
	eeprom_end = eeprom_start + len(fetched)
	eeprom[eeprom_start:eeprom_end] = fetched

	print('[*] received {} bytes of data'.format(len(fetched)))

	if (output_filename == None):
		output_filename = "output_{}_to_{}.bin".format(hex(address_start), hex(address_stop))
	
	with open(output_filename, "wb") as file:
		file.write(bytes(eeprom))

	print('[*] saved to {}'.format(output_filename))

def flash_eeprom (ecu, input_filename, flash_calibration=True, flash_program=True):
	print('\n[*] Loading up {}'.format(input_filename))

	with open(input_filename, 'rb') as file:
		eeprom = file.read()

	print('[*] Loaded {} bytes'.format(len(eeprom)))

	if (input('[?] Ready to flash! Do you wish to continue? [y/n]: ') != 'y'):
		print('[!] Aborting!')
		return

	if flash_program:
		print('[*] start routine 0x00 (erase program code section)')
		ecu.bus.execute(StartRoutineByLocalIdentifier(0x00))

		flash_start = 0x8A0010
		flash_size = 0x05FFF0
		payload_start = 0x020010
		payload_stop = payload_start+flash_size
		payload = eeprom[payload_start:payload_stop]

		with alive_bar(flash_size, unit='B') as bar:
			write_memory(ecu, payload, flash_start, flash_size, progress_callback=bar)

	if flash_calibration:
		print('[*] start routine 0x01 (erase calibration section)')
		ecu.bus.execute(StartRoutineByLocalIdentifier(0x01))

		flash_start = 0x890000
		flash_size = 0x00FFF0
		payload_start = 0x010000
		payload_stop = payload_start + flash_size
		payload = eeprom[payload_start:payload_stop]

		with alive_bar(flash_size, unit='B') as bar:
			write_memory(ecu, payload, flash_start, flash_size, progress_callback=bar)

	ecu.bus.set_timeout(300)
	print('    [*] start routine 0x02')
	ecu.bus.execute(StartRoutineByLocalIdentifier(0x02)).get_data()
	ecu.bus.set_timeout(12)

	print('    [*] ecu reset')
	ecu.bus.execute(ECUReset(ResetMode.POWER_ON_RESET)).get_data()


def load_config (config_filename):
	return yaml.safe_load(open('gkflasher.yml'))

def load_arguments ():
	parser = argparse.ArgumentParser(prog='GKFlasher')
	parser.add_argument('-p', '--protocol', help='Protocol to use. canbus or kline')
	parser.add_argument('-i', '--interface')
	parser.add_argument('-b', '--baudrate')
	parser.add_argument('-f', '--flash', help='Filename to full flash')
	parser.add_argument('-fc', '--flash-calibration', help='Filename to flash calibration zone from')
	parser.add_argument('-fp', '--flash-program', help='Filename to flash program zone from')
	parser.add_argument('-r', '--read', action='store_true')
	parser.add_argument('-rc', '--read-calibration', action='store_true')
	parser.add_argument('-crc', '--fix-checksum')
	parser.add_argument('-o', '--output', help='Filename to save the EEPROM dump')
	parser.add_argument('-s', '--address-start', help='Offset to start reading/flashing from.', type=lambda x: int(x,0), default=0x000000)
	parser.add_argument('-e', '--address-stop', help='Offset to stop reading/flashing at.', type=lambda x: int(x,0))
	parser.add_argument('--eeprom-size', help='EEPROM size in bytes. ONLY USE THIS IF YOU REALLY, REALLY KNOW WHAT YOU\'RE DOING!!', type=int)
	parser.add_argument('-c', '--config', help='Config filename', default='gkflasher.yml')
	parser.add_argument('-v', '--verbose', action='count', default=0)
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

def initialize_bus (protocol, protocol_config):
	interface = protocol_config['interface']
	del protocol_config['interface']

	return gkbus.Bus(protocol, interface=interface, **protocol_config)

def cli_choose_ecu ():
	print('[!] Failed to identify your ECU!')
	print('[*] If you know what you\'re doing (like trying to revive a soft bricked ECU), you can choose your ECU from the list below:')

	for index, ecu in enumerate(ECU_IDENTIFICATION_TABLE):
		print('    [{}] {}'.format(index, ecu['ecu'].get_name()))

	try:
		choice = int(input('ECU or any other char to abort: '))
	except ValueError:
		print('[!] Aborting..')
		sys.exit(1)

	try:
		ECU_IDENTIFICATION_TABLE[choice]
	except IndexError:
		print('[!] Invalid value!')
		return cli_choose_ecu()

	return ECU_IDENTIFICATION_TABLE[choice]

def cli_identify_ecu (bus):
	print('[*] Trying to identify ECU automatically.. ')
	
	try:
		ecu = identify_ecu(bus)
	except ECUIdentificationException:
		ecu = cli_choose_ecu()['ecu']
		ecu.set_bus(bus)

	print('[*] Found! {}'.format(ecu.get_name()))
	return ecu

def main():
	GKFlasher_config, args = load_arguments()

	if (args.fix_checksum):
		fix_checksum(filename=args.fix_checksum)
		return 

	print('[*] Selected protocol: {}. Initializing..'.format(GKFlasher_config['protocol']))
	bus = initialize_bus(GKFlasher_config['protocol'], GKFlasher_config[GKFlasher_config['protocol']])	

	try:
		bus.execute(StopDiagnosticSession())
		bus.execute(StopCommunication())
	except (KWPNegativeResponseException, gkbus.GKBusTimeoutException):
		pass

	bus.init()

	print('[*] Trying to start diagnostic session')
	bus.execute(StartDiagnosticSession(DiagnosticSession.FLASH_REPROGRAMMING))
	bus.set_timeout(12)

	print('[*] Access Timing Parameters')
	try:
		available_timing = bus.execute(
			AccessTimingParameters(
				TimingParameterIdentifier.READ_LIMITS_OF_POSSIBLE_TIMING_PARAMETERS
			)
		).get_data()

		bus.execute(
			AccessTimingParameters(
				TimingParameterIdentifier.SET_TIMING_PARAMETERS_TO_GIVEN_VALUES, 
				*available_timing[1:]
			)
		)
	except KWPNegativeResponseException:
		print('[!] Not supported on this ECU!')

	enable_security_access(bus)

	#print_ecu_identification(bus)

	ecu = cli_identify_ecu(bus)

	print('[*] Trying to find calibration..')
	if (args.eeprom_size):
		print('[!] EEPROM size was selected by the user as {} bytes!'.format(args.eeprom_size))
		if (input('[?] Are you absolutely sure you know what you\'re doing? This could potentially result in bricking your ECU [y/n]: ') != 'y'):
			print('[!] Aborting.')
			return False
		eeprom_size = args.eeprom_size
	else:
		eeprom_size, eeprom_size_human = ecu.get_eeprom_size_bytes(), ecu.get_eeprom_size_human()
		description, calibration = ecu.get_calibration_description(), ecu.get_calibration()
		print('[*] Found! Description: {}, calibration: {}'.format(description, calibration))

	if (args.read):
		read_eeprom(bus, ecu, eeprom_size, address_start=args.address_start, address_stop=args.address_stop, output_filename=args.output)
	if (args.read_calibration):
		if (not args.output):
			args.output = 'output_calibration.bin'
		read_eeprom(bus, ecu, eeprom_size, address_start=0x090000, address_stop=0x090000+ecu.get_calibration_size_bytes(), output_filename=args.output)

	if (args.flash):
		flash_eeprom(ecu, input_filename=args.flash)
	if (args.flash_calibration):
		flash_eeprom(ecu, input_filename=args.flash_calibration, flash_calibration=True, flash_program=False)
	if (args.flash_program):
		flash_eeprom(ecu, input_filename=args.flash_program, flash_program=True, flash_calibration=False)

if __name__ == '__main__':
	main()