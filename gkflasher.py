import argparse, time, yaml, logging
from alive_progress import alive_bar
from gkbus.kwp.commands import *
from gkbus.kwp import KWPNegativeResponseException
import gkbus
from memory import find_eeprom_size_and_calibration, read_memory
from ecu import print_ecu_identification, enable_security_access
from checksum import fix_checksum

def read_vin(bus):
	vin_hex = bus.execute(ReadEcuIdentification(0x90)).get_data()[1:]
	return ''.join([chr(x) for x in vin_hex])

def read_voltage(bus):
	print('[*] Trying to read voltage (0x42/SAE_VPWR).. ', end='')

	voltage_hex = bus.execute(ReadStatusOfDTC(0x42)).get_data()
	
	voltage = hex(voltage_hex[0]) + hex(voltage_hex[1])[2:]
	voltage = int(voltage, 16)/1000
	print('{}V'.format(voltage))

def read_eeprom (bus, eeprom_size, address_start=0x000000, address_stop=None, output_filename=None):
	if (address_stop == None):
		address_stop = eeprom_size

	print('[*] Reading from {} to {}'.format(hex(address_start), hex(address_stop)))

	requested_size = address_stop-address_start
	print('[*] Requested area\'s size: {} bytes. initializing a table filled with {} 0xFF\'s.'.format(requested_size, eeprom_size))
	eeprom = [0xFF]*eeprom_size

	with alive_bar(requested_size+1, unit='B') as bar:
		fetched = read_memory(bus, address_start=address_start, address_stop=address_stop, progress_callback=bar)
	address_start = address_start - 0x080000 # !!!!!! FIXME TODO ALERT ACHTUNG
	eeprom_end = address_start + len(fetched)
	eeprom[address_start:eeprom_end] = fetched

	print('[*] received {} bytes of data'.format(len(fetched)))

	if (output_filename == None):
		output_filename = "output_{}_to_{}.bin".format(hex(address_start), hex(address_stop))
	
	with open(output_filename, "wb") as file:
		file.write(bytes(eeprom))

	print('[*] saved to {}'.format(output_filename))

def write (bus, input_filename, flash_start, flash_size, payload_start, payload_stop, eeprom):
	payload = eeprom[payload_start:payload_stop]
	print('[*] Preparing to write {} bytes @ {}.'.format(flash_size, hex(flash_start)))
	print('[*] Payload starts at {} in {}'.format(hex(payload_start), input_filename))

	print('    [*] request download')
	print(bus.execute(RequestDownload(offset=flash_start, size=flash_size)))

	packets_to_write = int(flash_size/254)
	packets_written = 0
	while packets_to_write >= packets_written:
		print('    [*] transfer data {}/{}'.format(packets_written, packets_to_write))
		payload_packet_start = packets_written*254
		payload_packet_end = payload_packet_start+254
		payload_packet = payload[payload_packet_start:payload_packet_end]

		#print('trying to write the following')
		#print([hex(x) for x in payload_packet])
		bus.execute(TransferData(list(payload_packet)))

		packets_written += 1

	print('    [*] transfer exit')
	print(bus.execute(RequestTransferExit()).get_data())

def flash_eeprom (bus, input_filename):
	print('\n[*] Loading up {}'.format(input_filename))

	with open(input_filename, 'rb') as file:
		eeprom = file.read()

	print('[*] Loaded {} bytes'.format(len(eeprom)))
	calibration = eeprom[0x090040:0x090048]
	calibration = ''.join([chr(x) for x in calibration])
	print('[*] {} calibration version: {}'.format(input_filename, calibration))

	if (input('[?] Ready to flash! Do you wish to continue? [y/n]: ') != 'y'):
		print('[!] Aborting!')
		return

	print('[*] start routine 0x01')
	bus.execute(StartRoutineByLocalId([0x01]))

	print('[*] start routine 0x00')
	bus.execute(StartRoutineByLocalId([0x00]))

	# unknown section
	flash_start = 0x8A0010
	flash_size = 0x05FFF0
	payload_start = 0x020010
	payload_stop = payload_start+flash_size
	write(bus, input_filename, flash_start, flash_size, payload_start, payload_stop, eeprom)

	# cal section

	flash_start = 0x890000
	flash_size = 0x00FFF0

	payload_start = 0x010000
	payload_stop = payload_start + flash_size
	write(bus, input_filename, flash_start, flash_size, payload_start, payload_stop, eeprom)


	print('    [*] start routine 0x02')
	print(bus.execute(StartRoutineByLocalId([0x02])).get_data())

	bus.execute(WriteDataByLocalIdentifier([0x99, 0x20, 0x04, 0x10, 0x20]))
	bus.execute(WriteDataByLocalIdentifier([0x98, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4C, 0x31, 0x30, 0x30]))
	print('    [*] ecu reset')
	print(bus.execute(ECUReset([0x01])).get_data())


def load_config (config_filename):
	return yaml.safe_load(open('gkflasher.yml'))

def load_arguments ():
	parser = argparse.ArgumentParser(prog='GKFlasher')
	parser.add_argument('-p', '--protocol', help='Protocol to use. canbus or kline')
	parser.add_argument('-i', '--interface')
	parser.add_argument('-b', '--baudrate')
	parser.add_argument('-f', '--flash', help='Filename to flash')
	parser.add_argument('-r', '--read', action='store_true')
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
	except KWPNegativeResponseException:
		pass

	bus.init()

	print('[*] Trying to start diagnostic session')
	bus.execute(StartDiagnosticSession())

	print('[*] Access Timing Parameters')
	bus.execute(AccessTimingParameters([0x00]))

	print('[*] Access Timing Parameters 2')
	bus.execute(AccessTimingParameters([0x03, 0x0, 0x02, 0x0, 0xFE, 0x0]))

	enable_security_access(bus)

	#print_ecu_identification(bus)

	print('[*] Trying to find eeprom size and calibration..')
	if (args.eeprom_size):
		print('[!] EEPROM size was selected by the user as {} bytes!'.format(args.eeprom_size))
		if (input('[?] Are you absolutely sure you know what you\'re doing? This could potentially result in bricking your ECU [y/n]: ') != 'y'):
			print('[!] Aborting.')
			return False
		eeprom_size = args.eeprom_size
	else:
		eeprom_size, eeprom_size_human, calibration = find_eeprom_size_and_calibration(bus)
		print('[*] Found! EEPROM is {}mbit, calibration: {}'.format(eeprom_size_human, calibration))

	if (args.read):
		read_eeprom(bus, eeprom_size, address_start=args.address_start, address_stop=args.address_stop, output_filename=args.output)

	if (args.flash):
		flash_eeprom(bus, input_filename=args.flash)

if __name__ == '__main__':
	main()