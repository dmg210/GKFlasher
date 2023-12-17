from gkbus.kwp.commands import ReadEcuIdentification, SecurityAccess, ReadMemoryByAddress
from gkbus.kwp import KWPNegativeResponseException

kwp_ecu_identification_parameters = [
	{'value': 0x86, 'name': 'DCS ECU Identification'},
	{'value': 0x87, 'name': 'DCX/MMC ECU Identification'},
	{'value': 0x88, 'name': 'VIN (original)'},
	{'value': 0x89, 'name': 'Diagnostic Variant Code'},
	{'value': 0x90, 'name': 'VIN (current)'},
	{'value': 0x96, 'name': 'Calibration identification'},
	{'value': 0x97, 'name': 'Calibration Verification Number'},
	{'value': 0x9A, 'name': 'ECU Code Fingerprint'},
	{'value': 0x9B, 'name': 'ECU Data Fingerprint'},
	{'value': 0x9C, 'name': 'ECU Code Software Identification'},
	{'value': 0x9D, 'name': 'ECU Data Software Identification'},
	{'value': 0x9E, 'name': 'ECU Boot Software Identification'},
	{'value': 0x9F, 'name': 'ECU Boot Fingerprint'},
	{'value': 0x8A, 'name': 'System supplier specific'},
	{'value': 0x8B, 'name': 'System supplier specific'},
	{'value': 0x8C, 'name': 'Hardware revision'},
	{'value': 0x8D, 'name': 'Hardware subsystem'},
	{'value': 0x8E, 'name': 'Calibration version'},
	{'value': 0x8F, 'name': 'System supplier specific'},
]

def print_ecu_identification (bus):
	print('[*] Reading ECU Identification..')
	for parameter in kwp_ecu_identification_parameters:
		try:
			value = bus.execute(ReadEcuIdentification(parameter['value'])).get_data()
		except KWPNegativeResponseException:
			continue

		value_hex = ' '.join([hex(x) for x in value[1:]])
		value_ascii = ''.join([chr(x) for x in value[1:]])

		print('')
		print('    [*] [{}] {}:'.format(hex(parameter['value']), parameter['name']))
		print('            [HEX]: {}'.format(value_hex))
		print('            [ASCII]: {}'.format(value_ascii))

def calculate_key(concat11_seed):
    key = 0
    index = 0
    
    while index < 0x10:
        if (concat11_seed & (1 << (index & 0x1f))) != 0:
            key = key ^ 0xffff << (index & 0x1f)
        index += 1
    
    return key

def get_security_key (seed):
	seed_concat = (seed[0]<<8) | seed[1]
	key = calculate_key(seed_concat)

	key_byte1 = (key >> 8) & 0xFF
	key_byte2 = key & 0xFF
	return [key_byte1, key_byte2]

def enable_security_access (bus):
	print('[*] Security Access 1')
	seed = bus.execute(SecurityAccess([0x01])).get_data()[1:]

	if (seed == [0x0, 0x0]):
		print('[*] ECU is not locked.')
		return

	key = get_security_key(seed)

	print('[*] Security Access 2')
	bus.execute(SecurityAccess([0x02] + key))

class ECU:
	def __init__ (self, name: str, eeprom_size_bytes: int, eeprom_size_human: int, memory_offset: int, bin_offset: int):
		self.name = name
		self.eeprom_size_bytes, self.eeprom_size_human = eeprom_size_bytes, eeprom_size_human
		self.memory_offset, self.bin_offset = memory_offset, bin_offset

	def get_name (self) -> str:
		return self.name 

	def get_eeprom_size_bytes (self) -> int:
		return self.eeprom_size_bytes

	def get_eeprom_size_human (self) -> int:
		return self.eeprom_size_human

	def set_bus (self, bus):
		self.bus = bus
		return self

	def calculate_memory_offset (self, offset: int) -> int:
		return offset + self.memory_offset

	def calculate_bin_offset (self, offset: int) -> int:
		return offset + self.bin_offset

	def get_calibration (self):
		calibration = self.bus.execute(ReadMemoryByAddress(offset=self.calculate_memory_offset(0x090000), size=8)).get_data()
		return ''.join([chr(x) for x in calibration])

	def get_calibration_description (self):
		description = self.bus.execute(ReadMemoryByAddress(offset=self.calculate_memory_offset(0x090040), size=8)).get_data()
		return ''.join([chr(x) for x in description])

ECU_IDENTIFICATION_TABLE = [
	{
		'offset': 0xA00A0,
		'expected': [54, 54, 51, 54],
		'ecu': ECU(
			name = 'SIMK43 8mbit',
			eeprom_size_bytes = 1048575,
			eeprom_size_human = 8,
			memory_offset = 0,
			bin_offset = 0
		)
	},
	{
		'offset': 0x88040,
		'expected': [99, 97, 54, 53],
		'ecu': ECU(
			name = 'SIMK43 V6 4mbit',
			eeprom_size_bytes = 524287,
			eeprom_size_human = 4,
			memory_offset = -0x8000,
			bin_offset = -0x080000
		)
	},
	{
		'offset': 0x090040,
		'expected': [99, 97, 54, 54],
		'ecu': ECU(
			name = 'SIMK43 2.0 4mbit',
			eeprom_size_bytes = 524287,
			eeprom_size_human = 4,
			memory_offset = 0,
			bin_offset = -0x080000
		)
	},
	{
		'offset': 0x48040,
		'expected': [99, 97, 54, 54],
		'ecu': ECU(
			name = 'SIMK41 2mbit',
			eeprom_size_bytes = 262143,
			eeprom_size_human = 2,
			memory_offset = -0x48000,
			bin_offset = -0x080000 - 1
		)
	}
]

def identify_ecu (bus) -> ECU:
	for ecu_identifier in ECU_IDENTIFICATION_TABLE:
		try:
			result = bus.execute(ReadMemoryByAddress(offset=ecu_identifier['offset'], size=4)).get_data()
		except KWPNegativeResponseException:
			continue

		if result == ecu_identifier['expected']:
			ecu = ecu_identifier['ecu']
			ecu.set_bus(bus)
			return ecu
	raise Exception('Failed to identify ECU!')