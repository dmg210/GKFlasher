"""SIMK memory layouts and chained CRC16 checksum correction."""

import copy
import crcmod

cks_types = [ # todo: incorporate into ECU definitions
	{
        'name': '2mbit',
        'identification_flag_address': 0xFEFE,
        'regions': [
			{
	        	'name': 'Boot',
		        'flag_address': 0xDEFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EF4,
		        'bin_offset': 0
		    },
        	{
	        	'name': 'Calibration', 
		        'flag_address': 0xFEFE,
		        'init_address': 0x00800C,
		        'cks_address': 0x0FEE0,
		        'bin_offset': -0x040000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0xFEFE,
		    	'init_address': 0x010052,
		    	'cks_address': 0x010010,
		    	'bin_offset': -0x040000
		    }
	    ]
	},
	{
        'name': '4mbit (FL2)',
        'identification_flag_address': 0x16135, # This is a random "OK" towards the end of the cal zone.
        'regions': [
			{
	        	'name': 'Boot',
		        'flag_address': 0x017EFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EEC, # 663057/58
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'MTOS',
		    	'flag_address': 0x017EFE,
		    	'init_address': 0xC012,
		    	'cks_address': 0xC000,
		    	'bin_offset': 0
		    },
        	{
		        'name': 'Calibration',
		        'flag_address': 0x017EFE,
		        'init_address': 0x01000C,
		        'cks_address': 0x017EE0,
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0x17EFE,
		    	'init_address': 0x020052,
		    	'cks_address': 0x020010,
		    	'bin_offset': -0x080000
		    }
	    ]
	},
	{
        'name': '4mbit',
        'identification_flag_address': 0x017EFE,
        'regions': [
			{
	        	'name': 'Boot',
		        'flag_address': 0x017EFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EF4,
		        'bin_offset': 0
		    },
		    {
		    	'name': 'MTOS',
		    	'flag_address': 0x017EFE,
		    	'init_address': 0xC012,
		    	'cks_address': 0xC000,
		    	'bin_offset': 0
		    },
        	{
		        'name': 'Calibration',
		        'flag_address': 0x017EFE,
		        'init_address': 0x01000C,
		        'cks_address': 0x017EE0,
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0x17EFE,
		    	'init_address': 0x020052,
		    	'cks_address': 0x020010,
		    	'bin_offset': -0x080000
		    }
	    ]
	},
	{
        'name': 'v6 (5WY17)',
        'identification_flag_address': 0xDEFE,
        'regions': [
        	{
	        	'name': 'Boot',
		        'flag_address': 0xDEFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EF4,
		        'bin_offset': 0
		    },	
        	{
	        	'name': 'Calibration',
		        'flag_address': 0xDEFE,
		        'init_address': 0x0800C,
		        'cks_address': 0xDEE0,
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0xDEFE,
		    	'init_address': 0x010052,
		    	'cks_address': 0x010010,
		    	'bin_offset': -0x080000
		    }
	    ]
	},
	{
        'name': 'v6 (5WY18+)',
        'identification_flag_address': 0xEEFE,
        'regions': [
        	{
	        	'name': 'Boot',
		        'flag_address': 0xEEFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EF4,
		        'bin_offset': 0
		    },	
        	{
	        	'name': 'Calibration',
		        'flag_address': 0xEEFE,
		        'init_address': 0x0800C,
		        'cks_address': 0xEEE0,
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0xEEFE,
		    	'init_address': 0x010052,
		    	'cks_address': 0x010010,
		    	'bin_offset': -0x080000
		    }
	    ]
	},	
	{
        'name': '8mbit',
        'identification_flag_address': 0x97EFE,
        'regions': [
			{
	        	'name': 'Boot',
		        'flag_address': 0x97EFE,
		        'init_address': 0x3FE4,
		        'cks_address': 0x3EEC,
		        'bin_offset': 0
		    },
		    {
		    	'name': 'MTOS',
		    	'flag_address': 0x97EFE,
		    	'init_address': 0xC012,
		    	'cks_address': 0xC000,
		    	'bin_offset': 0
		    },
		    {
		    	'name': 'RSW',
		    	'flag_address': 0x97EFE,
		    	'init_address': 0x82014,
		    	'cks_address': 0x82000,
		    	'bin_offset': 0
		    },
        	{
	        	'name': 'Calibration',
		        'flag_address': 0x97EFE,
		        'init_address': 0x09000C,
		        'cks_address': 0x097EE0,
		        'bin_offset': 0
	        },
		    {
		    	'name': 'Program',
				'flag_address': 0x97EFE,
		    	'init_address': 0x0A0052,
		    	'cks_address': 0x0A0010,
		    	'bin_offset': 0
		    }
	    ]
    },
	{
        'name': 'SIMK2K (Elantra 2.0 Beta)',
        'identification_flag_address': 0x01401E,
        'regions': [
        	{
		        'name': 'Calibration',
		        'flag_address': 0x01401E,
		        'init_address': 0x01200C,
		        'cks_address': 0x014000,
		        'bin_offset': -0x080000
		    },
		    {
		    	'name': 'Program',
		    	'flag_address': 0x17EFE,
		    	'init_address': 0x020052,
		    	'cks_address': 0x020010,
		    	'bin_offset': -0x080000
		    }
	    ]
	},
]

def read_and_reverse (payload, start, length):
	bts = list(payload[start:start+length])
	bts.reverse()
	return bts

def concat_3_bytes (payload):
	return ( (payload[0] << 8 | payload[1]) << 8 | payload[2])

def checksum (payload, start, stop, init):
	crc16 = crcmod.mkCrcFun(0x18005, initCrc=init)

	checksum = crc16(payload[start:stop])
	return checksum

def prepare_correction(payload, layout, report=print):
    """Calculate every selected region before returning a corrected copy."""
    corrected = bytearray(payload)
    fields = []
    for region in layout['regions']:
        name = region['name']
        address = region['cks_address']
        if address < 0 or address + 3 > len(payload):
            raise ValueError('Truncated {} checksum header'.format(name))
        count = payload[address + 2]
        report('[*] Calculating checksum for region {}'.format(name))
        report('[*] Amount of zones: {}'.format(count))
        if count in (0, 0xFF):
            report('[*] Skipping region {}'.format(name))
            continue
        initial = region['init_address']
        if initial < 0 or initial + 2 > len(payload):
            raise ValueError('Truncated {} checksum initial value'.format(name))
        value = int.from_bytes(payload[initial:initial + 2], 'little')
        for zone in range(count):
            record = address + zone * 8
            if record + 11 > len(payload):
                raise ValueError('Truncated {} checksum descriptor'.format(name))
            start = int.from_bytes(payload[record + 4:record + 7], 'little') + region['bin_offset']
            stop = int.from_bytes(payload[record + 8:record + 11], 'little') + region['bin_offset'] + 1
            if not 0 <= start < stop <= len(payload):
                raise ValueError('Invalid {} checksum range: {} - {}'.format(name, hex(start), hex(stop)))
            report('[*] Trying to find addresses of zone #{}.. {} - {}'.format(zone + 1, hex(start), hex(stop)))
            report('[*] Trying to find initial value.. {}'.format(hex(value)))
            value = checksum(payload, start, stop, value)
            report('[*] checksum of zone #{}: {}'.format(zone + 1, hex(value)))
        old = int.from_bytes(payload[address:address + 2], 'big')
        new = int.from_bytes(value.to_bytes(2, 'little'), 'big')
        fields.append({'name': name, 'offset': address, 'old': old, 'new': new})
        corrected[address:address + 2] = value.to_bytes(2, 'little')
        report('[*] OK! Current {} checksum: {}, new checksum: {}'.format(name, hex(old), hex(new)))
    if corrected == payload:
        report('[+] Image checksums already correct.')
    return bytes(corrected), fields


def detect_offsets(payload):
    for cks_type in cks_types:
        if payload[cks_type['identification_flag_address']:cks_type['identification_flag_address']+2] != b'OK':
            continue

        has_mtos = False
        for region in cks_type.get('regions', []):
            if region.get('name') == 'MTOS' and payload[region['init_address']:region['init_address']+2] == b'MT':
                has_mtos = True
                break

        fresh_type = copy.deepcopy(cks_type)

        if not has_mtos:
            fresh_type['regions'] = [
                r for r in fresh_type.get('regions', [])
                if r.get('name') != 'MTOS'
            ]

        return fresh_type

    return None
