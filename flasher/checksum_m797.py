"""Kefico/Bosch M7.9.7 additive checksums and boot integrity."""

import struct

from .utils import log
from ecu_definitions import (
    KEFICO_LAYOUT,
    M797_BOOT_BOUNDARY_CHECKSUM_OFFSET,
    M797_BOOT_HEADER_CHECKSUM_OFFSET,
    M797_CHECKSUM_ENTRY_SIZE,
    M797_CHECKSUM_TABLE_ENTRIES,
    M797_CHECKSUM_TABLE_OFFSET,
    M797_FLASH_END,
    M797_FLASH_START,
    M797_IMAGE_SIZE,
)

def m797_sum16_le(data: bytes) -> int:
    """Sum little-endian uint16 words into an unsigned 32-bit checksum."""
    if len(data) & 1:
        raise ValueError('M7.9.7 checksum range length must be even, got 0x{:X}'.format(len(data)))
    return sum(word[0] for word in struct.iter_unpack('<H', data)) & 0xFFFFFFFF


def m797_boot_boundary_checksum(image: bytes) -> int:
    """Sum the first/last LE words of each 8 KiB boot/program block; exclude calibration."""
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError('M7.9.7 boot checksum requires exactly 0x{:X} bytes'.format(M797_IMAGE_SIZE))
    total = 0
    for start, stop in ((0, 0x10000), (0x20000, M797_IMAGE_SIZE)):
        for block in range(start, stop, 0x2000):
            total += struct.unpack_from('<H', image, block)[0]
            total += struct.unpack_from('<H', image, block + 0x1FFE)[0]
    return total & 0xFFFFFFFF


def _m797_boot_header_checksum(image: bytes) -> int:
    return struct.unpack_from('<H', image, 0x8000)[0] + struct.unpack_from('<H', image, 0xFFFE)[0]


def m797_checksum_descriptors(image: bytes):
    """Parse 32 sixteen-byte records: LE uint32 start, inclusive end, sum and complement."""
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError('M7.9.7 checksum descriptors require a 512 KiB BIN')
    descriptors = []
    for index in range(M797_CHECKSUM_TABLE_ENTRIES):
        offset = M797_CHECKSUM_TABLE_OFFSET + index * M797_CHECKSUM_ENTRY_SIZE
        start, end = struct.unpack_from('<II', image, offset)
        if not M797_FLASH_START <= start <= end <= M797_FLASH_END:
            raise RuntimeError(
                'Invalid M7.9.7 checksum descriptor {} at BIN 0x{:05X}: '
                'start=0x{:08X}, end=0x{:08X}'.format(index, offset, start, end))
        size = end - start + 1
        if size & 1:
            raise RuntimeError('Odd-length M7.9.7 checksum descriptor {}: 0x{:06X}-0x{:06X}'.format(
                index, start, end))
        descriptors.append({'index': index, 'offset': offset, 'start': start, 'end': end, 'size': size})
    return descriptors


def _correct_m797_descriptors(corrected, descriptors):
    """Repair selected pairs before summing self-covered checksum tables."""
    # A valid checksum/complement pair contributes 2 * 0xFFFF to the word sum.
    # Normalize pairs first so replacing a self-covered entry preserves that sum.
    original = {d['offset']: bytes(corrected[d['offset'] + 8:d['offset'] + 16])
                for d in descriptors}
    for descriptor in descriptors:
        offset = descriptor['offset']
        stored = int.from_bytes(corrected[offset + 8:offset + 12], 'little')
        corrected[offset + 12:offset + 16] = (stored ^ 0xFFFFFFFF).to_bytes(4, 'little')

    for descriptor in descriptors:
        offset = descriptor['offset']
        start = descriptor['start'] - M797_FLASH_START
        stop = descriptor['end'] - M797_FLASH_START + 1
        calculated = m797_sum16_le(corrected[start:stop])
        corrected[offset + 8:offset + 12] = calculated.to_bytes(4, 'little')
        corrected[offset + 12:offset + 16] = (calculated ^ 0xFFFFFFFF).to_bytes(4, 'little')

    changes = []
    for descriptor in descriptors:
        offset = descriptor['offset']
        start = descriptor['start'] - M797_FLASH_START
        stop = descriptor['end'] - M797_FLASH_START + 1
        stored = int.from_bytes(corrected[offset + 8:offset + 12], 'little')
        inverse = int.from_bytes(corrected[offset + 12:offset + 16], 'little')
        if stored != m797_sum16_le(corrected[start:stop]) or inverse != (stored ^ 0xFFFFFFFF):
            raise RuntimeError('M7.9.7 checksum self-test failed for descriptor {}'.format(descriptor['index']))
        if corrected[offset + 8:offset + 16] != original[offset]:
            changes.append({
                'name': 'range 0x{:06X}-0x{:06X}'.format(descriptor['start'], descriptor['end']),
                'offset': offset + 8,
                'old': int.from_bytes(original[offset][:4], 'little'),
                'new': stored,
            })
    return changes


def m797_is_calibration_image(image: bytes) -> bool:
    """Identify padded calibration reads; reject partially missing boot/program data."""
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError('M7.9.7 checksum correction requires a 512 KiB BIN.')
    calibration = KEFICO_LAYOUT['regions']['calibration']['read']
    start = calibration['address'] - M797_FLASH_START
    stop = start + calibration['size']
    boot_missing = all(value == 0xFF for value in image[:start])
    program_missing = all(value == 0xFF for value in image[stop:])
    if boot_missing != program_missing:
        raise ValueError('M7.9.7 BIN has missing boot/program data. Use a full image or a calibration read.')
    return boot_missing and program_missing


def m797_correct_image_checksums(image: bytes, verbose: bool = True, log_callback=None) -> bytes:
    """Return a copy with both boot-integrity fields and all 32 descriptor pairs verified."""
    if m797_is_calibration_image(image):
        raise ValueError('A calibration read cannot be used for full flashing; use calibration-only flashing.')
    descriptors = m797_checksum_descriptors(image)
    corrected, changes = bytearray(image), []
    boot_fields = (
        ('boot header', M797_BOOT_HEADER_CHECKSUM_OFFSET, _m797_boot_header_checksum),
        ('boot boundary', M797_BOOT_BOUNDARY_CHECKSUM_OFFSET, m797_boot_boundary_checksum),
    )
    # Boot fields precede the descriptor pass because protected ranges may include them.
    for name, offset, calculate in boot_fields:
        old = struct.unpack_from('<I', corrected, offset)[0]
        new = calculate(corrected)
        if old != new:
            struct.pack_into('<I', corrected, offset, new)
            changes.append({'name': name, 'offset': offset, 'old': old, 'new': new})
    changes.extend(_correct_m797_descriptors(corrected, descriptors))
    for name, offset, calculate in boot_fields:
        stored, expected = struct.unpack_from('<I', corrected, offset)[0], calculate(corrected)
        if stored != expected:
            raise RuntimeError('M7.9.7 {} checksum self-test failed: stored 0x{:08X}, calculated 0x{:08X}'.format(
                name, stored, expected))
    if verbose:
        log('[*] Checking M7.9.7 image checksums', log_callback)
        if not changes:
            log('[+] Image checksums already correct.', log_callback)
        else:
            for change in changes:
                log('[+] Corrected {name} @ BIN 0x{offset:05X}: 0x{old:08X} -> 0x{new:08X}'.format(**change), log_callback)
            log('[+] Corrected {} checksum/integrity field(s)'.format(len(changes)), log_callback)
        log('[+] M7.9.7 checksum self-test passed', log_callback)
    return bytes(corrected)


def m797_correct_calibration_checksums(
        image: bytes, address: int, size: int, current_table: bytes | None = None
    ) -> bytes:
    """Correct calibration, optionally preserving live checksums for untouched firmware."""
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError('M7.9.7 checksum correction requires a 512 KiB BIN.')
    if size <= 0 or not M797_FLASH_START <= address < address + size <= M797_FLASH_END + 1:
        raise ValueError('Calibration checksum range is outside M7.9.7 external flash')
    corrected = bytearray(image)
    descriptors = m797_checksum_descriptors(image)
    if current_table is not None and len(current_table) != M797_CHECKSUM_TABLE_ENTRIES * M797_CHECKSUM_ENTRY_SIZE:
        raise ValueError('Incomplete ECU checksum table; calibration flash aborted')
    selected = []
    for descriptor in descriptors:
        offset = descriptor['offset']
        if current_table is not None:
            table_offset = offset - M797_CHECKSUM_TABLE_OFFSET
            live_entry = current_table[table_offset:table_offset + M797_CHECKSUM_ENTRY_SIZE]
            if live_entry[:8] != image[offset:offset + 8]:
                raise ValueError('BIN checksum layout differs from the ECU; use a matching BIN or a full flash')
        start, end = descriptor['start'], descriptor['end'] + 1
        if start >= address + size or end <= address:
            if current_table is not None:
                stored = int.from_bytes(live_entry[8:12], 'little')
                inverse = int.from_bytes(live_entry[12:16], 'little')
                if inverse != (stored ^ 0xFFFFFFFF):
                    raise ValueError('ECU has an invalid checksum complement; use a full flash')
                corrected[offset + 8:offset + 16] = live_entry[8:16]
            continue
        if start < address or end > address + size:
            raise ValueError('Checksum range crosses calibration boundary; use a full flash')
        selected.append(descriptor)
    if not selected:
        raise ValueError('No calibration checksum ranges found in the supplied BIN')
    try:
        _correct_m797_descriptors(corrected, selected)
    except RuntimeError as exc:
        raise ValueError(str(exc)) from exc
    return bytes(corrected)


def _m797_checksum_regions(descriptors):
    """Group independent zones under Boot, Calibration and Program."""
    layout = KEFICO_LAYOUT['regions']
    regions = {name.capitalize(): [] for name in layout}
    for descriptor in descriptors:
        label = next((
            name.capitalize() for name, region in layout.items()
            if region['read']['address'] <= descriptor['start'] <= descriptor['end']
            < region['read']['address'] + region['read']['size']
        ), 'External Flash')
        regions.setdefault(label, []).append(descriptor)
    return regions


def prepare_m797_checksum_correction(payload, log_callback=print):
    """Return a verified image and changes, logging the checked regions."""
    calibration_only = m797_is_calibration_image(payload)
    descriptors = m797_checksum_descriptors(payload)
    calibration = KEFICO_LAYOUT['regions']['calibration']['write']
    selected = [descriptor for descriptor in descriptors if not calibration_only or (
        calibration['address'] <= descriptor['start'] <= descriptor['end']
        < calibration['address'] + calibration['size']
    )]

    if calibration_only:
        corrected = m797_correct_calibration_checksums(
            payload, calibration['address'], calibration['size']
        )
    else:
        corrected = m797_correct_image_checksums(payload, verbose=False)

    fields = []
    if not calibration_only:
        fields.extend((
            ('Boot Header', M797_BOOT_HEADER_CHECKSUM_OFFSET),
            ('Boot Boundary', M797_BOOT_BOUNDARY_CHECKSUM_OFFSET),
        ))
    regions = _m797_checksum_regions(descriptors)
    region_names = {
        descriptor['index']: ('{} {}'.format(name, zone) if len(entries) > 1 else name)
        for name, entries in regions.items()
        for zone, descriptor in enumerate(entries, start=1)
    }
    for descriptor in selected:
        name = region_names[descriptor['index']]
        fields.extend(((name, descriptor['offset'] + 8),
                       (name + ' complement', descriptor['offset'] + 12)))
    changes = []
    results = {}
    for name, offset in fields:
        old = int.from_bytes(payload[offset:offset + 4], 'little')
        new = int.from_bytes(corrected[offset:offset + 4], 'little')
        field = {'name': name, 'offset': offset, 'old': old, 'new': new}
        results[offset] = field
        if old != new:
            changes.append(field)

    def report_result(field):
        log_callback('[*] OK! Current {} checksum: {}, new checksum: {}'.format(
            field['name'], hex(field['old']), hex(field['new'])
        ))

    for name, entries in regions.items():
        available = [entry for entry in entries if entry['offset'] + 8 in results]
        log_callback('[*] Calculating checksum for region {}'.format(name))
        log_callback('[*] Amount of zones: {}'.format(len(available)))
        if not available:
            log_callback('[*] Skipping region {}'.format(name))
            continue
        for zone, descriptor in enumerate(available, start=1):
            field = results[descriptor['offset'] + 8]
            log_callback('[*] Trying to find addresses of zone #{}.. {} - {}'.format(
                zone, hex(descriptor['start'] - M797_FLASH_START),
                hex(descriptor['end'] - M797_FLASH_START + 1)
            ))
            # M797 zones have independent additive checksums, each starting
            # at zero; SIMK instead chains its CRC between zones.
            log_callback('[*] Trying to find initial value.. 0x0')
            log_callback('[*] checksum of zone #{}: {}'.format(zone, hex(field['new'])))
            report_result(field)
        if name == 'Boot' and not calibration_only:
            for offset in (M797_BOOT_HEADER_CHECKSUM_OFFSET,
                           M797_BOOT_BOUNDARY_CHECKSUM_OFFSET):
                report_result(results[offset])
    if not changes:
        log_callback('[+] Image checksums already correct.')
    return corrected, changes


