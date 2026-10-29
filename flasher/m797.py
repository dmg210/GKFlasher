import time
import zlib
from contextlib import contextmanager
from pathlib import Path

from alive_progress import alive_bar
from gkbus.protocol import kwp2000



# ============================================================================
# CONSTANTS
# ============================================================================

M797_IMAGE_SIZE = 0x80000
M797_FLASH_START = 0x800000
M797_FLASH_END = 0x87FFFF

M797_FLASH_BLOCK_SIZE = 128
M797_TRANSFER_SIZE = 240
M797_MIN_SKIP_SIZE = 0x1000

M797_CHECKSUM_TABLE_OFFSET = 0x1FC20
M797_CHECKSUM_TABLE_ENTRIES = 32
M797_CHECKSUM_ENTRY_SIZE = 0x10

# Internal-ROM boot-integrity fields in the 0x808000 descriptor area.
M797_BOOT_HEADER_CHECKSUM_OFFSET = 0x8038
M797_BOOT_BOUNDARY_CHECKSUM_OFFSET = 0x803C

M797_DYNAMIC_LID = 0xF0
M797_DYNAMIC_READ_CHUNK = 0xF0
M797_XC167_PAGE_SIZE = 0x4000

M797_PROGRAMMING_PROFILES = {
    'standard': {
        'name': 'STANDARD',
        'selector': 0x64,
        'baudrate': 57600,
        'write_delay': 0.020,
    },
    'fast': {
        'name': 'FAST',
        'selector': 0x82,
        'baudrate': 108800,
        'write_delay': 0.002,
    },
}

M797_FLASH_REGIONS = (
    {
        'bin_offset': 0x00000,
        'address': 0x800000,
        'size': 0x10000,
        'verify_ranges': ((0x0000, 0x10000),),
    },
    {
        'bin_offset': 0x20000,
        'address': 0x820000,
        'size': 0x60000,
        'verify_ranges': ((0x0000, 0x60000),),
    },
    {
        'bin_offset': 0x10000,
        'address': 0x810000,
        'size': 0x10000,
        # KIA Flasher skips 0x818000-0x81818F during routine verification.
        'verify_ranges': ((0x0000, 0x8000), (0x8190, 0x7E70)),
    },
)

_M797_SECURITY_TABLE = (
    0x24DE49D0, 0x00000000, 0x00000000, 0x516A6710,
    0x00000000, 0x3231B5D0, 0x00000000, 0x00000000,
    0xE6158710, 0xBBB327B0, 0x00FE66F0, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x00000000,
    0x00000000, 0x00000000, 0x00000000, 0x8B55C990,
    0x6133BAB0, 0x00000000, 0xF356C350, 0x9135AF30,
    0x55F377F0, 0x00000000, 0x2055F650, 0x00000000,
    0x00000000, 0x75379B10, 0x00000000, 0xA34645D0,
)


# ============================================================================
# SMALL HELPERS
# ============================================================================

def _int24(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFF:
        raise ValueError('24-bit value out of range: {}'.format(hex(value)))
    return value.to_bytes(3, 'big')


def _hex(data: bytes) -> str:
    return ' '.join('{:02X}'.format(value) for value in data)


def _set_short_header(bus, enabled: bool) -> None:
    if hasattr(bus.transport, 'set_short_header'):
        bus.transport.set_short_header(enabled)
    else:
        bus.transport.short_header = enabled


def _page_remaining(address: int) -> int:
    return M797_XC167_PAGE_SIZE - (address & (M797_XC167_PAGE_SIZE - 1))


@contextmanager
def _m797_progress(total: int, title: str, progress_callback=None):
    """Use alive_progress for the CLI, or a caller-supplied incremental callback."""
    if progress_callback is None:
        with alive_bar(
            total,
            unit='B',
            title=title,
            enrich_print=False
        ) as bar:
            yield bar
    else:
        yield progress_callback



# ============================================================================
# IMAGE CHECKSUM CORRECTION
# ============================================================================

def _m797_sum16_le(data: bytes) -> int:
    """
    Return the Bosch/Kefico M7.9.7 32-bit additive checksum for a byte range.

    The protected data is interpreted as consecutive little-endian uint16
    words.  Every word is accumulated into an unsigned 32-bit sum.
    """
    if len(data) & 1:
        raise ValueError(
            'M7.9.7 checksum range length must be even, got 0x{:X}'
            .format(len(data))
        )

    total = 0

    for offset in range(0, len(data), 2):
        total += int.from_bytes(
            data[offset:offset + 2],
            'little'
        )

    return total & 0xFFFFFFFF


def _m797_boot_boundary_checksum(image: bytes) -> int:
    """
    Calculate the internal-ROM boot-boundary integrity value stored at BIN
    offset 0x803C.

    The ROM sums the first and last little-endian 16-bit word of every
    0x2000-byte block in:
        BIN 0x00000-0x0FFFF
        BIN 0x20000-0x7FFFF

    BIN 0x10000-0x1FFFF is excluded.
    """
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError(
            'M7.9.7 boot checksum requires exactly 0x{:X} bytes'
            .format(M797_IMAGE_SIZE)
        )

    total = 0

    for region_start, region_end in (
        (0x00000, 0x10000),
        (0x20000, M797_IMAGE_SIZE),
    ):
        for block_start in range(region_start, region_end, 0x2000):
            total += int.from_bytes(
                image[block_start:block_start + 2],
                'little'
            )
            total += int.from_bytes(
                image[
                    block_start + 0x1FFE:
                    block_start + 0x2000
                ],
                'little'
            )

    return total & 0xFFFFFFFF


def _m797_checksum_descriptors(image: bytes):
    """
    Parse and validate the 32-entry Bosch/Kefico checksum descriptor table.

    Table:
        BIN 0x1FC20
        32 entries
        16 bytes per entry

    Entry layout:
        +0x00  uint32 LE  ECU start address
        +0x04  uint32 LE  ECU end address, inclusive
        +0x08  uint32 LE  checksum
        +0x0C  uint32 LE  one's-complement checksum
    """
    descriptors = []

    for index in range(M797_CHECKSUM_TABLE_ENTRIES):
        offset = (
            M797_CHECKSUM_TABLE_OFFSET
            + index * M797_CHECKSUM_ENTRY_SIZE
        )

        start = int.from_bytes(
            image[offset:offset + 4],
            'little'
        )
        end = int.from_bytes(
            image[offset + 4:offset + 8],
            'little'
        )

        if not (
            M797_FLASH_START <= start <= M797_FLASH_END
            and M797_FLASH_START <= end <= M797_FLASH_END
            and start <= end
        ):
            raise RuntimeError(
                'Invalid M7.9.7 checksum descriptor {} at BIN 0x{:05X}: '
                'start=0x{:08X}, end=0x{:08X}'
                .format(index, offset, start, end)
            )

        size = end - start + 1

        if size & 1:
            raise RuntimeError(
                'Odd-length M7.9.7 checksum descriptor {}: '
                '0x{:06X}-0x{:06X}'
                .format(index, start, end)
            )

        descriptors.append({
            'index': index,
            'offset': offset,
            'start': start,
            'end': end,
            'size': size,
        })

    return descriptors


def m797_correct_image_checksums(
        image: bytes,
        verbose: bool = True
    ) -> bytes:
    """
    Recalculate every known M7.9.7 external-flash checksum/integrity field.

    This corrects:
      1. BIN 0x8038 internal-ROM boot header checksum:
             low16(entry pointer @ BIN 0x8000)
             + uint16 LE @ BIN 0xFFFE

      2. BIN 0x803C internal-ROM boot boundary checksum.

      3. The 32 Bosch/Kefico checksum descriptors beginning at BIN 0x1FC20.
         Each descriptor stores:
             checksum = sum of all LE uint16 words in [start..end]
             inverse  = ~checksum

    The supplied object is not modified.  A corrected bytes object is returned.
    """
    if len(image) != M797_IMAGE_SIZE:
        raise ValueError(
            'M7.9.7 checksum correction requires exactly {} bytes (0x{:X})'
            .format(M797_IMAGE_SIZE, M797_IMAGE_SIZE)
        )

    corrected = bytearray(image)
    changes = []

    # Parse the table before changing anything so a malformed/non-M7.9.7 image
    # is rejected before we begin silently modifying data.
    descriptors = _m797_checksum_descriptors(corrected)

    # ------------------------------------------------------------------
    # Boot integrity @ BIN 0x8038.
    # Do this before descriptor checksums because descriptor ranges may cover
    # these bytes.
    # ------------------------------------------------------------------
    entry_low = int.from_bytes(
        corrected[0x8000:0x8002],
        'little'
    )
    final_word = int.from_bytes(
        corrected[0xFFFE:0x10000],
        'little'
    )

    boot_header = (entry_low + final_word) & 0xFFFFFFFF

    old_boot_header = int.from_bytes(
        corrected[
            M797_BOOT_HEADER_CHECKSUM_OFFSET:
            M797_BOOT_HEADER_CHECKSUM_OFFSET + 4
        ],
        'little'
    )

    if old_boot_header != boot_header:
        corrected[
            M797_BOOT_HEADER_CHECKSUM_OFFSET:
            M797_BOOT_HEADER_CHECKSUM_OFFSET + 4
        ] = boot_header.to_bytes(4, 'little')

        changes.append({
            'name': 'boot header',
            'offset': M797_BOOT_HEADER_CHECKSUM_OFFSET,
            'old': old_boot_header,
            'new': boot_header,
        })

    # ------------------------------------------------------------------
    # Boot integrity @ BIN 0x803C.
    # ------------------------------------------------------------------
    boot_boundary = _m797_boot_boundary_checksum(corrected)

    old_boot_boundary = int.from_bytes(
        corrected[
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET:
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET + 4
        ],
        'little'
    )

    if old_boot_boundary != boot_boundary:
        corrected[
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET:
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET + 4
        ] = boot_boundary.to_bytes(4, 'little')

        changes.append({
            'name': 'boot boundary',
            'offset': M797_BOOT_BOUNDARY_CHECKSUM_OFFSET,
            'old': old_boot_boundary,
            'new': boot_boundary,
        })

    # ------------------------------------------------------------------
    # Main checksum table.
    # ------------------------------------------------------------------
    for descriptor in descriptors:
        offset = descriptor['offset']
        start = descriptor['start']
        end = descriptor['end']

        bin_start = start - M797_FLASH_START
        bin_end = end - M797_FLASH_START + 1

        checksum = _m797_sum16_le(
            corrected[bin_start:bin_end]
        )
        inverse = (~checksum) & 0xFFFFFFFF

        old_checksum = int.from_bytes(
            corrected[offset + 8:offset + 12],
            'little'
        )
        old_inverse = int.from_bytes(
            corrected[offset + 12:offset + 16],
            'little'
        )

        if old_checksum != checksum or old_inverse != inverse:
            corrected[offset + 8:offset + 12] = checksum.to_bytes(
                4,
                'little'
            )
            corrected[offset + 12:offset + 16] = inverse.to_bytes(
                4,
                'little'
            )

            changes.append({
                'name': 'range 0x{:06X}-0x{:06X}'.format(start, end),
                'offset': offset + 8,
                'old': old_checksum,
                'new': checksum,
            })

    # ------------------------------------------------------------------
    # Final self-verification.
    #
    # The checksum table itself can be inside a protected region because each
    # checksum is stored beside its one's complement; replacing both leaves
    # their combined 16-bit additive contribution invariant.
    # ------------------------------------------------------------------
    for descriptor in descriptors:
        index = descriptor['index']
        offset = descriptor['offset']
        start = descriptor['start']
        end = descriptor['end']

        bin_start = start - M797_FLASH_START
        bin_end = end - M797_FLASH_START + 1

        calculated = _m797_sum16_le(
            corrected[bin_start:bin_end]
        )

        stored = int.from_bytes(
            corrected[offset + 8:offset + 12],
            'little'
        )
        stored_inverse = int.from_bytes(
            corrected[offset + 12:offset + 16],
            'little'
        )

        if stored != calculated:
            raise RuntimeError(
                'M7.9.7 checksum self-test failed for descriptor {} '
                '(0x{:06X}-0x{:06X}): stored 0x{:08X}, '
                'calculated 0x{:08X}'
                .format(
                    index,
                    start,
                    end,
                    stored,
                    calculated
                )
            )

        expected_inverse = (~stored) & 0xFFFFFFFF

        if stored_inverse != expected_inverse:
            raise RuntimeError(
                'M7.9.7 checksum complement self-test failed for '
                'descriptor {}: stored 0x{:08X}, expected 0x{:08X}'
                .format(
                    index,
                    stored_inverse,
                    expected_inverse
                )
            )

    # Verify the two boot-integrity values again after every table update.
    final_boot_header = (
        int.from_bytes(corrected[0x8000:0x8002], 'little')
        + int.from_bytes(corrected[0xFFFE:0x10000], 'little')
    ) & 0xFFFFFFFF

    stored_boot_header = int.from_bytes(
        corrected[
            M797_BOOT_HEADER_CHECKSUM_OFFSET:
            M797_BOOT_HEADER_CHECKSUM_OFFSET + 4
        ],
        'little'
    )

    if stored_boot_header != final_boot_header:
        raise RuntimeError(
            'M7.9.7 boot-header checksum self-test failed: '
            'stored 0x{:08X}, calculated 0x{:08X}'
            .format(stored_boot_header, final_boot_header)
        )

    final_boot_boundary = _m797_boot_boundary_checksum(corrected)
    stored_boot_boundary = int.from_bytes(
        corrected[
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET:
            M797_BOOT_BOUNDARY_CHECKSUM_OFFSET + 4
        ],
        'little'
    )

    if stored_boot_boundary != final_boot_boundary:
        raise RuntimeError(
            'M7.9.7 boot-boundary checksum self-test failed: '
            'stored 0x{:08X}, calculated 0x{:08X}'
            .format(stored_boot_boundary, final_boot_boundary)
        )

    if verbose:
        print('')
        print('[*] Checking M7.9.7 image checksums')

        if not changes:
            print('[+] Image checksums already correct')
        else:
            for change in changes:
                print(
                    '[+] Corrected {} @ BIN 0x{:05X}: '
                    '0x{:08X} -> 0x{:08X}'
                    .format(
                        change['name'],
                        change['offset'],
                        change['old'],
                        change['new']
                    )
                )

            print(
                '[+] Corrected {} checksum/integrity field(s)'
                .format(len(changes))
            )

        print('[+] M7.9.7 checksum self-test passed')

    return bytes(corrected)


# ============================================================================
# SECURITY / PROGRAMMING SESSION
# ============================================================================

def m797_calculate_key(seed: bytes) -> bytes:
    if len(seed) != 4:
        raise ValueError('M7.9.7 security seed must be exactly 4 bytes')

    seed_value = int.from_bytes(seed, 'big')
    key = 0
    working = _M797_SECURITY_TABLE[0]

    for bit_index in range(32):
        if seed_value & (1 << bit_index):
            key ^= working

        if bit_index == 31:
            break

        if working & 0x80000000:
            working = _M797_SECURITY_TABLE[bit_index + 1]
        else:
            working = (working << 1) & 0xFFFFFFFF

    return (key & 0xFFFFFFFF).to_bytes(4, 'big')


def m797_calculate_recovery_key(seed: bytes) -> bytes:
    if len(seed) != 4:
        raise ValueError('M7.9.7 security seed must be exactly 4 bytes')

    value = int.from_bytes(seed, 'big')
    polynomial = 0xFABC568E

    for _ in range(40):
        if value & 0x80000000:
            value = ((value << 1) & 0xFFFFFFFF) ^ polynomial
        else:
            value = (value << 1) & 0xFFFFFFFF

    return value.to_bytes(4, 'big')


def m797_choose_programming_profile() -> str:
    """Ask whether to use standard or fast M7.9.7 programming speed.

    Standard programming (selector 0x64 / 57600 baud) is the safe default.
    Fast programming (selector 0x82 / 108800 baud) is optional because not
    every M7.9.7 firmware is known to support the faster session.
    """
    while True:
        choice = input(
            '[?] Use fast programming (108800 baud)? [y/N]: '
        ).strip().lower()

        if choice in ('', 'n', 'no'):
            profile = 'standard'
            break

        if choice in ('y', 'yes'):
            profile = 'fast'
            break

        print('[!] Please answer y or n.')

    selected = M797_PROGRAMMING_PROFILES[profile]
    print(
        '[*] Programming speed: {} ({} baud)'
        .format(
            selected['name'],
            selected['baudrate'],
            selected['selector']
        )
    )
    return profile


def m797_prepare_flash_session(
        bus,
        programming_profile: str = 'standard'
    ) -> None:
    """Enter an M7.9.7 programming session at the selected baud rate."""
    try:
        profile = M797_PROGRAMMING_PROFILES[programming_profile]
    except KeyError as exc:
        raise ValueError(
            'Unknown M7.9.7 programming profile: {}'
            .format(programming_profile)
        ) from exc

    if hasattr(bus, '_stop_keepalive'):
        bus._stop_keepalive()

    _set_short_header(bus, True)

    bus.execute(
        kwp2000.commands.AccessTimingParameters()
        .set_timing_parameters_to_given_values(
            0x00, 0x28, 0x00, 0x14, 0x00
        )
    )

    bus.execute(
        kwp2000.commands.StartDiagnosticSession(
            kwp2000.enums.DiagnosticSession.FLASH_REPROGRAMMING,
            profile['selector']
        )
    )

    bus.transport.hardware.set_baudrate(profile['baudrate'])
    bus.transport.hardware.set_write_delay(profile['write_delay'])


def m797_security_access(
        bus,
        retry_delay: float = 0.5,
        timeout: float = 7.0
    ) -> None:
    request = kwp2000.commands.SecurityAccess().request_seed(
        0x81,
        bytes([0x05]) + b'SECURITY'
    )

    deadline = time.monotonic() + timeout
    waiting_message_printed = False

    while True:
        try:
            seed_response = bus.execute(request).get_data()
            break
        except kwp2000.Kwp2000NegativeResponseException as exc:
            if exc.status.identifier != 0x37:
                raise

            if time.monotonic() >= deadline:
                raise TimeoutError(
                    'M7.9.7 security delay did not expire within {:.1f}s'
                    .format(timeout)
                ) from exc

            if not waiting_message_printed:
                print('[*] ECU security delay active, waiting...')
                waiting_message_printed = True

            time.sleep(retry_delay)

    if len(seed_response) < 2 or seed_response[0] != 0x81:
        raise ValueError(
            'Unexpected M7.9.7 security seed response: {!r}'
            .format(seed_response)
        )

    seed = seed_response[1:]
    print('[*] M7.9.7 security seed: {}'.format(_hex(seed)))

    if seed and not any(seed):
        print('[*] ECU reports zero seed; programming security is already unlocked')
        return

    try:
        bus.execute(
            kwp2000.commands.SecurityAccess().send_key(
                m797_calculate_key(seed),
                0x82
            )
        )
        return
    except kwp2000.Kwp2000NegativeResponseException as exc:
        if exc.status.identifier != 0x35:
            raise

    # Blank external flash uses the internal-ROM fallback polynomial.
    print('[*] Normal security key rejected; trying blank-flash recovery key')
    bus.execute(
        kwp2000.commands.SecurityAccess().send_key(
            m797_calculate_recovery_key(seed),
            0x82
        )
    )


@contextmanager
def _m797_programming_session(
        bus,
        programming_profile: str = 'standard'
    ):
    """
    Enter programming mode at the selected speed, unlock security, and always
    restore normal KWP framing when the operation finishes or raises.
    """
    m797_prepare_flash_session(
        bus,
        programming_profile=programming_profile
    )

    try:
        print('[*] Security Access')
        m797_security_access(bus)
        yield
    finally:
        try:
            _set_short_header(bus, False)
        except Exception:
            pass


# ============================================================================
# GENERIC FLASH PROGRAMMING
# ============================================================================

def m797_wait_for_routine(
        bus,
        routine_identifier: int,
        poll_delay: float = 0.2
    ):
    while True:
        try:
            return bus.execute(
                kwp2000.commands.RequestRoutineResultsByLocalIdentifier(
                    routine_identifier
                )
            )
        except kwp2000.Kwp2000NegativeResponseException as exc:
            if exc.status.identifier != 0x23:
                raise
            time.sleep(poll_delay)


def m797_erase_region(bus, address: int, size: int) -> None:
    end_address = address + size - 1
    print('[*] Erasing 0x{:06X}-0x{:06X}'.format(address, end_address))

    bus.execute(
        kwp2000.commands.StartRoutineByLocalIdentifier(
            0x02,
            *_int24(address),
            *_int24(end_address)
        )
    )
    m797_wait_for_routine(bus, 0x02)


def m797_request_download(bus, address: int, size: int) -> None:
    bus.execute(
        kwp2000.commands.RequestDownload(
            address,
            kwp2000.enums.CompressionType.UNCOMPRESSED,
            kwp2000.enums.EncryptionType.UNENCRYPTED,
            size
        )
    )


def m797_find_nonblank_ranges(data: bytes) -> list[tuple[int, int]]:
    """
    Return aligned write ranges while skipping erased runs >= 0x1000 bytes.
    Small FF gaps remain inside surrounding transfers to avoid excessive
    RequestDownload fragmentation.
    """
    block_size = M797_FLASH_BLOCK_SIZE
    blank_block = bytes([0xFF]) * block_size
    block_count = (len(data) + block_size - 1) // block_size

    first_used = None
    last_used = None

    for block_index in range(block_count):
        start = block_index * block_size
        chunk = data[start:start + block_size]

        if chunk != blank_block[:len(chunk)]:
            if first_used is None:
                first_used = block_index
            last_used = block_index

    if first_used is None:
        return []

    ranges = []
    range_start_block = first_used
    block_index = first_used

    while block_index <= last_used:
        start = block_index * block_size
        chunk = data[start:start + block_size]

        if chunk != blank_block[:len(chunk)]:
            block_index += 1
            continue

        blank_start = block_index
        while block_index <= last_used:
            offset = block_index * block_size
            chunk = data[offset:offset + block_size]
            if chunk != blank_block[:len(chunk)]:
                break
            block_index += 1

        blank_size = (block_index - blank_start) * block_size
        if blank_size >= M797_MIN_SKIP_SIZE:
            ranges.append((
                range_start_block * block_size,
                blank_start * block_size
            ))
            range_start_block = block_index

    if range_start_block <= last_used:
        ranges.append((
            range_start_block * block_size,
            min((last_used + 1) * block_size, len(data))
        ))

    return [(start, end) for start, end in ranges if end > start]


def _m797_transfer_chunk_sizes(total_size: int) -> list[int]:
    """
    Preserve the current proven packetization behavior: use 240-byte SID 0x36
    payloads, but reshape a final sub-128-byte tail into two larger packets.
    """
    if total_size < 0:
        raise ValueError('Transfer size cannot be negative')

    if total_size == 0:
        return []

    maximum = M797_TRANSFER_SIZE
    minimum_tail = M797_FLASH_BLOCK_SIZE
    full, remainder = divmod(total_size, maximum)

    if remainder == 0:
        return [maximum] * full

    if remainder >= minimum_tail:
        return [maximum] * full + [remainder]

    if full >= 1:
        penultimate = (maximum - minimum_tail) + remainder
        final = minimum_tail

        if not minimum_tail <= penultimate <= maximum:
            raise RuntimeError(
                'Cannot safely split {} bytes into <= {} byte TransferData '
                'packets with a >= {} byte final block'
                .format(total_size, maximum, minimum_tail)
            )

        return [maximum] * (full - 1) + [penultimate, final]

    return [remainder]


def m797_transfer_region(bus, data: bytes, progress_callback=None) -> None:
    offset = 0

    for chunk_size in _m797_transfer_chunk_sizes(len(data)):
        chunk = data[offset:offset + chunk_size]

        if len(chunk) != chunk_size:
            raise RuntimeError(
                'Internal transfer packetizer error at offset 0x{:X}: '
                'wanted {}, got {}'
                .format(offset, chunk_size, len(chunk))
            )

        command = kwp2000.commands.TransferData()
        command.set_data(chunk)
        bus.execute(command)

        offset += chunk_size

        if progress_callback:
            progress_callback(chunk_size)

    if offset != len(data):
        raise RuntimeError(
            'Transfer packetizer sent {} bytes, expected {}'
            .format(offset, len(data))
        )


def m797_verify_region(bus, address: int, data: bytes) -> int:
    end_address = address + len(data) - 1
    crc = zlib.crc32(data) & 0xFFFFFFFF

    print('[*] Verifying 0x{:06X}-0x{:06X}, CRC32 {:08X}'.format(
        address,
        end_address,
        crc
    ))

    bus.execute(
        kwp2000.commands.StartRoutineByLocalIdentifier(
            0x01,
            *_int24(address),
            *_int24(end_address),
            *crc.to_bytes(4, 'big')
        )
    )
    m797_wait_for_routine(bus, 0x01)
    return crc


def m797_flash_region(
        bus,
        address: int,
        data: bytes,
        verify_ranges,
        progress_callback=None
    ) -> None:
    m797_erase_region(bus, address, len(data))

    print('[*] Flashing 0x{:06X}-0x{:06X}'.format(
        address,
        address + len(data) - 1
    ))

    write_ranges = m797_find_nonblank_ranges(data)
    progressed = 0

    for range_start, range_end in write_ranges:
        payload = data[range_start:range_end]

        if progress_callback and range_start > progressed:
            progress_callback(range_start - progressed)

        m797_request_download(bus, address + range_start, len(payload))
        m797_transfer_region(
            bus,
            payload,
            progress_callback=progress_callback
        )
        bus.execute(kwp2000.commands.RequestTransferExit())
        progressed = range_end

    if progress_callback and progressed < len(data):
        progress_callback(len(data) - progressed)

    for verify_offset, verify_size in verify_ranges:
        m797_verify_region(
            bus,
            address + verify_offset,
            data[verify_offset:verify_offset + verify_size]
        )


def m797_flash(
        bus,
        filename: str,
        programming_profile: str | None = None,
        confirm: bool = True,
        progress_callback=None
    ) -> None:
    """Program a complete 0x80000-byte M7.9.7 external-flash image."""
    print('\n[*] Loading up {}'.format(filename))

    image = Path(filename).read_bytes()
    print('[*] Loaded {} bytes'.format(len(image)))

    if len(image) != M797_IMAGE_SIZE:
        raise ValueError(
            'M7.9.7 full flash must be exactly {} bytes (0x{:X})'
            .format(M797_IMAGE_SIZE, M797_IMAGE_SIZE)
        )

    # Always calculate the final flash image ourselves. Tuned files are not
    # trusted to contain valid Bosch/Kefico checksum-table or boot-integrity
    # values. The source BIN on disk remains untouched.
    image = m797_correct_image_checksums(image)

    if confirm:
        if input('[?] Ready to flash! Do you wish to continue? [y/n]: ') != 'y':
            print('[!] Aborting!')
            return

    if programming_profile is None:
        programming_profile = m797_choose_programming_profile()
    else:
        # Validate the caller-selected profile without prompting.
        _m797_read_profile(programming_profile)

    with _m797_programming_session(
        bus,
        programming_profile=programming_profile
    ):
        for region in M797_FLASH_REGIONS:
            start = region['bin_offset']
            stop = start + region['size']
            data = image[start:stop]

            print('[*] Flashing BIN 0x{:05X}-0x{:05X} -> ECU 0x{:06X}'.format(
                start,
                stop - 1,
                region['address']
            ))

            if progress_callback is None:
                with alive_bar(region['size'], unit='B', enrich_print=False) as bar:
                    m797_flash_region(
                        bus,
                        region['address'],
                        data,
                        region['verify_ranges'],
                        progress_callback=bar
                    )
            else:
                m797_flash_region(
                    bus,
                    region['address'],
                    data,
                    region['verify_ranges'],
                    progress_callback=progress_callback
                )

        print('[*] Done!')

# ============================================================================
# PATCHLESS FULL-FLASH READ
# ============================================================================

# The stock application-side diagnostic implementation can temporarily open
# the external-flash class-4 SID 0x2C path by changing BOTH live runtime
# descriptor copies in RAM from the live calibration-specific CLOSED value
# to that calibration's class-4 descriptor value.  The descriptors are created
# while the spoof is active, then the original eight RAM bytes are restored
# before SID 0x21 retrieves any flash data.
#
# This read path performs no external-flash erase/program operation.

M797_READ_STARTUP_BAUD = 10400
M797_READ_STARTUP_SELECTOR = 0x14
M797_READ_DESCRIPTOR_ADDRESS = 0x00E048
M797_READ_STATE_LID = 0xF0
M797_READ_DATA_LIDS = tuple(range(0xF1, 0xF5))  # F1..F4 proven batch
M797_READ_DESCRIPTOR_PAGE_WORD = 0x0206
M797_DESCRIPTOR_RELOCATION_DELTA = 0x00E6

# Exact classifier words established from disassembly. These are HINTS only;
# they are no longer a whitelist. Unknown calibrations are allowed to probe.
M797_PATCHLESS_LINEAR_PROFILES = {
    'LCE4I33': {
        'class4_descriptor_word': 0x1A8A,
    },
    'GKH2I60': {
        'class4_descriptor_word': 0x1C64,
    },
    'TBE3I35': {
        'class4_descriptor_word': 0x1A92,
    },
}

# Additional class-4 comparator words seen in other M7.9.7 disassemblies.
# They are only attempted when they are physically close to the live
# descriptor word, to avoid writing arbitrary runtime pointers.
M797_KNOWN_CLASS4_WORDS = frozenset((
    0x1A3A,
    *(profile['class4_descriptor_word']
      for profile in M797_PATCHLESS_LINEAR_PROFILES.values()),
))

# Dynamic-memory address encodings observed in M7.9.7 application code.
M797_DYNAMIC_ADDRESS_MODES = ('linear', 'c166')

# Direct c166_four RAM-descriptor layouts are calibration-specific.
#
# IMPORTANT:
# "c166_four" describes the firmware architecture; it does NOT imply a
# universal RAM table base.  Runtime testing proved:
#
#   ADE1I52  count base near 0x8036 -> physical 0x380036
#   FCE2N64  count base near 0x803A -> physical 0x38003A
#
# Only runtime-proven layouts are synthesized automatically. Unknown
# calibrations are never probed by writing candidate table addresses.
M797_C166_DIRECT_PROFILES = {
    'ADE1I52': {
        'raw_slot_base': 0x380036,
        'oracle_target': 0x811B12,
        'oracle_expected': bytes.fromhex(
            '43 4C 33 3D 41 43 46 4B '
            '51 54 42 4C 4C 4C 4E 56'
        ),
        'description': 'c166_four base 0x8036 / physical 0x380036',
    },
    'FCE2N64': {
        'raw_slot_base': 0x38003A,
        'oracle_target': 0x8318EE,
        'oracle_expected': bytes.fromhex(
            'C0 E4 F0 14 5C 21 20 14 '
            '5C 11 D4 81 3C 80 D4 91'
        ),
        'description': 'shifted c166_four base 0x803A / physical 0x38003A',
    },
}

# Unknown calibrations are allowed to try every runtime-known architecture.
#
# ORDER MATTERS for the two six-byte c166_four layouts:
#
#   base 0x380044 is tried first, then 0x38003A, then 0x380036.
#
# The descending-base order is deliberate. A higher-base candidate leaves
# the F0 descriptor-count word of the known lower-base layouts untouched,
# so a wrong-layout 21 F0 fails without dereferencing a bogus F0 pointer.
# The reverse direction is unsafe: the old ADE 0x380036 probe placed its
# descriptor-page bytes over FCE2N64's real F0 count field at 0x3805DA,
# which wedged application diagnostics.
M797_C166_GENERIC_CANDIDATES = (
    {
        'name': 'c166_four_8044',
        'raw_slot_base': 0x380044,
        'description': 'c166_four base 0x8044 / physical 0x380044',
    },
    {
        'name': 'c166_four_shifted_803A',
        'raw_slot_base': 0x38003A,
        'description': 'shifted c166_four base 0x803A / physical 0x38003A',
    },
    {
        'name': 'c166_four_8036',
        'raw_slot_base': 0x380036,
        'description': 'c166_four base 0x8036 / physical 0x380036',
    },
)

M797_C166_RAW_DATA_LIDS = tuple(range(0xF0, 0xF5))       # F0..F4
M797_C166_RAW_DESC_LIDS = tuple(range(0xF5, 0xFA))       # F5..F9 storage
M797_C166_RAW_WINDOW_SIZE = 10 * 6
M797_C166_TABLE_WINDOW_SIZE = 5 * 6
M797_C166_DESC_WINDOW_SIZE = 5 * 6
M797_C166_DESCRIPTOR_TYPE_MEMORY = 0x09

# LCR0N53 / c166_lcr uses a different dynamic-LID structure:
#
#   near table base = 0x8014
#   stride          = 8 bytes
#   physical RAM    = 0x380014 + (LID * 8)
#
# Raw F0..F9 therefore occupy:
#   0x380794 .. 0x3807E3
#
# F0..F4 are used as active table entries and F5..F9 as descriptor storage.
# Each 40-byte half fits comfortably inside the KWP short-frame payload limit.
M797_LCR_RAW_SLOT_BASE = 0x380014
M797_LCR_RAW_DATA_LIDS = tuple(range(0xF0, 0xF5))
M797_LCR_RAW_DESC_LIDS = tuple(range(0xF5, 0xFA))
M797_LCR_RAW_WINDOW_START = M797_LCR_RAW_SLOT_BASE + (0xF0 * 8)
M797_LCR_RAW_WINDOW_SIZE = 10 * 8

M797_LCR_TABLE_WINDOW_START = M797_LCR_RAW_WINDOW_START
M797_LCR_TABLE_WINDOW_SIZE = 5 * 8
M797_LCR_DESC_WINDOW_START = (
    M797_LCR_RAW_WINDOW_START + M797_LCR_TABLE_WINDOW_SIZE
)
M797_LCR_DESC_WINDOW_SIZE = 5 * 8


def m797_choose_read_profile() -> str:
    """Choose standard (57.6 kbaud) or fast (108.8 kbaud) patchless read."""
    while True:
        choice = input(
            '[?] Use fast read (108800 baud)? [y/N]: '
        ).strip().lower()

        if choice in ('', 'n', 'no'):
            profile = 'standard'
            break

        if choice in ('y', 'yes'):
            profile = 'fast'
            break

        print('[!] Please answer y or n.')

    selected = M797_PROGRAMMING_PROFILES[profile]
    print(
        '[*] Read speed: {} ({} baud)'
        .format(selected['name'], selected['baudrate'])
    )
    return profile


def _m797_read_profile(profile_name: str):
    try:
        return M797_PROGRAMMING_PROFILES[profile_name]
    except KeyError as exc:
        raise ValueError(
            'Unknown M7.9.7 read profile: {}'.format(profile_name)
        ) from exc


def _m797_start_session_86(bus, selector: int):
    command = kwp2000.commands.StartDiagnosticSession(
        kwp2000.enums.DiagnosticSession.DEFAULT
    )
    command.set_data(bytes([0x86, selector]))
    return bus.execute(command)


def _m797_tester_present(bus) -> bytes:
    return bytes(
        bus.execute(
            kwp2000.commands.TesterPresent(
                kwp2000.enums.ResponseType.REQUIRED
            )
        ).get_data()
    )


def _m797_reset_serial_buffers(bus) -> None:
    socket = getattr(bus.transport.hardware, 'socket', None)
    if socket is None:
        return

    try:
        socket.reset_input_buffer()
    except Exception:
        pass

    try:
        socket.reset_output_buffer()
    except Exception:
        pass


def _m797_switch_read_baud(bus, profile_name: str) -> None:
    """
    Enter application session 0x86 and switch from startup 10400 baud to the
    selected read speed.  Standard = 0x64 / 57600; fast = 0x82 / 108800.
    """
    profile = _m797_read_profile(profile_name)

    if hasattr(bus, '_stop_keepalive'):
        bus._stop_keepalive()

    # Keep a conservative host-side delay during the speed handoff.  Once the
    # new baud is proven alive, the bulk reader tries zero host delay.
    if hasattr(bus.transport.hardware, 'set_write_delay'):
        bus.transport.hardware.set_write_delay(profile['write_delay'])

    print(
        '[*] StartDiagnosticSession: 10 86 {:02X} ({} baud)'
        .format(profile['selector'], profile['baudrate'])
    )

    response = bytes(
        _m797_start_session_86(bus, profile['selector']).get_data()
    )
    print('[+] Session accepted at 10400 baud: {}'.format(_hex(response)))

    bus.transport.hardware.set_baudrate(profile['baudrate'])
    _m797_reset_serial_buffers(bus)
    time.sleep(0.03)

    try:
        response = _m797_tester_present(bus)
    except Exception as exc:
        # Check whether the ECU failed to change speed before giving up.  Do
        # not perform any RAM write unless communication at the selected baud
        # has first been proven.
        bus.transport.hardware.set_baudrate(M797_READ_STARTUP_BAUD)
        _m797_reset_serial_buffers(bus)
        time.sleep(0.03)

        try:
            startup_response = _m797_tester_present(bus)
        except Exception:
            raise RuntimeError(
                'M7.9.7 did not respond at requested {} baud or startup '
                '10400 baud after 10 86 {:02X}; power-cycle the ECU before '
                'retrying'
                .format(profile['baudrate'], profile['selector'])
            ) from exc

        raise RuntimeError(
            'M7.9.7 rejected/failed the {} baud read-speed transition; ECU '
            'still responds at 10400 baud ({})'
            .format(profile['baudrate'], _hex(startup_response))
        ) from exc

    print(
        '[+] TesterPresent works at {} baud: {}'
        .format(profile['baudrate'], _hex(response))
    )

    # Use the timing values already proven by the previous reader.  If a
    # firmware rejects them at the higher baud, the session defaults remain
    # usable; the read can still continue.
    try:
        bus.execute(
            kwp2000.commands.AccessTimingParameters()
            .set_timing_parameters_to_given_values(
                0x00, 0x28, 0x00, 0x14, 0x00
            )
        )
        print('[+] ECU read timing parameters accepted.')
    except kwp2000.Kwp2000NegativeResponseException as exc:
        print(
            '[!] ECU read timing optimization not supported (NRC 0x{:02X}); '
            'using session defaults.'
            .format(exc.status.identifier)
        )

    # The old stable 10400-baud reader proved that host-side write delay can
    # be zero during reads.  Test that at the selected baud; if it is not
    # stable, fall back to the already-proven programming-profile delay.
    if hasattr(bus.transport.hardware, 'set_write_delay'):
        bus.transport.hardware.set_write_delay(0.0)
        try:
            _m797_tester_present(bus)
            print('[+] Host write delay: 0 ms')
        except Exception:
            bus.transport.hardware.set_write_delay(profile['write_delay'])
            _m797_reset_serial_buffers(bus)
            time.sleep(0.02)
            _m797_tester_present(bus)
            print(
                '[*] Host write delay fallback: {:.0f} ms'
                .format(profile['write_delay'] * 1000.0)
            )


def _m797_restore_startup_baud(bus, active_profile_name: str) -> None:
    """Best-effort return from 57.6/108.8 kbaud to the normal 10400 baud."""
    profile = _m797_read_profile(active_profile_name)

    try:
        print('[*] Restoring diagnostic baud to 10400')
        response = bytes(
            _m797_start_session_86(
                bus,
                M797_READ_STARTUP_SELECTOR
            ).get_data()
        )
        print(
            '[+] 10 86 {:02X} accepted at {} baud: {}'
            .format(
                M797_READ_STARTUP_SELECTOR,
                profile['baudrate'],
                _hex(response)
            )
        )
    except Exception as exc:
        print(
            '[!] Could not negotiate the return to 10400 baud: {}'
            .format(exc)
        )
        print('[!] ECU flash was not modified; power-cycle the ECU if needed.')
        return

    bus.transport.hardware.set_baudrate(M797_READ_STARTUP_BAUD)
    _m797_reset_serial_buffers(bus)

    if hasattr(bus.transport.hardware, 'set_write_delay'):
        bus.transport.hardware.set_write_delay(0.0)

    time.sleep(0.03)

    try:
        response = _m797_tester_present(bus)
        print(
            '[+] TesterPresent works again at 10400 baud: {}'
            .format(_hex(response))
        )
    except Exception as exc:
        print(
            '[!] Baud-return request was accepted, but final 10400-baud '
            'TesterPresent failed: {}'
            .format(exc)
        )


def _m797_dynamic_address_bytes(
        address: int,
        address_mode: str
    ) -> bytes:
    if not 0 <= address <= 0xFFFFFF:
        raise ValueError('Dynamic-LID address must fit in 24 bits')

    if address_mode == 'linear':
        return address.to_bytes(3, 'big')

    if address_mode == 'c166':
        page = address >> 14
        offset = address & 0x3FFF
        return bytes([
            offset & 0xFF,
            (offset >> 8) & 0xFF,
            page & 0xFF,
        ])

    raise ValueError(
        'Unknown M7.9.7 dynamic address mode: {}'
        .format(address_mode)
    )


def _m797_define_dynamic_lid(
        bus,
        lid: int,
        address: int,
        size: int,
        address_mode: str = 'linear'
    ):
    if not 1 <= size <= M797_DYNAMIC_READ_CHUNK:
        raise ValueError(
            'Dynamic read size must be 1..0x{:02X}'
            .format(M797_DYNAMIC_READ_CHUNK)
        )

    address_bytes = _m797_dynamic_address_bytes(
        address,
        address_mode
    )

    payload = bytes([
        lid,
        0x04,       # clear existing definition
        0x03,       # define by memory address
        0x01,       # output position 1
        size,
        *address_bytes,
    ])

    command = kwp2000.commands.DynamicallyDefineLocalIdentifier()
    command.set_data(payload)
    return bus.execute(command)


def _m797_read_dynamic_lid(
        bus,
        lid: int,
        size: int,
        retries: int = 3
    ) -> bytes:
    last_error = None

    for attempt in range(1, retries + 1):
        try:
            response = bytes(
                bus.execute(
                    kwp2000.commands.ReadDataByLocalIdentifier(lid)
                ).get_data()
            )

            if len(response) == size + 1 and response[0] == lid:
                return response[1:]

            if len(response) == size:
                return response

            raise RuntimeError(
                'Unexpected dynamic LID 0x{:02X} response length {} '
                '(expected {} or {}, raw={})'
                .format(
                    lid,
                    len(response),
                    size,
                    size + 1,
                    _hex(response)
                )
            )

        except Exception as exc:
            last_error = exc
            if attempt >= retries:
                break

            print(
                '[!] LID 0x{:02X} read attempt {}/{} failed: {}; retrying.'
                .format(lid, attempt, retries, exc)
            )
            time.sleep(0.02)

    raise last_error


def _m797_clear_dynamic_lid(bus, lid: int) -> None:
    command = kwp2000.commands.DynamicallyDefineLocalIdentifier()
    command.set_data(bytes([lid, 0x04]))
    bus.execute(command)


def _m797_write_ram(bus, address: int, data: bytes) -> bytes:
    """Direct application-side SID 0x3D RAM write."""
    return bytes(
        bus.execute(
            kwp2000.commands.WriteMemoryByAddress(address, data)
        ).get_data()
    )


def _m797_read_descriptor_pair(
        bus,
        address_mode: str
    ) -> bytes:
    _m797_define_dynamic_lid(
        bus,
        M797_READ_STATE_LID,
        M797_READ_DESCRIPTOR_ADDRESS,
        8,
        address_mode=address_mode
    )
    return _m797_read_dynamic_lid(
        bus,
        M797_READ_STATE_LID,
        8
    )


def _m797_validate_descriptor_pair(baseline: bytes) -> None:
    if len(baseline) != 8:
        raise RuntimeError(
            'Expected 8 descriptor bytes at E048:E04F, got {}'
            .format(len(baseline))
        )

    if baseline[:4] != baseline[4:8]:
        raise RuntimeError(
            'Runtime descriptor copies are not identical: {}'
            .format(_hex(baseline))
        )

    descriptor_word = int.from_bytes(baseline[0:2], 'little')
    page_word = int.from_bytes(baseline[2:4], 'little')

    print(
        '[*] Live descriptor : 0x{:04X}:0x{:04X}'
        .format(descriptor_word, page_word)
    )


def _m797_detect_dynamic_address_mode(bus):
    """
    Detect the stock SID 0x2C address parser without using calibration ID.

    A candidate is accepted only if F0 can define/read E048:E04F and the
    returned eight bytes form two identical 4-byte runtime descriptor copies.
    """
    errors = []

    for address_mode in M797_DYNAMIC_ADDRESS_MODES:
        print(
            '[*] Probing SID 0x2C address mode: {}'
            .format(address_mode)
        )

        try:
            baseline = _m797_read_descriptor_pair(
                bus,
                address_mode
            )
            _m797_validate_descriptor_pair(baseline)
        except Exception as exc:
            errors.append((address_mode, exc))
            print(
                '[*] {} address mode rejected: {}'
                .format(address_mode, exc)
            )
            continue

        print(
            '[+] SID 0x2C address mode detected: {}'
            .format(address_mode)
        )
        return address_mode, baseline

    raise RuntimeError(
        'Could not establish a usable stock SID 0x2C dynamic-memory parser. '
        'Tried {}. This ECU may belong to an older parser family that still '
        'requires RAM-side replacements for the historical normalization/'
        'page-high/slot fixes. Details: {}'
        .format(
            ', '.join(M797_DYNAMIC_ADDRESS_MODES),
            '; '.join(
                '{}={}'.format(mode, exc)
                for mode, exc in errors
            )
        )
    )



def _m797_get_c166_direct_profile(calibration_id: str):
    calibration_id = (calibration_id or 'UNKNOWN').strip().upper()
    profile = M797_C166_DIRECT_PROFILES.get(calibration_id)

    if profile is None:
        raise RuntimeError(
            'No runtime-proven c166_four RAM layout for calibration {}. '
            'Refusing to write a guessed dynamic-table address.'
            .format(calibration_id)
        )

    return profile


def _m797_c166_raw_slot_address(lid: int, raw_slot_base: int) -> int:
    if not 0 <= lid <= 0xFF:
        raise ValueError('C166 raw LID must fit in one byte')
    return raw_slot_base + (lid * 6)


def _m797_c166_window_addresses(raw_slot_base: int):
    raw_window_start = (
        raw_slot_base + (M797_C166_RAW_DATA_LIDS[0] * 6)
    )
    table_start = raw_window_start
    descriptor_start = (
        raw_window_start + M797_C166_TABLE_WINDOW_SIZE
    )

    return {
        'raw_window_start': raw_window_start,
        'raw_window_end': (
            raw_window_start + M797_C166_RAW_WINDOW_SIZE - 1
        ),
        'table_start': table_start,
        'table_end': (
            table_start + M797_C166_TABLE_WINDOW_SIZE - 1
        ),
        'descriptor_start': descriptor_start,
        'descriptor_end': (
            descriptor_start + M797_C166_DESC_WINDOW_SIZE - 1
        ),
    }


def _m797_c166_far_pointer_words(address: int):
    if not 0 <= address <= 0xFFFFFF:
        raise ValueError('C166 far pointer address must fit in 24 bits')

    page = address >> 14
    offset = address & 0x3FFF

    if page > 0xFFFF:
        raise ValueError('C166 page word does not fit in 16 bits')

    return offset, page


def _m797_build_c166_direct_window(definitions, raw_slot_base: int):
    """
    Build the 60-byte raw F0..F9 c166_four RAM window for one known layout.

    F0..F4:
        01 00 <descriptor offset LE> <descriptor page LE>

    F5..F9:
        09 <length> <flash offset LE> <flash page LE>
    """
    addresses = _m797_c166_window_addresses(raw_slot_base)
    raw_window_start = addresses['raw_window_start']
    window = bytearray(M797_C166_RAW_WINDOW_SIZE)

    for index, (lid, address, size) in enumerate(definitions):
        if lid not in M797_C166_RAW_DATA_LIDS:
            raise ValueError(
                'Direct C166 reader only supports F0..F4 data LIDs'
            )

        if not 1 <= size <= M797_DYNAMIC_READ_CHUNK:
            raise ValueError('C166 descriptor size must be 1..0xF0')

        if size > _page_remaining(address):
            raise ValueError(
                'C166 direct descriptor crosses a 0x4000 page boundary'
            )

        descriptor_lid = M797_C166_RAW_DESC_LIDS[index]
        descriptor_address = _m797_c166_raw_slot_address(
            descriptor_lid,
            raw_slot_base
        )
        descriptor_offset, descriptor_page = _m797_c166_far_pointer_words(
            descriptor_address
        )

        table_offset = (
            _m797_c166_raw_slot_address(lid, raw_slot_base)
            - raw_window_start
        )

        window[table_offset:table_offset + 6] = bytes([
            0x01,
            0x00,
            descriptor_offset & 0xFF,
            (descriptor_offset >> 8) & 0xFF,
            descriptor_page & 0xFF,
            (descriptor_page >> 8) & 0xFF,
        ])

        flash_offset, flash_page = _m797_c166_far_pointer_words(address)
        descriptor_window_offset = descriptor_address - raw_window_start

        window[
            descriptor_window_offset:
            descriptor_window_offset + 6
        ] = bytes([
            M797_C166_DESCRIPTOR_TYPE_MEMORY,
            size,
            flash_offset & 0xFF,
            (flash_offset >> 8) & 0xFF,
            flash_page & 0xFF,
            (flash_page >> 8) & 0xFF,
        ])

    return bytes(window)


def _m797_install_c166_direct_window(
        bus,
        window: bytes,
        raw_slot_base: int
    ) -> None:
    if len(window) != M797_C166_RAW_WINDOW_SIZE:
        raise ValueError(
            'Expected {} C166 raw-window bytes, got {}'
            .format(M797_C166_RAW_WINDOW_SIZE, len(window))
        )

    addresses = _m797_c166_window_addresses(raw_slot_base)

    table_bytes = window[:M797_C166_TABLE_WINDOW_SIZE]
    descriptor_bytes = window[
        M797_C166_TABLE_WINDOW_SIZE:
        M797_C166_TABLE_WINDOW_SIZE + M797_C166_DESC_WINDOW_SIZE
    ]

    # Descriptor records first; activate F0..F4 only after they are complete.
    _m797_write_ram(
        bus,
        addresses['descriptor_start'],
        descriptor_bytes
    )

    try:
        _m797_write_ram(
            bus,
            addresses['table_start'],
            table_bytes
        )
    except Exception:
        try:
            _m797_write_ram(
                bus,
                addresses['descriptor_start'],
                bytes(M797_C166_DESC_WINDOW_SIZE)
            )
        except Exception:
            pass
        raise


def _m797_clear_c166_direct_window(bus, raw_slot_base: int) -> None:
    addresses = _m797_c166_window_addresses(raw_slot_base)

    # Disable F0..F4 before clearing their descriptor records.
    _m797_write_ram(
        bus,
        addresses['table_start'],
        bytes(M797_C166_TABLE_WINDOW_SIZE)
    )
    _m797_write_ram(
        bus,
        addresses['descriptor_start'],
        bytes(M797_C166_DESC_WINDOW_SIZE)
    )


def _m797_c166_direct_preflight(bus, calibration_id: str):
    """
    Prove one runtime-known c166_four layout using its exact flash oracle.

    No unknown calibration is allowed to reach SID 0x3D here.
    """
    calibration_id = (calibration_id or 'UNKNOWN').strip().upper()
    profile = _m797_get_c166_direct_profile(calibration_id)
    raw_slot_base = profile['raw_slot_base']
    target = profile['oracle_target']
    expected = profile['oracle_expected']
    addresses = _m797_c166_window_addresses(raw_slot_base)

    definitions = [(0xF0, target, 0x10)]
    window = _m797_build_c166_direct_window(
        definitions,
        raw_slot_base
    )

    print('[*] Trying direct C166 RAM-descriptor fallback')
    print('[*] Layout: {}'.format(profile['description']))
    print(
        '[*] Raw F0..F9 RAM window: 0x{:06X}-0x{:06X}'
        .format(
            addresses['raw_window_start'],
            addresses['raw_window_end']
        )
    )

    installed = False

    try:
        _m797_install_c166_direct_window(
            bus,
            window,
            raw_slot_base
        )
        installed = True

        print(
            '[+] C166 descriptor window accepted: '
            '0x{:06X}-0x{:06X} ({} bytes)'
            .format(
                addresses['descriptor_start'],
                addresses['descriptor_end'],
                M797_C166_DESC_WINDOW_SIZE
            )
        )
        print(
            '[+] C166 table window accepted     : '
            '0x{:06X}-0x{:06X} ({} bytes)'
            .format(
                addresses['table_start'],
                addresses['table_end'],
                M797_C166_TABLE_WINDOW_SIZE
            )
        )

        data = _m797_read_dynamic_lid(
            bus,
            0xF0,
            0x10,
            retries=1
        )

        if data != expected:
            raise RuntimeError(
                '{} direct-RAM preflight mismatch at 0x{:06X}: '
                'expected {}, got {}'
                .format(
                    calibration_id,
                    target,
                    _hex(expected),
                    _hex(data)
                )
            )

        print(
            '[+] Direct C166 SID 0x21 flash read proven at 0x{:06X}: {}'
            .format(target, _hex(data))
        )

        return profile

    finally:
        if installed:
            try:
                _m797_clear_c166_direct_window(
                    bus,
                    raw_slot_base
                )
                print('[+] Direct C166 F0..F9 RAM window cleared.')
            except Exception as exc:
                raise RuntimeError(
                    'CRITICAL: could not clear direct C166 RAM window: {}. '
                    'Power-cycle the ECU before further diagnostics.'
                    .format(exc)
                )



def _m797_c166_generic_preflight(bus, candidate):
    """
    Architecture-only c166_four probe for an unknown calibration.

    It asks for two adjacent 16-byte blocks using only raw F0 and one scratch
    descriptor.  No calibration-specific oracle is required.

    Success criterion:
      - both 21 F0 requests return exactly 16 bytes
      - retargeting the descriptor is accepted
      - cleanup succeeds

    The candidate order is chosen so the known shifted-base mismatch fails
    benignly before the ADE-style base is attempted.
    """
    raw_slot_base = candidate['raw_slot_base']
    raw_f0 = _m797_c166_raw_slot_address(0xF0, raw_slot_base)
    raw_f1 = _m797_c166_raw_slot_address(0xF1, raw_slot_base)

    def build_descriptor(address):
        offset, page = _m797_c166_far_pointer_words(address)
        return bytes([
            M797_C166_DESCRIPTOR_TYPE_MEMORY,
            0x10,
            offset & 0xFF,
            (offset >> 8) & 0xFF,
            page & 0xFF,
            (page >> 8) & 0xFF,
        ])

    descriptor_offset, descriptor_page = _m797_c166_far_pointer_words(
        raw_f1
    )
    f0_table = bytes([
        0x01,
        0x00,
        descriptor_offset & 0xFF,
        (descriptor_offset >> 8) & 0xFF,
        descriptor_page & 0xFF,
        (descriptor_page >> 8) & 0xFF,
    ])

    targets = (0x800000, 0x800010)
    table_installed = False
    descriptor_installed = False

    print('[*] Trying {}'.format(candidate['description']))
    print('[*]   raw F0      : 0x{:06X}'.format(raw_f0))
    print('[*]   descriptor  : 0x{:06X}'.format(raw_f1))

    try:
        first = build_descriptor(targets[0])
        _m797_write_ram(bus, raw_f1, first)
        descriptor_installed = True

        _m797_write_ram(bus, raw_f0, f0_table)
        table_installed = True

        first_data = _m797_read_dynamic_lid(
            bus,
            0xF0,
            0x10,
            retries=1
        )

        if len(first_data) != 0x10:
            raise RuntimeError(
                'first structural read returned {} bytes, expected 16'
                .format(len(first_data))
            )

        second = build_descriptor(targets[1])
        _m797_write_ram(bus, raw_f1, second)

        second_data = _m797_read_dynamic_lid(
            bus,
            0xF0,
            0x10,
            retries=1
        )

        if len(second_data) != 0x10:
            raise RuntimeError(
                'second structural read returned {} bytes, expected 16'
                .format(len(second_data))
            )

        print(
            '[+] {} accepted two retargeted 16-byte flash reads.'
            .format(candidate['name'])
        )
        print('[+]   0x800000: {}'.format(_hex(first_data)))
        print('[+]   0x800010: {}'.format(_hex(second_data)))

        return {
            'raw_slot_base': raw_slot_base,
            'description': candidate['description'],
            'generic': True,
        }

    finally:
        # Disable F0 first.  These raw slots are expected to be unused for the
        # direct dynamic-LID fallback, and every proven family boots them zero.
        if table_installed:
            _m797_write_ram(bus, raw_f0, bytes(6))
        if descriptor_installed:
            _m797_write_ram(bus, raw_f1, bytes(6))



def _m797_read_flash_c166_direct(
        bus,
        result: bytearray,
        bar,
        profile
    ) -> None:
    """
    Full external-flash reader for one runtime-proven c166_four RAM layout.
    """
    raw_slot_base = profile['raw_slot_base']
    address = M797_FLASH_START
    end = M797_FLASH_START + M797_IMAGE_SIZE
    window_installed = False

    try:
        while address < end:
            definitions = []

            for lid in M797_C166_RAW_DATA_LIDS:
                if address >= end:
                    break

                remaining = end - address
                size = min(
                    M797_DYNAMIC_READ_CHUNK,
                    _page_remaining(address),
                    remaining
                )

                definitions.append((lid, address, size))
                address += size

            window = _m797_build_c166_direct_window(
                definitions,
                raw_slot_base
            )

            _m797_install_c166_direct_window(
                bus,
                window,
                raw_slot_base
            )
            window_installed = True

            for lid, chunk_address, size in definitions:
                chunk = _m797_read_dynamic_lid(
                    bus,
                    lid,
                    size
                )

                if len(chunk) != size:
                    raise RuntimeError(
                        'Short direct-C166 read at 0x{:06X}: '
                        'got {}, expected {}'
                        .format(chunk_address, len(chunk), size)
                    )

                result.extend(chunk)
                bar(size)

        _m797_clear_c166_direct_window(
            bus,
            raw_slot_base
        )
        window_installed = False

    finally:
        if window_installed:
            try:
                _m797_clear_c166_direct_window(
                    bus,
                    raw_slot_base
                )
                print('[+] Direct C166 F0..F9 RAM window cleared.')
            except Exception as exc:
                print(
                    '[!] CRITICAL: direct C166 RAM-window cleanup failed: {}. '
                    'Power-cycle ECU before further diagnostics.'
                    .format(exc)
                )


def _m797_lcr_raw_slot_address(lid: int) -> int:
    if not 0 <= lid <= 0xFF:
        raise ValueError('LCR raw LID must fit in one byte')
    return M797_LCR_RAW_SLOT_BASE + (lid * 8)


def _m797_build_lcr_direct_window(definitions):
    """
    Build the complete 80-byte raw F0..F9 LCR RAM window.

    F0..F4:
        8-byte active table entries:
            +0      descriptor count = 1
            +1      state/reserved = 0
            +2/+3   descriptor pool offset, little endian
            +4/+5   descriptor pool EXTS segment, little endian
            +6/+7   unused by SID 0x21 read path

    F5..F9:
        one 8-byte storage slot each; first six bytes contain:
            +0      returned data length
            +1      padding / ignored by SID 0x21
            +2/+3   linear address low word, little endian
            +4/+5   linear address high word, little endian
            +6/+7   zero

    Runtime proof on LCR0N53 established that SID 0x21 dereferences these
    descriptors directly without invoking SID 0x2C or the external-flash gate.
    """
    window = bytearray(M797_LCR_RAW_WINDOW_SIZE)

    for index, (lid, address, size) in enumerate(definitions):
        if lid not in M797_LCR_RAW_DATA_LIDS:
            raise ValueError(
                'Direct LCR reader only supports F0..F4 data LIDs'
            )

        if not 1 <= size <= M797_DYNAMIC_READ_CHUNK:
            raise ValueError('LCR descriptor size must be 1..0xF0')

        descriptor_lid = M797_LCR_RAW_DESC_LIDS[index]
        descriptor_address = _m797_lcr_raw_slot_address(descriptor_lid)

        descriptor_offset = descriptor_address & 0xFFFF
        descriptor_segment = (descriptor_address >> 16) & 0xFFFF

        table_window_offset = (
            _m797_lcr_raw_slot_address(lid)
            - M797_LCR_RAW_WINDOW_START
        )

        window[
            table_window_offset:
            table_window_offset + 8
        ] = bytes([
            0x01,
            0x00,
            descriptor_offset & 0xFF,
            (descriptor_offset >> 8) & 0xFF,
            descriptor_segment & 0xFF,
            (descriptor_segment >> 8) & 0xFF,
            0x00,
            0x00,
        ])

        low_word = address & 0xFFFF
        high_word = (address >> 16) & 0xFFFF
        descriptor_window_offset = (
            descriptor_address - M797_LCR_RAW_WINDOW_START
        )

        window[
            descriptor_window_offset:
            descriptor_window_offset + 8
        ] = bytes([
            size,
            0x00,
            low_word & 0xFF,
            (low_word >> 8) & 0xFF,
            high_word & 0xFF,
            (high_word >> 8) & 0xFF,
            0x00,
            0x00,
        ])

    return bytes(window)


def _m797_install_lcr_direct_window(bus, window: bytes) -> None:
    if len(window) != M797_LCR_RAW_WINDOW_SIZE:
        raise ValueError(
            'Expected {} LCR raw-window bytes, got {}'
            .format(M797_LCR_RAW_WINDOW_SIZE, len(window))
        )

    table_bytes = window[:M797_LCR_TABLE_WINDOW_SIZE]
    descriptor_bytes = window[
        M797_LCR_TABLE_WINDOW_SIZE:
        M797_LCR_TABLE_WINDOW_SIZE + M797_LCR_DESC_WINDOW_SIZE
    ]

    # Descriptors first; active tables second.
    _m797_write_ram(
        bus,
        M797_LCR_DESC_WINDOW_START,
        descriptor_bytes
    )

    try:
        _m797_write_ram(
            bus,
            M797_LCR_TABLE_WINDOW_START,
            table_bytes
        )
    except Exception:
        try:
            _m797_write_ram(
                bus,
                M797_LCR_DESC_WINDOW_START,
                bytes(M797_LCR_DESC_WINDOW_SIZE)
            )
        except Exception:
            pass
        raise


def _m797_clear_lcr_direct_window(bus) -> None:
    # Disable F0..F4 before clearing descriptor storage.
    _m797_write_ram(
        bus,
        M797_LCR_TABLE_WINDOW_START,
        bytes(M797_LCR_TABLE_WINDOW_SIZE)
    )
    _m797_write_ram(
        bus,
        M797_LCR_DESC_WINDOW_START,
        bytes(M797_LCR_DESC_WINDOW_SIZE)
    )


def _m797_lcr_direct_preflight(bus, calibration_id: str) -> bytes:
    """
    Prove the LCR linear descriptor primitive using an exact LCR0N53 oracle.

    This path is intentionally enabled only for the runtime-proven LCR0N53
    calibration until another c166_lcr variant is tested.
    """
    calibration_id = (calibration_id or 'UNKNOWN').strip().upper()

    if calibration_id != 'LCR0N53':
        raise RuntimeError(
            'LCR direct-RAM fallback is currently runtime-proven only for '
            'LCR0N53; detected calibration is {}'
            .format(calibration_id)
        )

    target = 0x845AC0
    expected = bytes.fromhex(
        'B9 E4 E0 08 EA 00 4C 5B '
        'E0 09 0D 28 C0 E4 5C 34'
    )

    window = _m797_build_lcr_direct_window([
        (0xF0, target, 0x10)
    ])

    print('[*] Trying LCR linear RAM-descriptor fallback')
    print(
        '[*] Raw F0..F9 LCR RAM window: 0x{:06X}-0x{:06X}'
        .format(
            M797_LCR_RAW_WINDOW_START,
            M797_LCR_RAW_WINDOW_START
            + M797_LCR_RAW_WINDOW_SIZE - 1
        )
    )

    installed = False

    try:
        _m797_install_lcr_direct_window(bus, window)
        installed = True

        print(
            '[+] LCR descriptor window accepted: '
            '0x{:06X}-0x{:06X} ({} bytes)'
            .format(
                M797_LCR_DESC_WINDOW_START,
                M797_LCR_DESC_WINDOW_START
                + M797_LCR_DESC_WINDOW_SIZE - 1,
                M797_LCR_DESC_WINDOW_SIZE
            )
        )
        print(
            '[+] LCR table window accepted     : '
            '0x{:06X}-0x{:06X} ({} bytes)'
            .format(
                M797_LCR_TABLE_WINDOW_START,
                M797_LCR_TABLE_WINDOW_START
                + M797_LCR_TABLE_WINDOW_SIZE - 1,
                M797_LCR_TABLE_WINDOW_SIZE
            )
        )

        data = _m797_read_dynamic_lid(
            bus,
            0xF0,
            0x10,
            retries=1
        )

        if data != expected:
            raise RuntimeError(
                'LCR0N53 direct-RAM preflight mismatch at 0x{:06X}: '
                'expected {}, got {}'
                .format(target, _hex(expected), _hex(data))
            )

        print(
            '[+] Direct LCR SID 0x21 flash read proven at 0x{:06X}: {}'
            .format(target, _hex(data))
        )

        return data

    finally:
        if installed:
            try:
                _m797_clear_lcr_direct_window(bus)
                print('[+] Direct LCR F0..F9 RAM window cleared.')
            except Exception as exc:
                raise RuntimeError(
                    'CRITICAL: could not clear direct LCR RAM window: {}. '
                    'Power-cycle the ECU before further diagnostics.'
                    .format(exc)
                )



def _m797_lcr_generic_preflight(bus):
    """
    Architecture-only LCR probe for an unknown calibration.

    Uses raw F0 at 0x380794 and raw F1 at 0x38079C, asks for two adjacent
    16-byte linear reads, then restores both locations to zero.
    """
    raw_f0 = 0x380794
    raw_f1 = 0x38079C

    descriptor_offset = raw_f1 & 0xFFFF
    descriptor_segment = (raw_f1 >> 16) & 0xFFFF

    f0_table = bytes([
        0x01, 0x00,
        descriptor_offset & 0xFF,
        (descriptor_offset >> 8) & 0xFF,
        descriptor_segment & 0xFF,
        (descriptor_segment >> 8) & 0xFF,
        0x00, 0x00,
    ])

    def build_descriptor(address):
        low_word = address & 0xFFFF
        high_word = (address >> 16) & 0xFFFF
        return bytes([
            0x10,
            0x00,
            low_word & 0xFF,
            (low_word >> 8) & 0xFF,
            high_word & 0xFF,
            (high_word >> 8) & 0xFF,
        ])

    table_installed = False
    descriptor_installed = False
    targets = (0x800000, 0x800010)

    print('[*] Trying c166_lcr 8-byte table / linear descriptor')

    try:
        _m797_write_ram(bus, raw_f1, build_descriptor(targets[0]))
        descriptor_installed = True

        _m797_write_ram(bus, raw_f0, f0_table)
        table_installed = True

        first_data = _m797_read_dynamic_lid(
            bus, 0xF0, 0x10, retries=1
        )
        if len(first_data) != 0x10:
            raise RuntimeError(
                'first LCR structural read returned {} bytes, expected 16'
                .format(len(first_data))
            )

        _m797_write_ram(bus, raw_f1, build_descriptor(targets[1]))
        second_data = _m797_read_dynamic_lid(
            bus, 0xF0, 0x10, retries=1
        )
        if len(second_data) != 0x10:
            raise RuntimeError(
                'second LCR structural read returned {} bytes, expected 16'
                .format(len(second_data))
            )

        print('[+] LCR architecture accepted two retargeted 16-byte reads.')
        print('[+]   0x800000: {}'.format(_hex(first_data)))
        print('[+]   0x800010: {}'.format(_hex(second_data)))
        return True

    finally:
        if table_installed:
            _m797_write_ram(bus, raw_f0, bytes(8))
        if descriptor_installed:
            _m797_write_ram(bus, raw_f1, bytes(6))



def _m797_read_flash_lcr_direct(
        bus,
        result: bytearray,
        bar
    ) -> None:
    """
    Full 512 KiB external-flash reader for LCR0N53 / c166_lcr.

    Each batch:
        one 40-byte SID 0x3D descriptor-storage write (F5..F9)
        one 40-byte SID 0x3D table activation write   (F0..F4)
        up to five SID 0x21 reads                     (F0..F4)

    LCR descriptors contain a 24-bit linear address and the SID 0x21 copy
    loop propagates low-word carry into the high word, so no 0x4000 C166
    page-boundary clipping is required.
    """
    address = M797_FLASH_START
    end = M797_FLASH_START + M797_IMAGE_SIZE
    window_installed = False

    try:
        while address < end:
            definitions = []

            for lid in M797_LCR_RAW_DATA_LIDS:
                if address >= end:
                    break

                remaining = end - address
                size = min(
                    M797_DYNAMIC_READ_CHUNK,
                    remaining
                )

                definitions.append((lid, address, size))
                address += size

            window = _m797_build_lcr_direct_window(definitions)

            _m797_install_lcr_direct_window(bus, window)
            window_installed = True

            for lid, chunk_address, size in definitions:
                chunk = _m797_read_dynamic_lid(
                    bus,
                    lid,
                    size
                )

                if len(chunk) != size:
                    raise RuntimeError(
                        'Short direct-LCR read at 0x{:06X}: '
                        'got {}, expected {}'
                        .format(chunk_address, len(chunk), size)
                    )

                result.extend(chunk)
                bar(size)

        _m797_clear_lcr_direct_window(bus)
        window_installed = False

    finally:
        if window_installed:
            try:
                _m797_clear_lcr_direct_window(bus)
                print('[+] Direct LCR F0..F9 RAM window cleared.')
            except Exception as exc:
                print(
                    '[!] CRITICAL: direct LCR RAM-window cleanup failed: {}. '
                    'Power-cycle ECU before further diagnostics.'
                    .format(exc)
                )


def _m797_known_class4_hint(calibration_id: str):
    calibration_id = (calibration_id or '').strip().upper()
    profile = M797_PATCHLESS_LINEAR_PROFILES.get(calibration_id)
    if profile is None:
        return None
    return profile['class4_descriptor_word']


def _m797_word_distance(a: int, b: int) -> int:
    delta = (a - b) & 0xFFFF
    return min(delta, (-delta) & 0xFFFF)


def _m797_descriptor_candidates(
        baseline: bytes,
        calibration_id: str
    ):
    """
    Return a bounded list of plausible class-4 descriptor words.

    The strongest generic observation is that the CLOSED and class-4
    descriptors relocate together and are 0xE6 bytes apart:
        19A4 -> 1A8A
        1B7E -> 1C64
    Exact calibration hints are retained, but unknown IDs are not rejected.
    """
    live_word = int.from_bytes(baseline[0:2], 'little')
    candidates = []

    def add(word: int, reason: str):
        word &= 0xFFFF
        if word == live_word:
            return
        if any(existing == word for existing, _ in candidates):
            return
        candidates.append((word, reason))

    # Generic relocation rule first: this is what makes unknown relocated
    # linear/single-gate variants self-identifying.
    add(
        live_word + M797_DESCRIPTOR_RELOCATION_DELTA,
        'live descriptor + 0xE6'
    )

    # Exact hint for a calibration we already know, but never required.
    hint = _m797_known_class4_hint(calibration_id)
    if hint is not None:
        add(hint, 'known calibration hint')

    # Bounded fallback to already-seen comparator words only when they are
    # close to the current descriptor. Do not brute-force arbitrary pointers.
    for word in sorted(M797_KNOWN_CLASS4_WORDS):
        if _m797_word_distance(word, live_word) <= 0x0200:
            add(word, 'nearby known class-4 word')

    return candidates


def _m797_build_descriptor_spoof(
        baseline: bytes,
        class4_word: int
    ) -> bytes:
    # Preserve the ECU's live page word exactly; only the classifier word is
    # changed, and both runtime copies are always written atomically.
    half = (
        int(class4_word & 0xFFFF).to_bytes(2, 'little')
        + baseline[2:4]
    )
    return half + half

def _m797_patchless_read_preflight(
        bus,
        baseline: bytes,
        calibration_id: str,
        address_mode: str
    ):
    """
    Prove RAM write/restore and discover a working class-4 descriptor.

    Returns:
        (spoof_bytes_or_None, class4_word_or_None)

    None means the ECU already accepts external-flash definitions without a
    RAM spoof. That can be a naturally open runtime or an ECU that was
    previously persistently patched; a warning is emitted in that case.
    """
    print('[*] Patchless read preflight')

    # Prove SID 0x3D without changing state.
    response = _m797_write_ram(
        bus,
        M797_READ_DESCRIPTOR_ADDRESS,
        baseline
    )
    print('[+] SID 0x3D no-op RAM write: {}'.format(_hex(response)))

    if _m797_read_descriptor_pair(bus, address_mode) != baseline:
        raise RuntimeError('Descriptor changed during SID 0x3D no-op proof')

    # Negative control. If already accepted, no RAM spoof is needed.
    try:
        _m797_define_dynamic_lid(
            bus,
            M797_READ_DATA_LIDS[0],
            M797_FLASH_START,
            0x10,
            address_mode=address_mode
        )
    except kwp2000.Kwp2000NegativeResponseException as exc:
        if exc.status.identifier != 0x12:
            raise
        print('[+] Stock external-flash gate is closed (NRC 0x12).')
    else:
        data = _m797_read_dynamic_lid(
            bus,
            M797_READ_DATA_LIDS[0],
            0x10
        )
        print(
            '[!] External flash is already readable without RAM spoof: {}'
            .format(_hex(data))
        )
        print(
            '[!] Continuing without a spoof. If this ECU still contains an '
            'old persistent read patch, the dump will contain the ECU exactly '
            'as it is currently flashed.'
        )
        return None, None

    candidates = _m797_descriptor_candidates(
        baseline,
        calibration_id
    )

    if not candidates:
        raise RuntimeError('No plausible class-4 descriptor candidates')

    print('[*] Auto-discovering class-4 descriptor word')

    for class4_word, reason in candidates:
        spoof = _m797_build_descriptor_spoof(
            baseline,
            class4_word
        )

        print(
            '[*] Trying 0x{:04X}:0x{:04X} ({})'
            .format(
                class4_word,
                int.from_bytes(baseline[2:4], 'little'),
                reason
            )
        )

        defined = False
        rejected_nrc = None
        candidate_error = None
        restore_error = None

        try:
            _m797_write_ram(
                bus,
                M797_READ_DESCRIPTOR_ADDRESS,
                spoof
            )

            try:
                _m797_define_dynamic_lid(
                    bus,
                    M797_READ_DATA_LIDS[0],
                    M797_FLASH_START,
                    0x10,
                    address_mode=address_mode
                )
                defined = True
            except kwp2000.Kwp2000NegativeResponseException as exc:
                rejected_nrc = exc.status.identifier
            except Exception as exc:
                candidate_error = exc

        except Exception as exc:
            candidate_error = exc

        finally:
            try:
                _m797_write_ram(
                    bus,
                    M797_READ_DESCRIPTOR_ADDRESS,
                    baseline
                )
            except Exception as exc:
                restore_error = exc

        if restore_error is not None:
            raise RuntimeError(
                'CRITICAL: failed to restore E048:E04F after candidate '
                '0x{:04X}: {}. ECU flash was not modified; power-cycle ECU.'
                .format(class4_word, restore_error)
            )

        restored = _m797_read_descriptor_pair(
            bus,
            address_mode
        )
        if restored != baseline:
            raise RuntimeError(
                'Descriptor restoration mismatch after candidate 0x{:04X}: '
                'expected {}, got {}'
                .format(
                    class4_word,
                    _hex(baseline),
                    _hex(restored)
                )
            )

        if not defined:
            if rejected_nrc is not None:
                print(
                    '[*] Candidate 0x{:04X} rejected (NRC 0x{:02X})'
                    .format(class4_word, rejected_nrc)
                )
                continue

            if candidate_error is not None:
                print(
                    '[*] Candidate 0x{:04X} failed: {}'
                    .format(class4_word, candidate_error)
                )
                continue

            print(
                '[*] Candidate 0x{:04X} did not define a flash LID'
                .format(class4_word)
            )
            continue

        try:
            data = _m797_read_dynamic_lid(
                bus,
                M797_READ_DATA_LIDS[0],
                0x10
            )
        except Exception as exc:
            print(
                '[*] Candidate 0x{:04X} defined but 0x21 failed: {}'
                .format(class4_word, exc)
            )
            continue

        print(
            '[+] Class-4 descriptor discovered: 0x{:04X}:0x{:04X}'
            .format(
                class4_word,
                int.from_bytes(baseline[2:4], 'little')
            )
        )
        print(
            '[+] Patchless 0x800000 read proven: {}'
            .format(_hex(data))
        )
        return spoof, class4_word

    raise RuntimeError(
        'No safe class-4 descriptor candidate opened the stock external-flash '
        'gate. This firmware may use a different descriptor layout or an '
        'older SID 0x2C parser family requiring additional RAM-side fixes.'
    )


def m797_read_flash(
        bus,
        calibration_id: str,
        output_filename: str = 'm797_read.bin',
        progress_callback=None,
        read_profile: str | None = None
    ) -> bytes:
    """
    Read the complete 512 KiB external flash without modifying ECU flash.

    Standard read: 57.6 kbaud (selector 0x64)
    Fast read:     108.8 kbaud (selector 0x82)

    Auto-detected read architectures:

      1) Native/linear-style application parser:
           SID 0x2C + paired E048:E04F RAM spoof + SID 0x21

      2) Runtime-profiled c166_four parser:
           calibration-specific raw F0..F9 table base + six-byte descriptors
           in 0x38xxxx RAM, using SID 0x3D then SID 0x21

      3) Runtime-profiled c166_lcr parser:
           8-byte raw table + linear six-byte descriptor

    Unknown calibration IDs are architecture-probed against every known direct-RAM layout.
    None of these paths writes or erases external flash.
    """
    calibration_id = (calibration_id or 'UNKNOWN').strip().upper()

    if not output_filename:
        output_filename = 'm797_read.bin'

    if read_profile is None:
        read_profile = m797_choose_read_profile()
    profile = _m797_read_profile(read_profile)

    print('')
    print('=' * 76)
    print('[*] M7.9.7 PATCHLESS FULL EXTERNAL-FLASH READ')
    print('=' * 76)
    print('[*] Calibration : {}'.format(calibration_id))
    print('[*] Read method : AUTO')
    print('[*] Range       : 0x{:06X}-0x{:06X}'.format(
        M797_FLASH_START,
        M797_FLASH_END
    ))
    print('[*] Size        : {} bytes (0x{:X})'.format(
        M797_IMAGE_SIZE,
        M797_IMAGE_SIZE
    ))
    print('[*] Baud        : {} ({})'.format(
        profile['baudrate'],
        profile['name']
    ))
    print('[*] Flash patch : NONE')
    print('[*] Flash erase : NONE')

    result = bytearray()
    baseline = None
    spoof = None
    descriptor_known_restored = True
    session_switched = False
    read_method = None
    c166_profile = None

    try:
        _m797_switch_read_baud(bus, read_profile)
        session_switched = True

        # --------------------------------------------------------------
        # Method A: native dynamic-LID parser + paired runtime gate.
        # --------------------------------------------------------------
        print('')
        print('[*] METHOD A - probing stock SID 0x2C dynamic parser')

        try:
            address_mode, baseline = _m797_detect_dynamic_address_mode(bus)
        except Exception as native_exc:
            print('[*] Native dynamic-LID method unavailable: {}'.format(
                native_exc
            ))
            address_mode = None
        else:
            print('[+] E048:E04F = {}'.format(_hex(baseline)))

            spoof, class4_word = _m797_patchless_read_preflight(
                bus,
                baseline,
                calibration_id,
                address_mode
            )

            if class4_word is not None:
                print(
                    '[+] Selected gate target: 0x{:04X}:0x{:04X}'
                    .format(
                        class4_word,
                        int.from_bytes(baseline[2:4], 'little')
                    )
                )

            print('[+] Selected address mode: {}'.format(address_mode))
            read_method = 'native'

        # --------------------------------------------------------------
        # Method B: direct raw C166 RAM descriptor fallback.
        # --------------------------------------------------------------
        # --------------------------------------------------------------
        # Direct-RAM architectures.
        #
        # Exact known calibrations use their proven oracle immediately.
        # Unknown calibrations are architecture-probed rather than rejected.
        # --------------------------------------------------------------
        if read_method is None and calibration_id == 'LCR0N53':
            print('')
            print('[*] METHOD B - known LCR linear RAM layout')
            _m797_lcr_direct_preflight(bus, calibration_id)
            read_method = 'lcr_direct'

        if (
            read_method is None
            and calibration_id in M797_C166_DIRECT_PROFILES
        ):
            print('')
            print('[*] METHOD B - known c166_four RAM layout')
            c166_profile = _m797_c166_direct_preflight(
                bus,
                calibration_id
            )
            read_method = 'c166_direct'

        if read_method is None:
            print('')
            print(
                '[*] METHOD B - unknown calibration; trying all known '
                'direct-RAM architectures'
            )

            # LCR first: its table lives well away from the six-byte c166
            # tables and wrong-family probes have so far failed cleanly.
            try:
                _m797_lcr_generic_preflight(bus)
            except Exception as exc:
                print('[*] LCR candidate rejected: {}'.format(exc))
            else:
                read_method = 'lcr_direct'

        if read_method is None:
            # Then the c166_four layouts in deliberately descending-base
            # order: 0x8044, 0x803A, then ADE-style 0x8036.
            for candidate in M797_C166_GENERIC_CANDIDATES:
                try:
                    c166_profile = _m797_c166_generic_preflight(
                        bus,
                        candidate
                    )
                except Exception as exc:
                    print(
                        '[*] {} candidate rejected: {}'
                        .format(candidate['name'], exc)
                    )
                    continue

                read_method = 'c166_direct'
                break

        if read_method is None:
            raise RuntimeError(
                'None of the known patchless read architectures matched '
                'calibration {}.'
                .format(calibration_id)
            )

        print('')
        if read_method == 'native':
            print('[+] Read architecture: native SID 0x2C + SID 0x21')
        elif read_method == 'c166_direct':
            print(
                '[+] Read architecture: c166_four raw RAM descriptor + SID 0x21'
            )
        else:
            print(
                '[+] Read architecture: c166_lcr linear RAM descriptor + SID 0x21'
            )

        with _m797_progress(
            M797_IMAGE_SIZE,
            'Reading M7.9.7',
            progress_callback=progress_callback
        ) as bar:

            if read_method == 'c166_direct':
                _m797_read_flash_c166_direct(
                    bus,
                    result,
                    bar,
                    c166_profile
                )

            elif read_method == 'lcr_direct':
                _m797_read_flash_lcr_direct(
                    bus,
                    result,
                    bar
                )

            else:
                address = M797_FLASH_START
                end = M797_FLASH_START + M797_IMAGE_SIZE
                batch_index = 0

                while address < end:
                    batch_index += 1
                    definitions = []

                    for lid in M797_READ_DATA_LIDS:
                        if address >= end:
                            break

                        remaining = end - address
                        size = min(
                            M797_DYNAMIC_READ_CHUNK,
                            _page_remaining(address),
                            remaining
                        )

                        definitions.append((lid, address, size))
                        address += size

                    if spoof is None:
                        for lid, chunk_address, size in definitions:
                            _m797_define_dynamic_lid(
                                bus,
                                lid,
                                chunk_address,
                                size,
                                address_mode=address_mode
                            )
                        descriptor_known_restored = True
                    else:
                        descriptor_known_restored = False
                        restore_error = None

                        try:
                            _m797_write_ram(
                                bus,
                                M797_READ_DESCRIPTOR_ADDRESS,
                                spoof
                            )

                            for lid, chunk_address, size in definitions:
                                _m797_define_dynamic_lid(
                                    bus,
                                    lid,
                                    chunk_address,
                                    size,
                                    address_mode=address_mode
                                )

                        finally:
                            try:
                                _m797_write_ram(
                                    bus,
                                    M797_READ_DESCRIPTOR_ADDRESS,
                                    baseline
                                )
                                descriptor_known_restored = True
                            except Exception as exc:
                                restore_error = exc

                        if restore_error is not None:
                            raise RuntimeError(
                                'CRITICAL: E048:E04F restore failed after '
                                'batch {}: {}. ECU flash was not modified; '
                                'power-cycle the ECU.'
                                .format(batch_index, restore_error)
                            )

                    for lid, chunk_address, size in definitions:
                        chunk = _m797_read_dynamic_lid(
                            bus,
                            lid,
                            size
                        )

                        if len(chunk) != size:
                            raise RuntimeError(
                                'Short read at 0x{:06X}: got {}, expected {}'
                                .format(chunk_address, len(chunk), size)
                            )

                        result.extend(chunk)
                        bar(size)

                    if batch_index == 1 or (batch_index % 32) == 0:
                        current = _m797_read_dynamic_lid(
                            bus,
                            M797_READ_STATE_LID,
                            8
                        )

                        if current != baseline:
                            raise RuntimeError(
                                'Runtime descriptor drift after batch {}: '
                                'expected {}, got {}'
                                .format(
                                    batch_index,
                                    _hex(baseline),
                                    _hex(current)
                                )
                            )

        if len(result) != M797_IMAGE_SIZE:
            raise RuntimeError(
                'Final dump size is {}, expected {}'
                .format(len(result), M797_IMAGE_SIZE)
            )

        Path(output_filename).write_bytes(result)

        print('')
        print('[+] FULL PATCHLESS READ COMPLETE')
        method_label = {
            'native': 'native dynamic LID',
            'c166_direct': 'direct c166_four RAM descriptor',
            'lcr_direct': 'direct c166_lcr linear RAM descriptor',
        }.get(read_method, str(read_method))

        print('[+] Method: {}'.format(method_label))
        print('[+] Saved {} bytes to {}'.format(
            len(result),
            output_filename
        ))
        print('[+] Saved BIN CRC32: {:08X}'.format(
            zlib.crc32(result) & 0xFFFFFFFF
        ))
        print('[+] ECU external flash was not erased or programmed.')

        return bytes(result)

    finally:
        # Native-method paired runtime-descriptor restoration.
        if (
            read_method == 'native'
            and baseline is not None
            and not descriptor_known_restored
        ):
            try:
                _m797_write_ram(
                    bus,
                    M797_READ_DESCRIPTOR_ADDRESS,
                    baseline
                )
                descriptor_known_restored = True
                print('[+] Final E048:E04F restoration completed.')
            except Exception as exc:
                print(
                    '[!] Final E048:E04F restoration failed: {}. Power-cycle '
                    'the ECU before further diagnostics.'
                    .format(exc)
                )

        if session_switched:
            if read_method == 'native':
                for lid in (
                    M797_READ_STATE_LID,
                    *M797_READ_DATA_LIDS
                ):
                    try:
                        _m797_clear_dynamic_lid(bus, lid)
                    except Exception:
                        pass

            elif read_method == 'c166_direct':
                if c166_profile is not None:
                    try:
                        _m797_clear_c166_direct_window(
                            bus,
                            c166_profile['raw_slot_base']
                        )
                    except Exception:
                        pass

            elif read_method == 'lcr_direct':
                try:
                    _m797_clear_lcr_direct_window(bus)
                except Exception:
                    pass

            _m797_restore_startup_baud(bus, read_profile)
