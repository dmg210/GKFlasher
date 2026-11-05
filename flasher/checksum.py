"""Family-neutral checksum detection, correction plans and atomic saving."""

from dataclasses import dataclass
import os
from pathlib import Path
import shutil
import sys
import tempfile

from . import checksum_m797, checksum_simk
# Compatibility exports for existing callers; algorithms live in their family modules.
from .checksum_simk import checksum, concat_3_bytes, read_and_reverse, cks_types
from .checksum_m797 import (
    m797_sum16_le, m797_boot_boundary_checksum, m797_checksum_descriptors,
    m797_is_calibration_image, m797_correct_image_checksums,
    m797_correct_calibration_checksums, prepare_m797_checksum_correction,
)
from ecu_definitions import M797_IMAGE_SIZE

__all__ = [
    'ChecksumField', 'ChecksumCorrection', 'detect_offsets', 'prepare_checksum_correction',
    'save_checksum_correction', 'correct_checksum', 'checksum', 'concat_3_bytes',
    'read_and_reverse', 'cks_types', 'm797_sum16_le', 'm797_boot_boundary_checksum',
    'm797_checksum_descriptors', 'm797_is_calibration_image', 'm797_correct_image_checksums',
    'm797_correct_calibration_checksums', 'prepare_m797_checksum_correction',
    'save_m797_checksum_correction',
]


@dataclass(frozen=True)
class ChecksumField:
    name: str
    offset: int
    old: int
    new: int

    @property
    def changed(self):
        return self.old != self.new

    def describe(self):
        return 'Current {} checksum: {}, new checksum: {}'.format(self.name, hex(self.old), hex(self.new))


@dataclass(frozen=True)
class ChecksumCorrection:
    original: bytes
    corrected: bytes
    algorithm: str
    fields: tuple[ChecksumField, ...]

    @property
    def changes(self):
        return tuple(field for field in self.fields if field.changed)

    def save(self, filename):
        save_checksum_correction(filename, self.original, self.corrected)


def detect_offsets(payload):
    if len(payload) == M797_IMAGE_SIZE:
        try:
            checksum_m797.m797_checksum_descriptors(payload)
        except RuntimeError:
            pass
        else:
            return {'name': 'Kefico/Bosch M7.9.7', 'algorithm': 'm797'}
    return checksum_simk.detect_offsets(payload)


def prepare_checksum_correction(payload, report=print):
    layout = detect_offsets(payload)
    if layout is None:
        raise ValueError('Calibration zone not detected.')
    report('[*] Trying to detect type.. {}'.format(layout['name']))
    algorithm = layout.get('algorithm', 'simk')
    if algorithm == 'm797':
        corrected, fields = checksum_m797.prepare_m797_checksum_correction(payload, report)
    else:
        corrected, fields = checksum_simk.prepare_correction(payload, layout, report)
    return ChecksumCorrection(bytes(payload), corrected, algorithm,
                              tuple(ChecksumField(**field) for field in fields))


def save_checksum_correction(filename, original, corrected):
    """Refuse stale previews and replace the BIN only after its complete write."""
    path = Path(filename).resolve()
    if path.read_bytes() != original:
        raise ValueError('BIN changed after checksum preview; reopen it before saving.')
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(dir=path.parent, prefix=path.name + '.', suffix='.tmp', delete=False) as output:
            temporary = Path(output.name)
            output.write(corrected)
            output.flush()
            os.fsync(output.fileno())
        shutil.copymode(path, temporary)
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)


def save_m797_checksum_correction(filename, corrected, changes):
    """Compatibility adapter for previously previewed M797 corrections."""
    original = bytearray(corrected)
    for change in changes:
        offset = change['offset']
        original[offset:offset + 4] = change['old'].to_bytes(4, 'little')
    save_checksum_correction(filename, original, corrected)


def correct_checksum(filename):
    """CLI presentation; calculation and saving are shared with the GUI."""
    print('[*] Reading {}'.format(filename))
    try:
        correction = prepare_checksum_correction(Path(filename).read_bytes())
        if input('[?] Save to {}? [y/n]: '.format(filename)) == 'y':
            if correction.changes:
                correction.save(filename)
            print('[*] Done!')
    except (OSError, ValueError, RuntimeError) as exc:
        print('[!] Error: {}'.format(exc))
        sys.exit(1)
    sys.exit(0)
