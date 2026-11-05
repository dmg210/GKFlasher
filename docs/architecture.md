# Backend and frontend responsibilities

GKFlasher uses gkbus for devices, channels, transports and diagnostic commands.
Family-specific code implements ECU memory layouts and programming sequences;
the CLI and GUI supply user interaction and progress presentation.

## Checksums

- `flasher/checksum_simk.py` owns SIMK layout detection and chained CRC16 calculation.
- `flasher/checksum_m797.py` owns M7.9.7 additive sums, complements and boot integrity.
- `flasher/checksum.py` dispatches to those algorithms and returns an immutable
  `ChecksumCorrection` containing the original image, corrected image and fields.

Both frontends call `prepare_checksum_correction()`. Calculation never modifies
the input file. The GUI renders a preview, while the CLI asks whether to save.
`ChecksumCorrection.save()` checks that the source still matches the preview,
writes a temporary file in the same directory, and replaces the original only
after the write succeeds. This process is shared by both ECU families.

The GUI retains the SIMK region preview and shows only incorrect fields for
M7.9.7. Console reporting includes the checked regions even when no correction
is needed. Existing checksum imports remain available through `checksum.py`
as compatibility exports; each algorithm has only one implementation.

## ECU operations

`flasher/simk.py` contains `SimkOperations`, which holds an ECU and frontend
callbacks. CLI and GUI reads share range handling, padded-image construction,
filename generation and saving. Flashing shares payload planning, erase,
transfer, verification and reset. Planning validates all selected payloads
before any erase and preserves the protected program header and calibration tail.

SIMK programming now consistently uses the program region's address plus 16
bytes; the old CLI path incorrectly used the region size as the address.
Verification failure aborts without reset, restores the transport timeout and
ends the GUI phase indicator. Connection lifetime belongs to the caller.

`flasher/m797.py` retains its distinct programming and RAM-only read sequences,
with reboot preparation in `m797_reboot.py`. They share checksum algorithms,
logging and byte-progress presentation with the rest of the application. The
refactor does not broaden firmware compatibility or remove reboot checks.

`flasher/ecu.py` owns layouts, security/timing helpers, family detection and
shared identification/DTC decoding and reporting. Family-specific callers
select the diagnostic session and DTC group. Existing M7.9.7 display entry
points are thin adapters to the same reporting implementation.

`flasher/memory.py` performs SIMK transfers. Reads count pages upwards and clip
the final page to the requested range; a 0x5F40-byte V6 calibration read returns
exactly 0x5F40 bytes. Transfer trimming includes the last nonblank byte.

## Connections and presentation

`flasher/connection.py` opens gkbus channels and ensures both the protocol and
device are closed even if cleanup of one resource fails. Opening the channel
separately allows RSW/MTOS to reuse it after leaving KWP. Backend operations
do not close a connection owned by a frontend.

`flasher/utils.py` provides shared CLI/GUI logging and byte-progress contexts.
The backend accepts byte increments; the GUI converts them to percentages.
This also works for a transfer of exactly 100 bytes, which must not be mistaken
for direct percentage updates. Existing RSW/kernel progress protocols retain
their own adapters.

The GUI remains responsible for dialogs, notifications and worker signals. It
permits one ECU operation at a time so workers cannot close or reconfigure each
other's connection. It does not import application helpers from `gkflasher.py`.
The CLI owns argument parsing and prompts, exits successfully after offline
checksum operations, and returns failure for operation errors after cleanup.

## Verification

From the repository root:

```powershell
python -X utf8 -B -m unittest discover -s tests
```

Tests cover independent checksum fixtures, stale previews and failed saves,
gkbus packet transcripts, shared SIMK programming sequences, protected flags,
partial-page reads, cleanup and exit codes, Qt workflows, RAM restoration and
reboot compatibility checks. They run without connected hardware. Protocol
tests complement bench validation; they do not establish compatibility with
additional firmware or replace verification of a physical flash/readback cycle.
