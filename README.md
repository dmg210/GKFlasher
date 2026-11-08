# GKFlasher

CLI flashing tool for SIMK41/SIMK43/SIM2K based vehicles. This project is a result of research gathered by black-box reverse engineering.

It can read & write ecu calibration data / program code, correct EEPROM checksums, clear adaptive values and program the immobilizer. It also provides BSL support for your ECU ([docs/bsl.md](docs/bsl.md)).

This project is supported by [OpenGK.org](https://opengk.org/)

![GUI interface](assets/gkflasher_gui.png)
![Reading over CANbus](assets/gkflasher_canbus_read.png)

## Installation 

We have precompiled MSI install packages available from the GitHub releases page.

Alternatively:

Clone the repository

`git clone https://github.com/Dante383/GKFlasher`

Install Python 3.10 for your specific operating system
https://www.python.org/downloads/release/python-31011/

Install required packages

`python3 -m pip install -r requirements.txt`

Confirm that no errors ocurred

Running the command `pip list` should show the following packages
-about-time
-alive-progress
-crcmod
-gkbus
-grapheme
-pyftdi
-PyQt5
-PyQt5-Qt5
-PyQt5-sip
-pyserial
-pyusb
-PyYAML
-setuptools
-python-can

## Usage 

Connect your K-line or CANbus adapter to your computer and the vehicle (or ECU for bench setup).
Pinouts for the Tiburon can be found on https://opengk.org. 

### GUI

Launch `python3 gui.py` 


### CLI

Launch `python3 gkflasher.py --protocol {canbus/kline} --interface {can0//dev/ttyUSB0}`. If it detects EEPROM size and calibration - all is good, you can proceed! 

### Reading 

Add `--read` to the parameters. By default the output
will be saved to `output_{address start}_to_{address stop}.bin`. You can use `--output {filename}` to override that

You can use `--address_start` and `--address_stop` to only read a certain portion.

Be aware that GKFlasher will always pad the output with 0xFF's to match the EEPROM size. For example, reading 16384 bytes from 0x090000 to 0x094000 (calibration zone) on 
an 8mbit EEPROM will still result in a 1mb output file. 

### Flashing 

Add `--flash {filename}` to the parameters. GKFlasher will attempt to detect current ECU calibration version 
and the calibration version of the file you're trying to flash before asking you for confirmation.

You don't need to flash the whole bin at once. You can also use `--flash-calibration {filename}` and `--flash-program {filename}`

You can use `--address_start` and `--address_stop` to only overwrite a certain portion. Be aware that input file offsets must match with intended EEPROM offset. 
For example, if you want to flash only the calibration zone (0x090000 - 0x094000 on 8mbit eeprom) the calibration zone must be located at 0x090000 - 0x094000 in the input file.
This behaviour is followed by default by GKFlasher's --read command.

### Parameters 

`-c --config {filename}` - Load the config file (default: gkflasher.yml). You could use this for example to prepare different configurations for different vehicles you're working on.

`-p --protocol {protocol}` - Currently supported: `canbus` and `kline`

`-b --baudrate {baudrate}`

`--desired-baudrate {baudrate identifier}` - See ecu_definitions.py for presets.
Selector `0x06` sends a custom baudrate supplied by `--session-baudrate`.

`--session-baudrate {baudrate}` - Override the physical K-Line speed after selecting a
session with `--desired-baudrate`. The selector sent to the ECU is unchanged.
With selector `0x06`, this value is also sent to the ECU as three big-endian bytes.

`--kline-p4-min {milliseconds}` - Set the gap between request bytes (0 inclusive to 18 ms exclusive).
Positive values enable echo-paced serial transmission with an 18 ms byte-gap guard,
leaving margin below the tested ECU's 22 ms receive deadline. Startup uses contiguous
frames before enabling pacing at the selected session speed. In this mode, lost KWP
memory-read responses get up to three attempts with a 250 ms response wait per frame
portion, instead of the normal long timeout. Writes and programming commands are never
automatically replayed after a response timeout. These are per-connection I/O settings;
the installed FTDI driver and its persistent settings are not changed.
On serial adapters, a nonzero value waits for each byte's echo before the next gap
and byte. This requires the companion gkbus serial echo-pacing change. Omit the option
to keep the existing timing. These options apply to normal K-Line diagnostics, not BSL or MTOS.

For an experimental calibration read with selector `0x05`, a 107143-baud interface,
and echo pacing:

```powershell
python gkflasher.py --protocol kline --interface COM69 --desired-baudrate 0x05 --session-baudrate 107143 --kline-p4-min 0.2 --read-calibration
```

On the CA663057/COM69 bench, guarded pacing and bounded read recovery completed
repeated verified 64 KiB calibration reads at approximately 3 kB/s. Recovery handles
occasional lost requests; this is not a guarantee of stall-free transmission on every setup.

To test the custom selector at the previously accepted 32609-baud request:

```powershell
python gkflasher.py --protocol kline --interface COM69 --desired-baudrate 0x06 --session-baudrate 32609 --read-calibration
```

The wire request is `10 85 06 00 7F 61`. The generic option accepts a positive
24-bit rate; actual ECU support varies. CA663057 accepted this request but rejected
an explicit 125000-baud request with NRC `0x22`. Its custom-rate parser has limitations;
an accepted baud request does not guarantee a timeout-free read. `0x06` is currently
a CLI option; it is not a fixed-rate entry in the GUI dropdown.

`-i --interface {interface}` - for example `/dev/ttyUSB0` or `COM3` (K-Line), `can0` (SocketCAN), `pcan:PCAN_USBBUS1` (python-can interface:channel) or `j2534:openport` (J2534 adapter, K-Line and CAN; `j2534` for the first installed one). If the interface isn't found, GKFlasher lists the available ones to choose from

`-r --read`

`--read-calibration` - Read just the calibration zone. You can always use `--address-start` and `--address-stop` manually - this just adjusts the offset based on the ECU for you

`--read-program` - Read just the program zone.

`--id` - display ECU identification parameters (KWP service 0x1A)

`--correct-checksum {filename}`

`--clear-adaptive-values`

`-o --output {filename}` - Filename to save the EEPROM dump

`-f --flash {input filename}`

`--flash-calibration {input filename}`

`--flash-program {input filename}`

`-s --address_start {offset}` - Offset to start reading/flashing from 

`-e --address_stop {offset}` - Offset to stop reading/flashing at

`--bin-to-sie {input filename}` - Convert BIN to SIE for (Chip-off) Flashing

`--sie-to-bin {input filename}` - Convert SIE to BIN after (Chip-off) Flashing

`--bsl` - Bootstrap loader, with the ECU in boot mode: read/write the whole external flash (boot sectors included) or read the internal ROM, on the K-line interface. See [docs/bsl.md](docs/bsl.md). Use with `--bsl-mode {hwinfo,read,readint,write}`, `--bsl-image {file}`, `--bsl-baudrate`, `--bsl-driver {auto,i4,v6}`.

`--mtos` - Mini Test Operating System - upload and execute a small routine in ECU RAM. See [docs/mtos.md](docs/mtos.md). Use with `--mtos-key`, `--mtos-mode {hello,dump,payload,loader,probe,read,read-calibration,fullflash}`, `--mtos-payload {file}`. The experimental `read-calibration` mode uses flow-controlled 120-byte blocks at 750000 baud on the 24 MHz C167 and verifies CRC16; start at 10400 baud.

`--rsw-boot1 {input filename}` - Flash Boot1 using RSW bootstrap

`--rsw-boot2 {input filename}` - Flash Boot2 using RSW bootstrap

`--rsw-asw {input filename}` - Flash ASW using RSW bootstrap

`--rsw-cal {input filename}` - Flash CAL using RSW bootstrap

`--rsw-full {input filename}` - Flash full image set using RSW bootstrap

`--rsw-virginize` - Virginize ECU using RSW bootstrap

`--immo` - Immobilizer functions

`-v --verbose` - Enable debug logging

`-l --logger` - Start KWP2000 Datalogger 

