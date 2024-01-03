import sys
from PyQt5 import QtWidgets, uic
from PyQt5.QtWidgets import QFileDialog
from PyQt5.QtCore import QThreadPool
from pyftdi import ftdi, usbtools
import gkbus, yaml
from gkbus.kwp.commands import *
from gkbus.kwp.enums import *
from gkbus.kwp import KWPNegativeResponseException
from flasher.ecu import enable_security_access, fetch_ecu_identification, identify_ecu, ECUIdentificationException, ECU
from flasher.memory import read_memory, write_memory
from flasher.checksum import *

class Progress(object):
	def __init__ (self, progress_bar, max_value: int):
		self.progress_bar = progress_bar
		self.progress_bar.setMaximum(max_value)
		self.progress_bar.setValue(0)

	def __call__ (self, value: int):
		self.progress_bar.setValue(self.progress_bar.value()+value)

	def title (self, title: str):
		pass

class Ui(QtWidgets.QMainWindow):
	def __init__(self):
		super(Ui, self).__init__()
		self.load_ui()

	def load_ui(self):
		uic.loadUi('flasher/gkflasher.ui', self)
		self.thread_manager = QThreadPool()
		self.show()
		
		self.detect_interfaces()
		self.add_listeners()

	def add_listeners (self):
		self.readCalibrationZone.clicked.connect(self.handler_read_calibration_zone)
		self.readProgramZone.clicked.connect(self.handler_read_program_zone)
		self.readFull.clicked.connect(self.handler_full_read)
		self.displayECUID.clicked.connect(self.handler_display_ecu_identification)
		self.readingFileBtn.clicked.connect(self.handler_select_file_reading)
		self.flashingFileBtn.clicked.connect(self.handler_select_file_flashing)
		self.checksumFileBtn.clicked.connect(self.handler_select_file_checksum)
		self.checksumCorrectBtn.clicked.connect(self.handler_checksum_correct)
		self.flashingCalibrationBtn.clicked.connect(self.handler_flash_calibration)
		self.flashingProgramBtn.clicked.connect(self.handler_flash_program)
		self.flashingFullBtn.clicked.connect(self.handler_flash_full)

	def handler_select_file_reading (self):
		filename = QFileDialog().getSaveFileName()[0]
		self.readingFileInput.setText(filename)

	def handler_select_file_flashing (self):
		filename = QFileDialog().getOpenFileName()[0]
		self.flashingFileInput.setText(filename)

	def handler_select_file_checksum (self):
		filename = QFileDialog().getOpenFileName()[0]
		self.checksumFileInput.setText(filename)

	def log (self, text):
		self.logOutput.append(text)

	def detect_interfaces(self):
		ftdi_ins = ftdi.Ftdi()
		devices = ftdi_ins.list_devices()
		for device_str in usbtools.UsbTools.build_dev_strings('ftdi', ftdi_ins.VENDOR_IDS, ftdi_ins.PRODUCT_IDS, devices):
			self.interfacesBox.addItem(' '.join(device_str), device_str[0])

	def get_interface_url (self):
		return self.interfacesBox.currentData()

	def progress_callback (self, value):
		self.progressBar.setValue(value)

	def gui_choose_ecu (self):
		self.log('Please use CLI!')

	def initialize_ecu (self, interface_url: str):
		self.log('[*] Initializing interface ' + self.get_interface_url())
		config = yaml.safe_load(open('gkflasher.yml'))
		del config['kline']['interface']
		bus = gkbus.Bus('kline', interface=interface_url, **config['kline'])

		try:
			bus.execute(StopDiagnosticSession())
			bus.execute(StopCommunication())
		except (KWPNegativeResponseException, gkbus.GKBusTimeoutException):
			pass

		bus.init(StartCommunication())

		self.log('[*] Trying to start diagnostic session')
		bus.execute(StartDiagnosticSession(DiagnosticSession.FLASH_REPROGRAMMING))
		bus.set_timeout(12)

		self.log('[*] Set timing parameters to maximum')
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
			self.log('[!] Not supported on this ECU!')

		self.log('[*] Security Access')
		enable_security_access(bus)

		self.log('[*] Trying to identify ECU automatically.. ')
	
		try:
			ecu = identify_ecu(bus)
		except ECUIdentificationException:
			ecu = ECU(**self.gui_choose_ecu()['ecu'])
			ecu.set_bus(bus)

		self.log('[*] Found! {}'.format(ecu.get_name()))
		return ecu

	def gui_read_eeprom (self, ecu, eeprom_size, address_start=0x000000, address_stop=None, output_filename=None):
		if (address_stop == None):
			address_stop = eeprom_size

		self.log('[*] Reading from {} to {}'.format(hex(address_start), hex(address_stop)))

		requested_size = address_stop-address_start
		eeprom = [0xFF]*eeprom_size

		fetched = read_memory(ecu, address_start=address_start, address_stop=address_stop, progress_callback=Progress(self.progressBar, requested_size))

		eeprom_start = ecu.calculate_bin_offset(address_start)
		eeprom_end = eeprom_start + len(fetched)
		eeprom[eeprom_start:eeprom_end] = fetched

		if (output_filename == None):
			try:
				calibration = ecu.get_calibration()
				description = ecu.get_calibration_description()
				hw_rev_c = ''.join([chr(x) for x in ecu.bus.execute(ReadEcuIdentification(0x8c)).get_data()[1:]])
				hw_rev_d = ''.join([chr(x) for x in ecu.bus.execute(ReadEcuIdentification(0x8d)).get_data()[1:]])
				output_filename = "{}_{}_{}_{}_{}.bin".format(description, calibration, hw_rev_c, hw_rev_d, date.today())
			except: # dirty
				output_filename = "output_{}_to_{}.bin".format(hex(address_start), hex(address_stop))
		
		with open(output_filename, "wb") as file:
			file.write(bytes(eeprom))

		self.log('[*] saved to {}'.format(output_filename))

	def gui_flash_eeprom (self, ecu, input_filename, flash_calibration=True, flash_program=True):
		self.log('[*] Loading up {}'.format(input_filename))

		with open(input_filename, 'rb') as file:
			eeprom = file.read()

		self.log('[*] Loaded {} bytes'.format(len(eeprom)))

		if flash_program:
			self.log('[*] start routine 0x00 (erase program code section)')
			ecu.bus.execute(StartRoutineByLocalIdentifier(0x00))

			flash_start = 0x8A0010
			flash_size = 0x05FFF0
			payload_start = 0x020010
			payload_stop = payload_start+flash_size
			payload = eeprom[payload_start:payload_stop]

			write_memory(ecu, payload, flash_start, flash_size, progress_callback=Progress(self.progressBar, flash_size))

		if flash_calibration:
			self.log('[*] start routine 0x01 (erase calibration section)')
			ecu.bus.execute(StartRoutineByLocalIdentifier(0x01))

			flash_start = ecu.calculate_memory_write_offset(0x090000)
			flash_size = ecu.get_calibration_size_bytes()
			payload_start = ecu.calculate_bin_offset(0x090000)
			payload_stop = payload_start + flash_size
			payload = eeprom[payload_start:payload_stop]

			write_memory(ecu, payload, flash_start, flash_size, progress_callback=Progress(self.progressBar, flash_size))

		ecu.bus.set_timeout(300)
		self.log('[*] start routine 0x02')
		ecu.bus.execute(StartRoutineByLocalIdentifier(0x02)).get_data()
		ecu.bus.set_timeout(12)

		self.log('[*] ecu reset')
		ecu.bus.execute(ECUReset(ResetMode.POWER_ON_RESET)).get_data()

	def handler_read_calibration_zone (self):
		self.thread_manager.start(self.read_calibration_zone)

	def read_calibration_zone (self):
		ecu = self.initialize_ecu(self.get_interface_url())
		eeprom_size = ecu.get_eeprom_size_bytes()
		if (self.readingFileInput.text() == ''):
			output_filename = None
		else:
			output_filename = self.readingFileInput.text()

		self.gui_read_eeprom(ecu, eeprom_size, address_start=0x090000, address_stop=0x090000+ecu.get_calibration_size_bytes(), output_filename=output_filename)

	def handler_read_program_zone (self):
		self.thread_manager.start(self.read_program_zone)

	def read_program_zone (self):
		pass

	def handler_full_read (self):
		self.thread_manager.start(self.full_read)

	def full_read (self):
		pass

	def handler_display_ecu_identification (self):
		self.thread_manager.start(self.display_ecu_identification)

	def display_ecu_identification (self):
		ecu = self.initialize_ecu(self.get_interface_url())


		for parameter_key, parameter in fetch_ecu_identification(ecu.bus).items():
			value_hex = ' '.join([hex(x) for x in parameter['value']])
			value_ascii = ''.join([chr(x) for x in parameter['value']])

			self.log('')
			self.log('    [*] [{}] {}:'.format(hex(parameter_key), parameter['name']))
			self.log('            [HEX]: {}'.format(value_hex))
			self.log('            [ASCII]: {}'.format(value_ascii))

	def handler_checksum_correct (self):
		self.thread_manager.start(self.correct_checksum)

	def correct_checksum (self):
		filename = self.checksumFileInput.text()
		self.log('[*] Reading {}'.format(filename))

		with open(filename, 'rb') as file:
			payload = file.read()

		self.log('Trying to detect type.. ')
		name, flag_address, offset_address, init_address, cks_address, bin_offset = detect_offsets(payload)
		self.log(name)

		self.log('[*] Trying to find addresses of Zone1.. ')
		zone1_start_offset = cks_address+0x04
		zone1_start = concat_3_bytes(read_and_reverse(payload, zone1_start_offset, 3)) + bin_offset

		zone1_stop_offset = cks_address+0x08
		zone1_stop = concat_3_bytes(read_and_reverse(payload, zone1_stop_offset, 3)) + bin_offset + 1
		self.log('{} - {}'.format(hex(zone1_start), hex(zone1_stop)))

		self.log('[*] Trying to find initial value.. ')
		initial_value_bytes = read_and_reverse(payload, init_address, 2)
		initial_value = (initial_value_bytes[0]<< 8) | initial_value_bytes[1]
		self.log(hex(initial_value))

		self.log('[*] checksum of zone1: ')
		zone1_cks = checksum(payload, zone1_start, zone1_stop, initial_value)
		self.log(hex(zone1_cks))

		self.log('[*] Trying to find addresses of Zone2.. ')
		zone2_start_offset = cks_address+0xC
		zone2_start = concat_3_bytes(read_and_reverse(payload, zone2_start_offset, 3)) + bin_offset

		zone2_stop_offset = cks_address+0x10
		zone2_stop = concat_3_bytes(read_and_reverse(payload, zone2_stop_offset, 3)) + bin_offset + 1
		self.log('{} - {}'.format(hex(zone2_start), hex(zone2_stop)))

		self.log('[*] checksum of zone2: ')
		zone2_cks = checksum(payload, zone2_start, zone2_stop, zone1_cks)
		self.log(hex(zone2_cks))

		checksum_b1 = (zone2_cks >> 8) & 0xFF
		checksum_b2 = (zone2_cks & 0xFF)
		checksum_reversed = (checksum_b2 << 8) | checksum_b1

		current_checksum = int.from_bytes(payload[cks_address:cks_address+2], "big")

		self.log('[*] OK! Current checksum: {}, new checksum: {}'.format(hex(current_checksum), hex(checksum_reversed)))

		self.log('[*] Saving to {}'.format(filename))
		with open(filename, 'rb+') as file:
			file.seek(cks_address)
			file.write(checksum_reversed.to_bytes(2, "big"))
		self.log('[*] Done!')

	def handler_flash_calibration (self):
		self.thread_manager.start(self.flash_calibration)

	def flash_calibration (self):
		ecu = self.initialize_ecu(self.get_interface_url())
		filename = self.flashingFileInput.text()
		self.gui_flash_eeprom(ecu, input_filename=filename, flash_calibration=True, flash_program=False)

	def handler_flash_program (self):
		self.thread_manager.start(self.flash_program)

	def flash_program (self):
		ecu = self.initialize_ecu(self.get_interface_url())
		filename = self.flashingFileInput.text()
		self.gui_flash_eeprom(ecu, input_filename=filename, flash_calibration=False, flash_program=True)

	def handler_flash_full (self):
		self.thread_manager.start(self.flash_full)

	def flash_full (self):
		ecu = self.initialize_ecu(self.get_interface_url())
		filename = self.flashingFileInput.text()
		self.gui_flash_eeprom(ecu, input_filename=filename, flash_calibration=True, flash_program=True)

if __name__ == "__main__":
	app = QtWidgets.QApplication(sys.argv)
	window = Ui()
	sys.exit(app.exec_())