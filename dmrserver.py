import configparser
import hashlib
import io
import json
import os
import random
import shutil
import socket
import string
import struct
import sys
import threading as th
import traceback
import time
from datetime import datetime

# Version
DMR_VERSION = "v1.0.0 Alpha"

# Path to the resources subdirectory
DMR_RESOURCES_PATH = "resources"

# Default config values
default_host = socket.gethostname()
default_port = 7246
default_server_id =''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(16))
default_server_name = os.getlogin() + " on " + socket.gethostname()
default_server_description = "Join and build your city.\n\nRules:\n- Feed the llamas\n- Balance your budget\n- Do uncle Vinny some favors"

# Config constants
DMR_HOST = None
DMR_PORT = None
DMR_SERVER_ID = None
DMR_SERVER_NAME = None
DMR_SERVER_DESCRIPTION = None

# Hard-coded constants
DMR_SEPARATOR = b"<SEPARATOR>"
DMR_BUFFER_SIZE = 4096
DMR_DELAY = .1

# Methods

def prep():
	"""TODO"""
	create_subdirectories()
	load_config()
	prep_profiles()
	#clear_temp()
	prep_regions() 


def start():
	"""TODO Starts the server.

	Arguments:
		None

	Returns:
		None
	"""

	report("Starting server...")

	report("- creating socket...")
	s = socket.socket()

	report("- binding host and port...")
	s.bind((DMR_HOST, DMR_PORT))

	report("- listening for connections...")
	s.listen(5)

	while (True):

		try:

			c, address = s.accept()
			report("Connection accepted with " + str(address[0]) + ":" + str(address[1]) + ".")

			RequestHandler(c).start()	

		except socket.error as e:

			report(str(e), None, "ERROR")


def get_dmr_path(filename):
	"""TODO Gives the path of a given file in the DMR "resources" subdirectory

	Arguments:
		filename (str)

	Returns:
		TODO type: the path to the given file
	"""
	return os.path.join(DMR_RESOURCES_PATH, filename)


def md5(filename):
	"""TODO Creates the hashcode for a given file.

	Arguments:
		filename (str)

	Returns:
		TODO type: hashcode
	"""
	hash_md5 = hashlib.md5()
	with open(filename, "rb") as f:
		for chunk in iter(lambda: f.read(4096), b""):
			hash_md5.update(chunk)
	return hash_md5.hexdigest()


def string_md5(text):
	"""TODO"""
	return hashlib.md5(text.encode()).hexdigest()


def file_md5(file):
	"""TODO"""
	hash_md5 = hashlib.md5()
	for chunk in iter(lambda: file.read(4096), b""):
		hash_md5.update(chunk)
	return hash_md5.hexdigest()


def create_subdirectories():
	"""TODO Creates the required subdirectories if they do not yet exist.

	Arguments:
		None

	Returns:
		None
	"""

	report("Creating subdirectories...")

	directories = ["DMRBackups", "DMRProfiles", "DMRTemp", "Plugins", "Regions"]

	for directory in directories:
		new_directory = os.path.join("_DMR", directory)
		if not os.path.exists(new_directory):
			try:
				os.makedirs(new_directory)
				if (directory == "Plugins" or "Regions"):
					shutil.unpack_archive(get_dmr_path(directory + ".zip"), new_directory)
			except:
				report("Failed to create " + directory + " subdirectory.", None, "WARNING")
				report('(this may have been printed by error, check your "_DMR" subdirectory)', None, "WARNING")


def load_config():
	"""TODO Loads the config file from the resources subdirectory or creates it if it does not yet exist.

	Arguments:
		None

	Returns:
		None
	"""

	global DMR_HOST
	global DMR_PORT
	global DMR_SERVER_ID
	global DMR_SERVER_NAME
	global DMR_SERVER_DESCRIPTION

	report("Loading config...")

	config_path = os.path.join("_DMR", "serverconfig.ini")

	try:

		config = configparser.RawConfigParser()
		config.read(config_path)

		DMR_HOST = config.get('server', "host")
		DMR_PORT = int(config.get('server', 'port'))
		DMR_SERVER_ID = config.get('server', "server_id")
		DMR_SERVER_NAME = config.get('server', "server_name")
		DMR_SERVER_DESCRIPTION = config.get('server', "server_description")

	except:

		config.remove_section('server')
		config.add_section('server')
		config.set('server', 'host', default_host)
		config.set('server', 'port', default_port)
		config.set('server', 'server_id', default_server_id)
		config.set('server', 'server_name', default_server_name)
		config.set('server', 'server_description', default_server_description)
		
		with open(config_path, 'wt') as config_file:
			config.write(config_file)

		DMR_HOST = default_host
		DMR_PORT = default_port
		DMR_SERVER_ID = default_server_id
		DMR_SERVER_NAME = default_server_name
		DMR_SERVER_DESCRIPTION = default_server_description


def clear_temp():
	"""TODO"""
	report("Clearing temporary files...")
	purge_directory(os.path.join("_DMR", "DMRTemp"))


def prep_profiles():
	"""TODO"""

	report("Preparing profiles...")

	# Profiles directory
	profiles_directory = os.path.join("_DMR", "DMRProfiles")

	# Users database
	filename = os.path.join(profiles_directory, "users.json")
	if (not os.path.exists(filename)):
		create_empty_json(filename)

	# Claims directory
	claims_directory = os.path.join(profiles_directory, "regions")
	if (not os.path.exists(claims_directory)):
		os.makedirs(claims_directory)

	# Get region directory names
	regions = []
	regions_directory = os.path.join("_DMR", "Regions")
	items = os.listdir(regions_directory)
	for item in items:
		path = os.path.join(regions_directory, item)
		if (not os.path.isfile(path)):
			regions.append(item)

	# Create databases for each region
	for region in regions:
		
		# Get database
		filename = os.path.join(claims_directory, region + ".json")
		data = None
		try:
			data = load_json(filename)
		except:
			data = dict()

		# Region directory
		region_directory = os.path.join(regions_directory, region)
		
		# Get savegame paths
		savegame_paths = []
		items = os.listdir(region_directory)
		for item in items:
			path = os.path.join(region_directory, item)
			if (os.path.isfile(path) and path[-4:] == ".sc4"):
				savegame_paths.append(path)

		# Open savegames as DBPF objects
		savegames = []
		for savegame_path in savegame_paths:
			savegames.append(DBPF(savegame_path))

		# Get the region subfile of each DBPF object and update the database
		for savegame in savegames:

			# Get region subfile
			savegame.get_SC4ReadRegionalCity()

			# Get values from region subfile
			savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
			savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
			savegameSize = savegame.SC4ReadRegionalCity["citySizeX"]

			# Get md5 hashcode of date subfile
			savegame_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))

			# Get dictionary for savegame data
			coords = str(savegameX) + " " + str(savegameY)
			entry = data.get(coords, dict())
			if (entry == None):
				entry = dict()
			data[coords] = entry

			# Set entry values
			set_savegame_data(entry, savegame)

			# Reserve tiles which the savegame occupies
			for offsetX in range(savegameSize):
				x = savegameX + offsetX
				for offsetY in range(savegameSize):
					y = savegameY + offsetY
					data.setdefault(str(x) + " " + str(y), None)

		update_json(filename, data)

	# Profiles manager
	global dmr_profiles_manager
	dmr_profiles_manager = ProfilesManager()
	dmr_profiles_manager.start()


def create_empty_json(filename):
	"""TODO"""
	with open(filename, 'w') as file:
		data = dict()
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def load_json(filename):
	"""TODO"""
	with open(filename, 'r') as file:
		return json.load(file)


def set_savegame_data(entry, savegame):
	"""TODO entry values"""

	# No overwrite
	entry.setdefault("filename", os.path.basename(os.path.normpath(savegame.filename)))
	entry.setdefault("owner", None)
	entry.setdefault("modified", None)

	# Overwrite
	entry["size"] = savegame.SC4ReadRegionalCity["citySizeX"]
	entry["date_subfile_hash"] = file_md5(savegame.decompress_subfile("2990c1e5"))
	entry["gamemode"] = savegame.SC4ReadRegionalCity["modeFlag"]
	entry["difficulty"] = savegame.SC4ReadRegionalCity["starCount"]
	entry["mayor_rating"] = savegame.SC4ReadRegionalCity["mayorRating"]
	entry["residential_population"] = savegame.SC4ReadRegionalCity["residentialPopulation"]
	entry["commercial_population"] = savegame.SC4ReadRegionalCity["commercialPopulation"]
	entry["industrial_population"] = savegame.SC4ReadRegionalCity["industrialPopulation"]
	entry["population"] = entry["residential_population"] + entry["commercial_population"] + entry["industrial_population"]
	entry["population_density"] = round(entry["population"] / (entry["size"] * entry["size"]))
	entry["residential_population_density"] = round(entry["residential_population"] / (entry["size"] * entry["size"]))


def update_json(filename, data):
	"""TODO"""
	with open(filename, 'w') as file:
		file.seek(0)
		json.dump(data, file, indent=4)
		file.truncate()


def package_plugins_and_regions():
	"""TODO"""

	report("Packaging plugins and regions...")

	report("- packaging plugins...")
	package("plugins")

	report("- packaging regions...")
	package("regions")

	# Regions manager
	global dmr_regions_manager
	dmr_regions_manager = RegionsManager()
	dmr_regions_manager.start()


def prep_regions():
	"""TODO"""

	report("Preparing regions...")

	export("regions")

	# Regions manager
	global dmr_regions_manager
	dmr_regions_manager = RegionsManager()
	dmr_regions_manager.start()


def package(type):
	"""TODO"""

	directory = None
	if (type == "plugins"):
		directory = "Plugins"
	elif (type == "regions"):
		directory = "Regions"

	target = os.path.join("_DMR", directory)
	destination = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Outbound", directory)))

	if (os.path.exists(destination)):
		os.remove(destination)

	shutil.make_archive(destination, "zip", target)


def export(type):
	"""TODO"""

	# Select directory name from input
	directory = None
	if (type == "plugins"):
		directory = "Plugins"
	elif (type == "regions"):
		directory = "Regions"

	# Set target and destination directories
	target = os.path.join("_DMR", directory)
	destination = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Outbound", directory)))

	# Delete destination directory if it exists 
	if (os.path.exists(destination)):
		shutil.rmtree(destination)
	
	# Create the parent directories if they do not yet exist
	#if (not os.path.exists(destination)):
	#	os.makedirs(destination)
	
	# Copy recursively
	shutil.copytree(target, destination)	


def purge_directory(directory):
	"""TODO

	Arguments:
		TODO

	Returns:
		TODO
	"""
	for filename in os.listdir(directory):
		file_path = os.path.join(directory, filename)
		try:
			if os.path.isfile(file_path) or os.path.islink(file_path):
				os.unlink(file_path)
			elif os.path.isdir(file_path):
				shutil.rmtree(file_path)
		except PermissionError as e:
			raise CustomException('Failed to delete "' + file_path + '" because the file is being used by another process.') #\n\n' + str(e)


def send_tree(c, rootpath):
	"""TODO"""

	# Loop through all files in path and append them to a list
	fullpaths = []
	for path, directories, files in os.walk(rootpath):
		for file in files:
			fullpaths.append(os.path.join(path, file))

	# Send file count
	c.send(str(len(fullpaths)).encode())

	# Loop through the file list and send each one to the client
	for fullpath in fullpaths:

		# Separator
		c.recv(DMR_BUFFER_SIZE)

		# Get relative path to file 
		relpath = os.path.relpath(fullpath, rootpath)

		# Send hashcode
		c.send(md5(fullpath).encode())

		# Separator
		c.recv(DMR_BUFFER_SIZE)

		# Send filesize
		c.send(str(os.path.getsize(fullpath)).encode())

		# Separator
		c.recv(DMR_BUFFER_SIZE)

		# Send relative path
		c.send(relpath.encode())

		# Send the file if not cached
		if (c.recv(DMR_BUFFER_SIZE).decode() != "cached"):
			with open(fullpath, "rb") as file:
				while True:
					bytes_read = file.read(DMR_BUFFER_SIZE)
					if not bytes_read:
						break
					c.sendall(bytes_read)


def send_or_cached(c, filename):
	"""TODO"""
	c.send(md5(filename).encode())
	if (c.recv(DMR_BUFFER_SIZE).decode() == "not cached"):
		send_file(c, filename)
	else:
		c.close()


def send_file(c, filename):
	"""TODO"""

	report("Sending file " + filename + "...")

	filesize = os.path.getsize(filename)
	c.send(str(filesize).encode())

	with open(filename, "rb") as f:
		while True:
			bytes_read = f.read(DMR_BUFFER_SIZE)
			if not bytes_read:
				break
			c.sendall(bytes_read)


def receive_file(c, filename):
	"""TODO"""

	filesize = int(c.recv(DMR_BUFFER_SIZE).decode())

	c.send(DMR_SEPARATOR)

	report("Receiving " + str(filesize) + " bytes...")
	report("writing to " + filename)

	if (os.path.exists(filename)):
		os.remove(filename)

	filesize_read = 0
	with open(filename, "wb") as f:
		while (filesize_read < filesize):
			bytes_read = c.recv(DMR_BUFFER_SIZE)
			if not bytes_read:    
				break
			f.write(bytes_read)
			filesize_read += len(bytes_read)
			#print('Downloading "' + filename + '" (' + str(filesize_read) + " / " + str(filesize) + " bytes)...", int(filesize_read), int(filesize)) #os.path.basename(os.path.normpath(filename))


def xor(conditionA, conditionB):
	return (conditionA or conditionB) and (not (conditionA and conditionB))


def report(message, object=None, type="INFO", ): #TODO do this in the logger to make sure output prints correctly
	"""TODO"""
	color = '\033[94m '
	output = datetime.now().strftime("[%H:%M:%S] [DMR")
	if (object != None):
		output += "/" + object.__class__.__name__
		color = '\033[0m '
	output+= "] [" + type + "] " + message
	if (type=="WARNING"):
		color = '\033[93m '
	elif (type == "ERROR" or type == "FATAL"):
		color = '\033[91m '
	print(color + output)


# Objects

class DBPF():
	"""TODO include credits to original php file"""


	def __init__(self, filename, offset=0):
		"""TODO"""

		self.filename = filename
		self.offset = offset

		self.NONSENSE_BYTE_OFFSET = 9

		# Try opening the file to read bytes
		try:
			self.file = open(self.filename, 'rb')
		except Exception as e:
			raise e #TODO

		# Advance to offset
		start = self.offset
		if (self.offset > 0):
			self.file.seek(self.offset)

		# Verify that the file is a DBPF
		test = self.file.read(4)
		if (test != b"DBPF"):
			return #TODO raise exception

		# Read the header
		self.majorVersion = self.read_UL4()
		self.minorVersion = self.read_UL4()
		self.reserved = self.file.read(12)
		self.dateCreated = self.read_UL4()
		self.dateModified = self.read_UL4()
		self.indexMajorVersion = self.read_UL4()
		self.indexCount = self.read_UL4()
		self.indexOffset = self.read_UL4()
		self.indexSize = self.read_UL4()
		self.holesCount = self.read_UL4()
		self.holesOffset = self.read_UL4()
		self.holesSize = self.read_UL4()
		self.indexMinorVersion = self.read_UL4() - 1
		self.reserved2 = self.file.read(32)
		self.header_end = self.file.tell()

		# Seek to index table
		self.file.seek(offset + self.indexOffset)

		# Read index table
		self.indexData = []
		for index in range(0, self.indexCount):
			self.indexData.append(dict())
			self.indexData[index]['typeID'] = self.read_ID()
			self.indexData[index]['groupID'] = self.read_ID()
			self.indexData[index]['instanceID'] = self.read_ID()
			if ((self.indexMajorVersion == "7") and (self.indexMinorVersion == "1")):
				self.indexData[index]['instanceID2'] = self.read_ID()
			self.indexData[index]['offset'] = self.read_UL4()
			self.indexData[index]['filesize'] = self.read_UL4()
			self.indexData[index]['compressed'] = False
			self.indexData[index]['truesize'] = 0


	def decompress(self, length):

		buf = ""
		answer = bytes()
		answerlen = 0
		numplain = ""
		numcopy = ""
		offset = ""

		while (length > 0):
			try:
				cc = self.read_UL1(self.file)
			except Exception as e:
				report(str(e), self, "ERROR")
				break
			length -= 1
			#print("Control char is " + str(cc) + ", length remaining is " + str(length) + ".\n")
			if (cc >= 252): #0xFC
				numplain = cc & 3 #0x03
				if (numplain > length):
					numplain = length
				numcopy = 0
				offset = 0
			elif (cc >= 224): #0xE0
				numplain = (cc - 223) << 2 #223 = 0xdf
				numcopy = 0
				offset = 0
			elif (cc >= 192): #0xC0
				length -= 3
				byte1 = self.read_UL1(self.file)
				byte2 = self.read_UL1(self.file)
				byte3 = self.read_UL1(self.file)
				numplain = cc & 3 #0x03
				numcopy = ((cc & 12) << 6) + 5 + byte3 #12 = 0x0c
				offset = ((cc & 16) << 12) + (byte1 << 8) + byte2 #16 = 0x10
			elif (cc >= 128): #0x80
				length -= 2
				byte1 = self.read_UL1(self.file)
				byte2 = self.read_UL1(self.file)
				numplain = (byte1 & 192) >> 6 #192 = 0xc0
				numcopy = (cc & 63) + 4 #63 = 0x3f
				offset = ((byte1 & 63) << 8) + byte2 #63 = 0x3f
			else:
				length -= 1
				byte1 = self.read_UL1(self.file)
				numplain = (cc & 3) #3 = 0x03
				numcopy = ((cc & 28) >> 2) + 3 #28 = 0x1c
				offset = ((cc & 96) << 3) + byte1 #96 = 0x60
			length -= numplain

			# This section basically copies the parts of the string to the end of the buffer:
			if (numplain > 0):
				buf = self.file.read(numplain)
				answer = answer + buf
			fromoffset = len(answer) - (offset + 1)  # 0 == last char
			for index in range(numcopy):
				#print(str(answer))
				#print(str(cc))
				#print(str(offset))
				#print(str(fromoffset))
				#TODO remove try and except block. decompression algorithm breaks with a control char of 206. the offset becomes larger than the length of the answer, causing a negative fromindex and an indexing error. for now it does not seem to affect city coordinates
				try:
					answer = answer + (answer[fromoffset + index]).to_bytes(1, 'little') #substr(fromoffset + index, 1)
				except Exception as e:
					report(str(e), self, "ERROR")
					return io.BytesIO(answer)
			answerlen += numplain
			answerlen += numcopy

		return io.BytesIO(answer)


	def read_UL1(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<B', file.read(1))[0]


	def read_UL2(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<H', file.read(2))[0]
	
	
	def read_UL4(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return struct.unpack('<L', file.read(4))[0]


	def read_ID(self, file=None):
		"""TODO"""
		if (file == None):
			file = self.file
		return file.read(4)[::-1].hex()


	def get_indexData_entry_by_type_ID(self, type_id):
		"""TODO"""
		for entry in self.indexData:
			if (entry['typeID'] == type_id):
				return entry


	def goto_subfile(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		self.file.seek(entry['offset'])
		#print(entry['offset'] + 9)


	def get_subfile_size(self, type_id):
		"""TODO"""
		entry = self.get_indexData_entry_by_type_ID(type_id)
		return entry['filesize']


	#def get_subfile_header(self, type_id):
	#	"""TODO"""
	#	self.goto_subfile(type_id)
	#	return (self.read_UL4(), self.read_ID(), ) #TODO how to read these values?


	def decompress_subfile(self, type_id):
		"""TODO"""
		self.goto_subfile(type_id)
		self.file.read(self.NONSENSE_BYTE_OFFSET)
		return self.decompress(self.get_subfile_size(type_id))


	def get_SC4ReadRegionalCity(self):
		"""TODO"""

		data = self.decompress_subfile("ca027edb")
	
		#print(data.read())
		#data.seek(0)

		self.SC4ReadRegionalCity = dict()

		self.SC4ReadRegionalCity['majorVersion'] = self.read_UL2(data)
		self.SC4ReadRegionalCity['minorVersion'] = self.read_UL2(data)
		
		self.SC4ReadRegionalCity['tileXLocation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['tileYLocation'] = self.read_UL4(data)
		
		self.SC4ReadRegionalCity['citySizeX'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['citySizeY'] = self.read_UL4(data)
		
		self.SC4ReadRegionalCity['residentialPopulation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['commercialPopulation'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['industrialPopulation'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['unknown1'] = data.read(4) #TODO read float

		self.SC4ReadRegionalCity['mayorRating'] = self.read_UL1(data)
		self.SC4ReadRegionalCity['starCount'] = self.read_UL1(data)
		self.SC4ReadRegionalCity['tutorialFlag'] = self.read_UL1(data)

		self.SC4ReadRegionalCity['cityGUID'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['unknown5'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown6'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown7'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown8'] = self.read_UL4(data)
		self.SC4ReadRegionalCity['unknown9'] = self.read_UL4(data)

		self.SC4ReadRegionalCity['modeFlag'] = self.read_UL1(data)

		#TODO keep reading file

		return self.SC4ReadRegionalCity

	
	def get_cSC4Simulator(self):
		"""TODO"""

		data = self.decompress_subfile("2990c1e5")

		print(data.read())
		data.seek(0)

		self.cSC4Simulator = dict()

		#TODO


# Workers

class BackupManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""
		super().__init__(self)
	

	def run(self):
		"""TODO"""
		print("TO IMPLEMENT")


class ProfilesManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""

		super().__init__()
	
		self.filename = os.path.join("_DMR", os.path.join("DMRProfiles", "users.json"))
		self.data = self.load_json(self.filename)


	def run(self):
		"""TODO"""
		report("Monitoring database for changes...", self) #TODO why is the spacing wrong?
		old_data = str(self.data)
		while (True): #TODO pretty dumb way of checking if a dictionary has been modified. also this thread probably needs to stop at some point
			try:
				time.sleep(DMR_DELAY)
				new_data = str(self.data)
				if (old_data != new_data):
					report('Updating "' + self.filename + '"...', self)
					self.update_json(self.filename, self.data)
					report("Done.", self)
				old_data = new_data
			except Exception as e:
				report(str(e), self, "ERROR")


	def load_json(self, filename):
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return dict()

	
	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


class RegionsManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""

		super().__init__()

		self.regions_modified = False
		self.export_regions = False
		self.tasks = []
		self.outputs = dict()
	

	def run(self):
		"""TODO"""
		
		while(True): #TODO end thread

			try:

				# Package regions if requested, otherwise check for new tasks
				if (self.export_regions):

					report("Exporting regions as requested...", self)

					export("regions")

					self.regions_modified = False
					self.export_regions = False

				else:

					# Check for the next task
					if (len(self.tasks) > 0):

						# Get the next task
						task = self.tasks.pop()

						# Read values from tuple
						save_id = task[0]
						user_id = task[1]
						region = task[2]
						savegame = task[3]

						report('Processing task "' + save_id + '"...', self)

						# Another layer of exception handling so that the request handler isn't waiting around in the event of an error
						try:

							# Get values from savegame
							filename = savegame.filename
							savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
							savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
							savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
							savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]

							# Set "coords" variable. Used as a key in the region database and also for the name of the new save file
							coords = str(savegameX) + " " + str(savegameY)

							# Get region database
							data_filename = os.path.join("_DMR", os.path.join("DMRProfiles", os.path.join("regions", region + ".json")))
							data = self.load_json(data_filename)
							
							# Get city entry
							entry = None
							try:
								entry = data[coords]
							except:
								entry = dict()
								data[coords] = entry

							# Filter out cities that don't match the region configuration
							if (entry == None):
								self.outputs[save_id] = "Invalid city location."

							# Filter out cities of the wrong size
							if ("size" in entry.keys()):
								if (savegameSizeX != savegameSizeY or savegameSizeX != entry["size"]):
									self.outputs[save_id] = "Invalid city size."

							# Filter out claims on tiles with unexpired claims of other users
							if ("owner" in entry.keys()):
								owner = entry["owner"]
								if (owner != None and owner != user_id):
									expires = datetime.strptime(entry["modified"], "%Y-%m-%d %H:%M:%S") + datetime.timedelta(days=30) #TODO make the expiry date configurable
									if (expires > datetime.now()):
										self.outputs[save_id] = "City already claimed."

							# Proceed if save push has not been filtered out
							if (not save_id in self.outputs.keys()):

								# Delete previous save file if it exists
								if ("filename" in entry.keys()):
									previous_filename = os.path.join("_DMR", os.path.join("Regions", os.path.join(region, entry["filename"])))
									if (os.path.exists(previous_filename)):
										os.remove(previous_filename)

								# Copy save file from temporary directory to regions directory
								destination = os.path.join("_DMR", os.path.join("Regions", os.path.join(region, coords + ".sc4")))
								if (os.path.exists(destination)):
									os.remove(destination)
								shutil.copy(filename, destination)

								# Set entry values
								entry["filename"] = coords + ".sc4"
								entry["owner"] = user_id
								entry["modified"] = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
								set_savegame_data(entry, savegame)

								# Update database
								self.update_json(data_filename, data)

								# Mark regions as modified
								self.regions_modified = True

								# Report success
								self.outputs[save_id] = "ok"

						except Exception as e:

							# Report an error to the request handler
							self.outputs[save_id] = "Unexpected error."

							# Raise the exception so that it appears in the server's output
							raise e

						report("Done.", self)

					else:
						
						time.sleep(DMR_DELAY)

			except Exception as e:

				report(str(e), self, "ERROR")


	def load_json(self, filename):
		"""TODO"""
		try:
			with open(filename, 'r') as file:
				return json.load(file)
		except:
			return dict()

	
	def update_json(self, filename, data):
		"""TODO"""
		with open(filename, 'w') as file:
			file.seek(0)
			json.dump(data, file, indent=4)
			file.truncate()


class RequestHandler(th.Thread):
	"""TODO"""


	def __init__(self, c):
		"""TODO"""
		super().__init__()
		self.c = c


	def run(self):
		"""TODO"""

		c = self.c

		request = c.recv(DMR_BUFFER_SIZE).decode()

		report("Request: " + request, self)

		if (request== "ping"):
			self.ping(c)
		elif (request == "server_id"):
			self.send_server_id(c)
		elif (request == "server_name"):
			self.send_server_name(c)
		elif (request == "server_description"):
			self.send_server_description(c)
		elif (request == "user_id"):
			self.send_user_id(c)
		elif (request == "salt"):
			self.send_salt(c)
		elif (request == "plugins"):
			self.send_plugins(c)
		elif (request == "regions"):
			self.send_regions(c)
		elif (request == "push_delete"):
			self.delete(c)
		elif (request == "push_save"):
			self.save(c)

		c.close()
	
		#report("- connection closed.", self)

	
	def ping(self, c):
		"""TODO"""
		c.send(b"pong")


	def send_server_id(self, c):
		"""TODO"""
		c.send(DMR_SERVER_ID.encode())


	def send_server_name(self, c):
		"""TODO"""
		c.send(DMR_SERVER_NAME.encode())


	def send_server_description(self, c):
		"""TODO"""
		c.send(DMR_SERVER_DESCRIPTION.encode())

	
	def send_user_id(self, c):
		"""TODO"""
		
		c.send(DMR_SEPARATOR)
		
		hash = c.recv(DMR_BUFFER_SIZE).decode()

		# Get database
		data = dmr_profiles_manager.data

		# Send the user_id that matches the hash
		for user_id in data.keys():
			salt = data[user_id]["salt"]
			if (hashlib.md5((user_id + salt).encode()).hexdigest() == hash):
				c.send(user_id.encode())


	def send_salt(self, c):
		"""TODO"""

		c.send(DMR_SEPARATOR)
		
		user_id = self.receive_user_id(c)

		salt = ''.join(random.SystemRandom().choice(string.ascii_letters + string.digits) for i in range(16))

		# Get database
		data = dmr_profiles_manager.data

		# Get database entry for user
		key = user_id
		entry = data.get(key, dict())
		if (entry == None):
			entry = dict()
		data[key] = entry

		# Set salt in database entry
		entry["salt"] = salt

		# Send salt
		c.send(salt.encode())


	def send_plugins(self, c):
		"""TODO"""

		#filename = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Outbound", "Plugins.zip")))
		#send_or_cached(c, filename)

		send_tree(c, os.path.join("_DMR", "Plugins"))


	def send_regions(self, c):
		"""TODO"""

		if (dmr_regions_manager.regions_modified):
			dmr_regions_manager.export_regions = True
			while (dmr_regions_manager.export_regions):
				time.sleep(DMR_DELAY)

		#filename = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Outbound", "Regions.zip")))
		#send_or_cached(c, filename)

		send_tree(c, os.path.join("_DMR", "DMRTemp", "Outbound", "Regions"))


	def delete(self, c):
		"""TODO"""

		c.send(DMR_SEPARATOR)

		user_id = self.receive_user_id(c)
		c.send(DMR_SEPARATOR)
		region = c.recv(DMR_BUFFER_SIZE).decode()
		c.send(DMR_SEPARATOR)
		city = c.recv(DMR_BUFFER_SIZE).decode()

		c.send(DMR_SEPARATOR) #TODO verify that the user can make the deletion

		#TODO only delete file if user is authorized

		filename = os.path.join("_DMR", os.path.join("Regions", os.path.join(region, city)))

		os.remove(filename)


	def save(self, c):
		"""TODO"""
		
		# Separator
		c.send(DMR_SEPARATOR)

		#TODO receive password if required

		# Receive user id
		user_id = self.receive_user_id(c)
		c.send(DMR_SEPARATOR) #TODO verify real user?

		# Receive file count
		file_count = int(c.recv(DMR_BUFFER_SIZE).decode())
		c.send(DMR_SEPARATOR)

		# Set save id
		save_id = datetime.now().strftime("%Y%m%d%H%M%S") + string_md5(user_id)

		# Receive files
		for count in range(file_count):

			# Receive region name
			region = c.recv(DMR_BUFFER_SIZE).decode()
			c.send(DMR_SEPARATOR)

			# Receive city name
			city = c.recv(DMR_BUFFER_SIZE).decode()
			c.send(DMR_SEPARATOR)

			# Receive file
			path = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Inbound", os.path.join(save_id, region))))
			if (not os.path.exists(path)):
				os.makedirs(path)
			filename = os.path.join(path, str(count) + ".sc4")
			receive_file(c, filename)
			c.send(DMR_SEPARATOR)

		# Separator
		c.recv(DMR_BUFFER_SIZE)

		# Get path to save directory
		path = os.path.join("_DMR", os.path.join("DMRTemp", os.path.join("Inbound", save_id)))

		# Get regions in save directory
		regions = os.listdir(path)

		# Only allow save pushes of one region
		if (len(regions) > 1):
			c.send(b"Too many regions.")
			return		

		# Loop through regions. Should only loop once since save pushes of multiple regions are filtered out.
		for region in regions:

			# Get region path
			region_path = os.path.join(path, region)

			# Create DBPF objects for each file
			savegames = []
			for filename in os.listdir(region_path):
				filename = os.path.join(region_path, filename)
				savegames.append(DBPF(filename))

			# Extract the region subfile from each DBPF
			for savegame in savegames:
				savegame.get_SC4ReadRegionalCity()
			
			# Filter out tiles that do not border every other tile
			report("Savegame filter 1", self)
			new_savegames = []
			for savegame in savegames:
				add = True
				savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
				savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
				savegameSizeX = savegame.SC4ReadRegionalCity["citySizeX"]
				savegameSizeY = savegame.SC4ReadRegionalCity["citySizeY"]
				for neighbor in savegames:
					if (neighbor == savegame):
						continue
					neighborX = neighbor.SC4ReadRegionalCity["tileXLocation"]
					neighborY = neighbor.SC4ReadRegionalCity["tileYLocation"]
					neighborSizeX = neighbor.SC4ReadRegionalCity["citySizeX"]
					neighborSizeY = neighbor.SC4ReadRegionalCity["citySizeY"]
					conditionX1 = (neighborX == savegameX - neighborSizeX)
					conditionX2 = (neighborX == savegameX + savegameSizeX)
					conditionY1 = (neighborY == savegameY - neighborSizeY)
					conditionY2 = (neighborY == savegameY + savegameSizeY)
					conditionX = xor(conditionX1, conditionX2) and ((neighborY + neighborSizeY > savegameY) or (neighborY < savegameY + savegameSizeY))
					conditionY = xor(conditionY1, conditionY2) and ((neighborX + neighborSizeX > savegameX) or (neighborX < savegameX + savegameSizeX))
					condition = xor(conditionX, conditionY)
					if (not condition):
						add = False
				if (add):
					new_savegames.append(savegame)
					report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
				else:
					report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
			savegames = new_savegames

			# Filter out tiles which have identical date subfiles as their previous versions
			if(len(savegames) > 1):
				report("Savegame filter 2", self)
				new_savegames = []
				for savegame in savegames:
					savegameX = savegame.SC4ReadRegionalCity["tileXLocation"]
					savegameY = savegame.SC4ReadRegionalCity["tileYLocation"]
					coords = str(savegameX) + " " + str(savegameY)
					data = load_json(os.path.join("_DMR", os.path.join("DMRProfiles", os.path.join("regions", os.path.join(region + ".json")))))
					if (coords in data.keys()):
						entry = data[coords]
						date_subfile_hash = entry["date_subfile_hash"]
						new_date_subfile_hash = file_md5(savegame.decompress_subfile("2990c1e5"))
						if (date_subfile_hash != new_date_subfile_hash):
							new_savegames.append(savegame)
							report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
						else:
							report("NO (" + str(savegameX) + ", " + str(savegameY) + ")", self)
					else:
						new_savegames.append(savegame)
						report("YES (" + str(savegameX) + ", " + str(savegameY) + ")", self)
				savegames = new_savegames
			else:
				report("Skipping savegame filter 2", self)

			# If one savegame remains, pass it to the regions manager, otherwise report to the client that the save push is invalid
			if (len(savegames) == 1):

				# Get the savegame
				savegame = savegames[0]

				# Send the task to the regions manager
				dmr_regions_manager.tasks.append((save_id, user_id, region, savegame))

				# Wait for the output
				while (not save_id in dmr_regions_manager.outputs.keys()):
					time.sleep(DMR_DELAY)

				# Send the output to the client
				c.send((dmr_regions_manager.outputs[save_id]).encode())

			else:

				# Report to the client that the save push is invalid
				c.send(b"Unpause the game and retry.")

		# Delete temporary files
		shutil.rmtree(path)
		

	def receive_user_id(self, c):
		"""TODO"""
		
		user_id = c.recv(DMR_BUFFER_SIZE).decode()
		
		data = dmr_profiles_manager.data
		
		entry = None
		try:
			entry = data[user_id]
		except:
			entry = dict()
			data[user_id] = entry

		entry.setdefault("IPs", [])
		entry.setdefault("ban", False)
		#entry.setdefault("banIPs", False) #TODO implement

		ip = c.getpeername()[0]
		IPs_entry = entry["IPs"]
		if (not ip in IPs_entry):
			IPs_entry.append(ip)

		if (entry["ban"]):
			return None
		else:
			return user_id


# Logger

class Logger():
	"""TODO"""
	
	def __init__(self):
		"""TODO"""
		self.terminal = sys.stdout
		self.log = "dmrserver-" + datetime.now().strftime("%Y%m%d%H%M%S") + ".log"
   

	def write(self, message):
		"""TODO"""
		self.terminal.write(message)
		with open(self.log, "a") as log:
			log.write(message)
			log.close()  

	def flush(self):
		"""TODO"""
		self.terminal.flush()


# Main Method

def test_DBPF():
	"""TODO"""
	savegame = DBPF("City - Big City Tutorial (2).sc4")
	print(file_md5(savegame.decompress_subfile("2990c1e5")))


def main():
	"""The main method."""

	sys.stdout = Logger()

	report("Server version " + DMR_VERSION)

	try:
		prep()
		start()
	except Exception as e:
		report(str(e), None, "FATAL")
		traceback.print_exc()
	

if __name__ == '__main__':
	main()
	#test_DBPF()