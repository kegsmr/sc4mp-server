import configparser
import hashlib
import os
import random
import shutil
import socket
import string
import sys
import threading as th
import traceback
from datetime import datetime
#import dbpf.dbpf
#import dbpf.tgi
#import dbpf.tgimatch


# Version
DMR_VERSION = "v1.0.0 Alpha"

# Path to the resources subdirectory
dmr_resources_path = "resources"

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


# Methods

def prep():
	"""TODO"""
	create_subdirectories()
	load_config()
	package_plugins_and_regions()


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
	return os.path.join(dmr_resources_path, filename)


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


def package_plugins_and_regions():
	"""TODO"""
	report("Packaging plugins and regions...")
	#print("(this may take several minutes)")
	package("plugins")
	package("regions")


def package(type):
	"""TODO"""

	report("- packaging " + type + "...")

	directory = None
	if (type == "plugins"):
		directory = "Plugins"
	elif (type == "regions"):
		directory = "Regions"

	target = os.path.join("_DMR", directory)
	destination = os.path.join("_DMR", os.path.join("DMRTemp", directory))

	if (os.path.exists(destination)):
		os.remove(destination)

	shutil.make_archive(destination, "zip", target)


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

	c.close()


def receive_file(c, filename):
	"""TODO"""

	filesize = c.recv(DMR_BUFFER_SIZE).decode()

	c.send(b"ok")

	report("Receiving " + filesize + " bytes...")
	report("writing to " + filename)

	if (os.path.exists(filename)):
		os.remove(filename)

	filesize_read = 0
	with open(filename, "wb") as f:
		while True:
			bytes_read = c.recv(DMR_BUFFER_SIZE)
			if not bytes_read:    
				break
			f.write(bytes_read)
			filesize_read += len(bytes_read)
			#print('Downloading "' + filename + '" (' + str(filesize_read) + " / " + str(filesize) + " bytes)...", int(filesize_read), int(filesize)) #os.path.basename(os.path.normpath(filename))


def report(message, object=None, type="INFO", ):
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
		super().__init__(self)
	

	def run(self):
		"""TODO"""
		print("TO IMPLEMENT")


class RegionsManager(th.Thread):
	"""TODO"""

	
	def __init__(self):
		"""TODO"""
		super().__init__(self)
	

	def run(self):
		"""TODO"""
		print("TO IMPLEMENT")


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
		elif (request == "plugins"):
			self.send_plugins(c)
		elif (request == "regions"):
			self.send_regions(c)
		elif (request == "push_delete"):
			self.delete(c)
		elif (request == "push_save"):
			self.save(c)
	
		#report("- connection closed.", self)

	
	def ping(self, c):
		"""TODO"""
		c.send(b"pong")
		c.close


	def send_server_id(self, c):
		"""TODO"""
		c.send(DMR_SERVER_ID.encode())
		c.close


	def send_server_name(self, c):
		"""TODO"""
		c.send(DMR_SERVER_NAME.encode())
		c.close


	def send_server_description(self, c):
		"""TODO"""
		c.send(DMR_SERVER_DESCRIPTION.encode())
		c.close


	def send_plugins(self, c):
		"""TODO"""

		filename = os.path.join("_DMR", os.path.join("DMRTemp", "Plugins.zip"))
		
		send_or_cached(c, filename)


	def send_regions(self, c):
		"""TODO"""

		package("regions")	#TODO check to see if regions have changed before repackaging

		filename = os.path.join("_DMR", os.path.join("DMRTemp", "Regions.zip"))

		send_or_cached(c, filename)


	def delete(self, c):
		"""TODO"""

		c.send(b"ok")

		user_id = c.recv(DMR_BUFFER_SIZE).decode()
		c.send(b"ok")
		region = c.recv(DMR_BUFFER_SIZE).decode()
		c.send(b"ok")
		city = c.recv(DMR_BUFFER_SIZE).decode()

		c.send(b"ok") #TODO verify that the user can make the deletion

		#TODO only delete file if user is authorized

		filename = os.path.join("_DMR", os.path.join("Regions", os.path.join(region, city)))

		os.remove(filename)

		c.close()


	def save(self, c):
		"""TODO"""
		
		c.send(b"ok")

		user_id = c.recv(DMR_BUFFER_SIZE).decode()
		c.send(b"ok")
		region = c.recv(DMR_BUFFER_SIZE).decode()
		c.send(b"ok")
		city = c.recv(DMR_BUFFER_SIZE).decode()

		c.send(b"ok") #TODO verify that the user can make the claim

		#TODO only receive file if user is authorized

		filename = os.path.join("_DMR", os.path.join("Regions", os.path.join(region, city)))

		receive_file(c, filename)

		c.close()


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