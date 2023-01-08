import configparser
import hashlib
import os
import shutil
import socket
import threading
import random
import zipfile
import string


# Path to the resources subdirectory
dmr_resources_path = "resources"


# Default config values
default_host = socket.gethostname()
default_port = 7246

# Config constants
DMR_HOST = None
DMR_PORT = None

# Hard-coded constants
DMR_SEPARATOR = b"<SEPARATOR>"
DMR_BUFFER_SIZE = 4096


"""Gives the path of a given file in the DMR "resources" subdirectory

Arguments:
	filename (str)

Returns:
	TODO type: the path to the given file
"""
def get_dmr_path(filename):
	return os.path.join(dmr_resources_path, filename)


"""Creates the required subdirectories if they do not yet exist.

Arguments:
	None

Returns:
	None
"""
def create_subdirectories():

	print("[DMR] Creating subdirectories...")

	directories = ["DMRBackups", "DMRProfiles", "DMRTemp", "Plugins", "Regions"]

	for directory in directories:
		new_directory = os.path.join("_DMR", directory)
		if not os.path.exists(new_directory):
			try:
				os.makedirs(new_directory)
				if (directory == "Plugins" or "Regions"):
					shutil.unpack_archive(get_dmr_path(directory + ".zip"), new_directory)
			except:
				print ("Failed to create " + directory + " subdirectory.")
				print('(this may have been printed by error, check your "_DMR" subdirectory)')


"""Loads the config file from the resources subdirectory or creates it if it does not yet exist.

Arguments:
	None

Returns:
	None
"""
def load_config():

	global DMR_HOST
	global DMR_PORT
	global DMR_BUFFER_SIZE

	print("[DMR] Loading config...")

	configpath = os.path.join("_DMR", "serverconfig.ini")
	try:
		config = configparser.RawConfigParser()
		config.read(configpath)

		DMR_HOST = config.get('server', "host")
		DMR_PORT = int(config.get('server', 'port'))
	except:
		config.remove_section('server')
		config.add_section('server')
		config.set('server', 'host', default_host)
		config.set('server', 'port', default_port)
		
		with open(configpath, 'wt') as configfile:
			config.write(configfile)

		DMR_HOST = default_host
		DMR_PORT = default_port


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
def package_plugins_and_regions():
	print("[DMR] Packaging plugins and regions...")
	#print("(this may take several minutes)")
	package("plugins")
	package("regions")


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
def package(type):

	print("packaging " + type + "...")

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


"""Starts the server.

Arguments:
	None

Returns:
	None
"""
def start_server():

	print("[DMR] Starting server...")

	print("creating socket...")
	s = socket.socket()

	print("binding host and port...")
	s.bind((DMR_HOST, DMR_PORT))

	print("listening for connections...")
	s.listen(5)

	while (True):

		#try:

		c, address = s.accept()
		print("connection accepted with " + str(address[0]) + ":" + str(address[1]) + ".")

		request = c.recv(DMR_BUFFER_SIZE).decode()

		print("request: " + request)

		if (request== "ping"):
			ping(c)
		elif (request == "plugins"):
			send_plugins(c)
		elif (request == "regions"):
			send_regions(c)
		elif (request == "push_delete"):
			delete(c)
		elif (request == "push_save"):
			save(c)
		
		print("connection closed.")

		#except:

			#print("connection error.")


"""TODO"""
def ping(c):
	c.send(b"pong")
	c.close


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
def send_plugins(c):
	filename = os.path.join("_DMR", os.path.join("DMRTemp", "Plugins.zip"))
	send_file(c, filename)


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
def send_regions(c):

	package("regions")

	filename = os.path.join("_DMR", os.path.join("DMRTemp", "Regions.zip"))

	send_file(c, filename)
	

def delete(c):
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


def save(c):
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


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
def send_file(c, filename):

	print("Sending file " + filename + "...")

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

	print("[Socket] Receiving " + filesize + " bytes...")
	print("writing to " + filename)

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


"""TODO

Arguments:
	TODO

Returns:
	TODO
"""
#TODO documentation
#class server_thread(threading.Thread):
	#TODO


"""The main method.

Arguments:
	None

Returns:
	None
"""
def main():
	print("[DMR] Server version X.XX") #TODO version
	create_subdirectories()
	load_config()
	package_plugins_and_regions()
	start_server()
	

# Load the main function
if __name__ == '__main__':
	main()