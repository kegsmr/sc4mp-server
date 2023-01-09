A file for reading and writing [DBPF](http://en.wikipedia.org/wiki/DBPF_(file_format)) files

DBPF(fd):
	takes a file and parses the first 96 bytes, checking to make sure it is a DBPF.
	if fd is a string, try and open(fd, 'rb')
	parse the index into self.records
	try to parse the directory record into self.records, setting the record.size field to the un

DBPF.records:
	retrieves the entirity of the index table from the file

DBPF.search(tgi):
	retreive a number of records that match the passed type/group/instance ID's
