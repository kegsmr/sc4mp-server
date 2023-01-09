import struct
import array
from collections import namedtuple

Header = struct.Struct("<4s17L24s")
class Index(namedtuple("DBPF_Index", 'version count offset size')): pass
class Record(namedtuple("DBPF_Record", 'type group instance offset length size raw')): pass

class DBPF:
	"""a database backed DBPF file"""
	@property
	def version(self):
		"""a real number representing the header version"""
		return version(self.header[1], self.header[2])

	@property
	def user_version(self):
		"""a real number representing the user version"""
		return version(self.header[3], self.header[4])

	@property
	def flags(self):
		"""flags"""
		return self.header[5]

	@property
	def ctime(self):
		"""creation time"""
		return self.header[6]

	@property
	def mtime(self):
		"""modification time"""
		return self.header[7]

	@property
	def index(self):
		"""the table of files in this DBPF"""
		iv = self.header[8] if self.header[1] == 1 else self.header[15]
		return Index(iv, self.header[9], self.header[10], self.header[11])

	@property
	def holes(self):
		"""the table of holes in this DBPF"""
		return Index(0, self.header[12], self.header[13], self.header[14])

	def __init__(self, fd):
		if isinstance(fd, str):
			fd = open(fd, 'rb')
		#if not isinstance(fd, file):
		#	raise ArgumentException('File')
		self._fd = fd;

		fd.seek(0)
		self.header = Header.unpack(fd.read(Header.size))
		if self.header[0] != b'DBPF':
			raise DBPFException('Not a DBPF file')

	@property
	def _index_width(self):
		"""the width of records in the index table"""
		return {7.0:5, 7.1:6}.get(self.index.version, '')

	def _table(self, offset, length, width):
		"""parse the passed """
		self._fd.seek(offset)
		raw = array.array('L',self._fd.read(length));
		for i in range(0, len(raw), width):
			yield raw[i : i + width]

	def save(self, fd):
		"""save files to the passed fd"""
		# prepare
		head = list(self.header)
		ind = []
		o = Header.size
		for tgi in self.records:
			f = self.record(*tgi)
			d = dict( key = tgi, offset = o, length = len(f), raw = f )
			ind.append(d)
			o += len(f)
		# <index<count:4><offset:4><size:4>:12>
		head[9] = len(ind)
		head[10] = o
		head[11] = len(ind) * self._index_width * 4
		# zero hole table
		head[12] = head[13] = head[14] = 0
		# save header
		fd.seek(0)
		fd.write(Header.pack(*head))
		# save files
		for r in ind:
			fd.write(r['raw'])
		# save index
		for r in ind:
			rec = list(r['key']) + [r['offset'], r['length']]
			fd.write(struct.pack("5L", *rec))

	@property
	def records(self):
		"""retrieve all TGIs"""
		ind = self.index
		for rec in self._table(ind.offset, ind.size, self._index_width):
			yield rec[:3]

	def record(self, T, G, I):
		"""retrieve the (first) file called TGI"""
		ind = self.index
		for rec in self._table(ind.offset, ind.size, self._index_width):
			if rec[0] != T or rec[1] != G or rec[2] != I:
				continue
			self._fd.seek(rec[-2])
			return self._fd.read(rec[-1])

#util
def version(major, minor): return float('.'.join([str(major),str(minor)]))

#exceptions
class ArgumentException(Exception): pass
class DBPFException(Exception): pass

if __name__ == '__main__':
	import sys
	import tgi
	db = DBPF(sys.argv[1])
	for r in db.records:
		print(tgi.TGI(*r))
	if len(sys.argv) > 2:
		db.save(open(sys.argv[2],"wb"))
