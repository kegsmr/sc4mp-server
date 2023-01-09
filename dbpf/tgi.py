def ID(value):
	"""coerces valid IDs into integers"""
	if value is None:
		return None
	if isinstance(value, float) or isinstance(value, int):
		return value
	if isinstance(value, str):
		return int(value, 16)
	return None

class TGI:
	"""a lossy type,group,instance type"""

	def __init__(self, tid=None, gid=None, iid=None):
		self.tid = ID(tid)
		self.gid = ID(gid)
		self.iid = ID(iid)

	@property
	def query(self):
		"""produices SQL WHERE clauses"""
		where = []
		if ID(self.tid) is not None:
			where.append("tid=?")
		if ID(self.gid) is not None:
			where.append("gid=?")
		if ID(self.iid) is not None:
			where.append("iid=?")
		return " AND ".join(where)

	def __iter__(self):
		"""converts the string into a tuple"""
		if ID(self.tid) is not None:
			yield self.tid
		if ID(self.gid) is not None:
			yield self.gid
		if ID(self.iid) is not None:
			yield self.iid

	def __str__(self):
		"""format as string acceptable by parse"""
		return "T{:08x}G{:08x}I{:08x}".format(*self)

	def __eq__(self, other):
		"""equates two IDs"""
		return other.tid == self.tid and other.gid == self.gid and other.iid == self.iid

def parse(line=""):
	"""turns a TxxxxxxxxGxxxxxxxxIxxxxxxxx into a tuple"""
	l,c,r = line.partition('T')
	if c != 'T':
		return None
	l,c,r = r.partition('G')
	if c != 'G':
		return None
	T = ID(l)
	l,c,r = r.partition('I')
	if c != 'I':
		return None
	G = ID(l)
	l,c,r = r.partition(';')
	I = ID(l)
	return TGI(tid=T,gid=G,iid=I)

