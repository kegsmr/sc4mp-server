from dbpf.tgi import parse
from dbpf.dbpf import DBPF

def parser(fname):
	for l in open(fname):
		tgi = parse(l)
		if tgi is None:
			continue
		yield tgi

def search(db, fname):
	if not isinstance(db, DBPF):
		raise Exception("pass a dbpf file")
	p = parser(fname)
	db.load()
	for tgi in p:
		res = db.search(tgi)
		if len(res) == 0:
			continue
		if len(res) > 1:
			raise Exception("multiple records found")
		yield res[0]

if __name__ == '__main__':
	import sys
	db = DBPF(sys.argv[1])
	for r in search(db, sys.argv[2]):
		print(r, len(db[r]))
