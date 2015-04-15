import StringIO
from binascii import unhexlify


def dejunk(pyew,doprint=True):
	""" Remove junkcode like mov xx, call xx,jmp """
	dis = pyew.disassemble(pyew.buf, pyew.processor, pyew.type, pyew.lines, pyew.bsize, baseoffset=pyew.offset)
	print "Warning! The operation may change file, please backup before use this function"
	maxsize = pyew.maxsize
	s = StringIO.StringIO()
	s.write(dis)
	s.seek(0)
	junk_patterns = ['e8', 'b8', 'be'] #[call, mov]
	jmp_patterns = ['0f84', '0f85', '0f82', '0f83', '0f86', '0f87', '0f8f', '0f8e','0f88','0f89']
	lines = s.readlines()
	flag = False
	for i in lines:
		if '--------------' not in i:
			sp = i.split()
			if sp[1] in junk_patterns:
				if sp[1] == 'e8':
					if  int(sp[4], 16) > maxsize:
						print sp
						pyew.f.seek(int(sp[0], 16))
						pyew.f.write(unhexlify('90'))
						pyew.seek(int(sp[0], 16))
				# deal with mov
				elif int(sp[2][4:6] + sp[2][2:4] + sp[2][:2], 16) > maxsize:
					print sp
					pyew.f.seek(int(sp[0], 16))
					pyew.f.write(unhexlify('90'))
					pyew.seek(int(sp[0], 16))

	        # deal with jmp 
	        elif sp[1] in jmp_patterns:
	        	if not flag:
		        	flag = True
		        	addroffset = sp[0]
		        	offvalue = sp[4]
		        	mclocal = sp[1]
		        elif sp[4] ==offvalue:
		        	flag = False
		        	if jmp_patterns.index(mclocal) %2 == 0:
		        		if sp[1] == jmp_patterns[jmp_patterns.index(mclocal)+1]:
							pyew.f.seek(int(addroffset, 16))
							print sp
			                pyew.f.write(unhexlify('90eb'))
			                pyew.seek(int(addroffset, 16))
			        elif sp[1] == jmp_patterns[jmp_patterns.index(mclocal)-1]:
						pyew.f.seek(int(addroffset, 16))
						pyew.f.write(unhexlify('90eb'))
						pyew.seek(int(addroffset, 16))


functions = {"dejunk": dejunk}