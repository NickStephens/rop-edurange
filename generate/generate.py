#!/usr/bin/env python

import sys
import os
import random
import string
from definitions import *

'''
This scripts attempts to generate a slightly differnt vulnerable binary
each time. The vulnerability will stay consistent, but changes will be
made that require tweaks to the exploit.
'''

def random_string(n):
	'''
		generate a random string of length n.
	'''

	return ''.join(random.choice(string.letters) for _ in range(n))

def generate_globals(n, necessary=[]):
	'''
		generate a number of globals.
	'''

	out  = ""

	for df in necessary:
		out += df + "\n"

	for i in range(n):
		valid = False
		while (not valid):
			valid = True
			var = random_string(random.randint(0,10)+1)
			for n in necessary:
				if var in n:
					valid = False
			if var in ckeywords:
				valid = False
		out += "char %s[%d];\n" % (var, (random.randint(0,10)+1)*16)

	return out

def generate_plt(necessary=[]):
	''' 
		generates a function to populate the PLT in a random order.
		necessary is a list of libc function calls which will be included in addition
		to those randomly picked from libcfuncs.
	'''


	out  = "void init_plt(void)\n"
	out += "{\n"

	maxf = len(libcfuncs)
	random.shuffle(libcfuncs)
	for i in range(random.randint(0,maxf)):
		out += libcfuncs[i] + "\n"

	for f in necessary:
		out += f + "\n"

	out += "}"

	return out
		
def generate_vulnfunc():
	'''
		generate the vulnerable function. at this point this just determines the buffersize.
	'''

	return vulnfunc % (random.randint(0x10, 0x201))

# only generates easy for the time being
def main(argc, argv):
	
	f = open("out.c", "w");

	f.write(preamble)

	print preamble
	# generate globals
	# if easy or medium, must include name
	glbls = generate_globals(random.randint(0, 5), ["char name[20];"])
	print glbls
	f.write(glbls)

	# if easy must include system
	plt = generate_plt(["system(\"\");"])
	print plt
	f.write(plt)

	vuln  = generate_vulnfunc()

	codes = routines.values()
	codes.append(vuln)

	# see if we add any bloat
	bloatcnt = random.randint(0,len(bloat))
	random.shuffle(bloat)

	for i in range(bloatcnt):
		codes.append(bloat[i])

	random.shuffle(codes)
	for code in codes:
		print code
		f.write(code)

	f.close()

	os.system("gcc -fno-stack-protector -m32 -o vuln out.c")

if __name__ == "__main__":
	main(len(sys.argv), sys.argv)
