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
		
def generate_easy_vulnfunc():
	'''
		generate the vulnerable function. at this point this just determines the buffersize.
	'''

	return vulnfunc % (random.randint(3, 15)*16)

def generate_hard_vulnfunc():
	'''
		generate the vulnerable function. at this point this just determines the buffersize.
	'''

	return hard_vulnfunc % (random.randint(0x10, 0x201))

def generate_easy():
	'''
		generates a 'easy' difficulty binary. 
		it gives the attacker a nice place to store data in the bss
		it gives the attacker a way to call system directly through the plt.
	'''

	out = ""

	out += preamble
	# generate globals
	# if easy or medium, must include name
	glbls = generate_globals(random.randint(0, 5), ["char name[20];"])
	out += glbls

	# if easy must include system
	plt = generate_plt(["system(\"\");"])
	out += plt

	vuln  = generate_easy_vulnfunc()

	codes = routines.values()
	codes.append(vuln)

	# see if we add any bloat
	bloatcnt = random.randint(0,len(bloat))
	random.shuffle(bloat)

	for i in range(bloatcnt):
		codes.append(bloat[i])

	random.shuffle(codes)
	for code in codes:
		out += code

	return out

def generate_medium():
	'''
		generates a 'medium' difficulty binary.
		it gives the attacker a nice place to store data in the bss
		the attacker has to call system themself, there is no system symbol in the binary
	'''

	out = ""

	out += preamble
	# generate globals
	glbls = generate_globals(random.randint(0, 5), ["char name[20];"])
	out += glbls

	plt = generate_plt([])
	out += plt

	vuln  = generate_easy_vulnfunc()

	codes = routines.values()
	codes.append(vuln)

	# see if we add any bloat
	bloatcnt = random.randint(0,len(bloat))
	random.shuffle(bloat)

	for i in range(bloatcnt):
		codes.append(bloat[i])

	random.shuffle(codes)
	for code in codes:
		out += code

	return out

def generate_hard():
	'''
		generates a 'hard' difficulty binary.
		the attacker has no known address where user input is copied 
		the attacker has to call system themself, there is no system symbol in the binary
	'''

	out = ""

	out += preamble
	# generate globals
	glbls = generate_globals(random.randint(0, 5), ["char name[20];"])
	out += glbls

	plt = generate_plt()
	out += plt

	vuln  = generate_hard_vulnfunc()

	codes = routines.values()
	codes.append(vuln)

	# see if we add any bloat
	bloatcnt = random.randint(0,len(bloat))
	random.shuffle(bloat)

	for i in range(bloatcnt):
		codes.append(bloat[i])

	random.shuffle(codes)
	for code in codes:
		out += code

	return out

# only generates easy for the time being
def main(argc, argv):
	
	difficulty = 'easy'

	f = open("out.c", "w");

	if (argc > 1):
		difficulty = argv[1]

	if difficulty == 'easy':
		code = generate_easy()
	elif difficulty == 'medium':
		code = generate_medium()	
	elif difficulty == 'hard':
		code = generate_hard()
	else:
		print "[-] unrecognized difficulty, defaulting to easy"

	print code
	f.write(code)

	f.close()

	os.system("gcc -fno-stack-protector -m32 -o vuln out.c")

if __name__ == "__main__":
	main(len(sys.argv), sys.argv)
