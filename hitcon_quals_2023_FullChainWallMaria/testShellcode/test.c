//gcc shellcode.s test.c

#include <sys/mman.h>

 enum{
     Pagesz = 4*1024,
 };

extern char shellcode[];

int main(int argc, char** argv)
{
    int (*f)() = (int(*)())shellcode;
    void *addr =  (void*)((unsigned long long)f / Pagesz * Pagesz);
    mprotect(addr, Pagesz, PROT_READ|PROT_WRITE|PROT_EXEC);
    f();
}
