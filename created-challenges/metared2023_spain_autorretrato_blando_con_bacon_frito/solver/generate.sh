gcc -static -nostdlib solver.s -o solverBin
objcopy --dump-section .text=shellcodeRAW solverBin

