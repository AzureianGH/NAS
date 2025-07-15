#!/bin/bash
gcc -nostartfiles -Wl,-e,main -o test/main test/test.elf -m64 -no-pie
