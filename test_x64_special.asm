#width 64
#global main

main:
    ; System call instructions
    syscall
    sysret
    sysenter
    sysexit
    
    ; Processor identification
    cpuid
    
    ; Time stamp counter
    rdtsc
    rdtscp
    
    ; Model specific registers
    rdmsr
    wrmsr
    
    ; Performance monitoring
    rdpmc
    
    ; Random number generation
    rdrand rax
    rdrand rbx
    rdseed rcx
    rdseed rdx
    
    ; Segment operations
    swapgs
    
    ; Monitor/wait
    monitor
    mwait
    
    ; Cache management
    clflush [rax]
    clflushopt [rbx]
    clwb [rcx]
    
    ; Memory fencing
    mfence
    sfence
    lfence
    
    ; Prefetch instructions
    prefetcht0 [rax]
    prefetcht1 [rbx]
    prefetcht2 [rcx]
    prefetchnta [rdx]
    
    ; Special instructions
    ud2
    pause
    
    ; Cache invalidation
    invd
    wbinvd
    invlpg [rax]
    
    ; 64-bit interrupt return
    iretq
    
    ; Exit
    mov edi, 0
    call exit
