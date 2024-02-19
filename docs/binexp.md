## **Shellcode**
x86 assembly in byte form typically given as payload to a vulnerable program to be executed.

## **Buffer Overflow**
Typically, an insecure input function such as gets() may allow the user to modify data
beyond the allowed boundaries of the memory area and potentially be able to overwrite data or even
redirect program flow.

## Implications of Buffer Overflow 
- Data already pushed to the stack can be overwritten causing incorrect or unintended behaviour.
- When a function is called, it will push a return address to the stack before setting up the stack
frame. This is so that when the function is done, this return address is popped back into the
EIP/RIP register to resume the caller function to continue its work. Corrupting this pushed return
address will allow us to arbitrarily execute another function or executable region.
- As an extension of the previous point, we can use so called ROP gadgets to develop even more
complex control flow. This is called return oriented programming.
- In some more exotic cases, the attacker may target the pushed EBP/RBP to switch to another
entirely different stack of his choosing once the function returns. This is referred to as stack
pivoting.

## Mitigations
- **Stack canary:** At runtime, a randomized stack cookie is added after the stack frame. If this cookie
gets corrupted, the stack check will abruptly exit the program instead of returning. This prevents
attempts at EIP/RIP control as well as return oriented programming.
- **ASLR:** Address space randomization randomizes the base address on every execution. Without
any kind of leak, the attacker will be forced to bruteforce the base address. This can be a very
large search space on 64 bit systems.
- **NX or DEP:** The stack is marked as non executable by default to thwart attempts at running
shellcodes stored on stack.

**Format string exploit**
If input is passed directly to the first parameter of printf, the user can arbitrarily
input format specifiers to leak data or even overwrite them.
<br />

## **Heap corruption**

This deals with exploiting the heap allocators and corrupting the heap structures. Heap
allocators tend to have a lot of attack vectors as developers have to settle for a compromise between
security and performance. Typically, we will be dealing with GLIBC’s allocators on Linux.

When a memory is freed after being malloc’d, this chunk gets move to a bin depending on its size. Well
known ones include TCache, Fastbin, smallbin, largebin and unsorted. These bins are used to track
deallocated chunks for reuse when more memory gets allocated in the future.

## General Heap corruption techniques
- **Use after free:** The user has access to memory chunk even after it has been freed. This chunk
can be manipulated before it gets reused after a subsequent malloc, causing unintended
behaviour if memory is not zeroed out. It can even allow for altering the heap bin structure
entirely. For example, the next pointer of tcache chunk can be overwritten to arbitrarily allocate
a non heap memory chunk.
- **Double free:** A chunk is freed twice, usually causing this chunk to be tracked in the list of freed
chunks twice. The same chunk can get allocated in two different regions.

Many mitigations have been implemented in recent GLIBC version though there are far too many to list.
