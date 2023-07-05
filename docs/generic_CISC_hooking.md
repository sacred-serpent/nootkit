# Generic CISC Hooking Method

This is an idea I came up with, and I'll try to incorporate it as a replacement hooking mechanism for `nootkit` in a later version.

## The Method

1. Place absolute jmp at start of target function

Since we don't know the exact location where our stolen bytes cut off an instruction, we can't use a simple trampoline
which replicates those stolen instructions and jumps back to the original function with an offset of the stolen bytes.
We have to find the amount of bytes needed to be stolen to create valid instructions which we can be replicated by our trampoline.
This amount of bytes can be:

a. Greater than the absolute jmp gadget's size
b. Smaller than it.

For the first case, we can employ an iterative method using a hook on the illegal instruction interrupt handler:

2. To call the regular function, employ a regular trampoline, containing only the stolen bytes (which again might be invalid)

3. When the trampoline code inevitably triggers an illegal instruction, within the interrupt handler,  identify that the interrupt originated
from our trampoline. From there, steal one extra byte from the target function.

4. Repeat the trampoline-handler method, restoring register context as meeded, until a valid instruction has been fully stolen.

5. Jump back to the original function, with a modified offset.

On subsequent calls to the trampoline, this method won't have to be repeated, as the stolen bytes are kept valid.

Now, we still have case b to handle; however, it really mostly handles itself.
If the function ends within the length of our stolen bytes, a control flow operation will be contained within the initial trampoline.

However, if any of the bytes we've overwritten are actually the beginning of another function subsequent in memory, we're in a scramble.

This whole method can also be employed in usermode by setting a signal handler for SIGILL.
