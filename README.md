# FileHook

This DLL can be injected into a process to load up a buffer containing the contents of any file from disk, and then redirect any future file creates/reads to this buffer.

Pretty much like a RAM disk, but not an actual RAM disk.

I use this for fuzzing, when I want to have a single buffer in-memory for modifying a file and ensure the process only reads from my buffer (also prevents unneccessary disk accesses), so if the program does multiple reads, instead of intercepting and fuzzing each read, or by modifying the file and saving to disk before causing the reads, we simply have a single mapped buffer of the file in-memory and redirect all reads to perform against our mapped in-mem image instead of disk.

Initally developed this to work with a custom hypervisor fuzzer that doesn't support disks, but its useful in other cases too.

This should support both ASYNC and SYNC reads, including OVERLAPPED reads. Not great for running on a target long-term (due to likely mem-leaks or something), I use this for snapshot fuzzing so haven't been worrried about that. 

Note: There are three #define HARDCODED_FILEPATH vars, one is the target to intercept, another is one we will map in-mem (may be the same as target or different), another is used if we fake writes.

The idea is:

1. Prog attempts to call CreateFileW on e.g. c:\test.txt
2. We load test.txt in-mem
3. Prog attempts to read from file (ReadFile API or something that wraps it)
4. We intercept read, and emulate the read through our mem-mapped version of the file


Note: Requires Detours https://github.com/microsoft/Detours

Note: Currently no real supports for writes, we can either fake it or forward to OS
