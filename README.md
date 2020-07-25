# FileHook

This DLL can be injected into a process to load up a buffer containing the contents of any file from disk, and then redirect any future file creates/reads to this buffer.

I use this for fuzzing, when I want to have a single buffer in-memory for modifying a file and ensure the process only reads from my buffer (also prevents unneccessary disk accesses).

Note: Requires Detours https://github.com/microsoft/Detours

Note: Currently no support for writes, any writes attempted to the file path specified will cause errors (due to only a single file-handle & single mapped buffer of the file existing in-mem)
