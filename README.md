# POC-EDR-unhook-bypass

**Warning:** Directories `C:\Users\john.doe\` and `C:\Users\Public\john.doe\` will be encrypted.

- 1/ Unhook `ntdll.dll` and `kernelbase.dll` to allow syscalls (blocked by EDR)
- 2/ Inject `ransomtest.dll` in other process (firefox and chrome works)
  The EDR seems to monitor the process but not injected dlls (`remove` and `unlink` syscalls are blocked by EDR by executing `ransomtest.exe` directly, even with `ntdll.dll` unhooked)
- 3/ Say goodbye to all John Doe files (`C:\Users\john.doe\` and `C:\Users\Public\john.doe\` directories)

I don't know exactly why it worked, but it did and it's a PoC.

## Binaries

- [john.doe.exe](bin/john.doe.exe), a SFX executable that setup John Doe files (also in [john.doe.zip](bin/john.doe.zip)
- [ransomtest.dll](bin/ransomtest.dll), the encryptor
- [injectdll.exe](bin/injectdll.exe), a utility to inject the encryptor in other processes and bypass EDR
