# Remote Process Cookie for Windows 7

## Summary

Remote process cookies can be obtained by performing a brute-force attack on a recreated ntdll.RtlDecodePointer using known pointer encodings as control variables.

## Usage

The project contains a simple debugger and a test program.  The debugger creates a debugged process from a user-selected file, determines the created process's local cookie in the system breakpoint debug event, prints the cookie value, and then detaches.  The test program calls NtQueryInformationProcess with PROCESS_INFORMATION_CLASS = 0x24 to print its local process cookie.

## Issues

Cookie collisions are possible.  If GetRemoteProcessCookie discovers multiple 'valid' cookies then it returns 0.  

## Notes

- Designed for / tested on Windows 7 SP1 x64.
- Absolute offsets are used to avoid loading symbols and may break in future OS updates.

## Credits

Idea by [mattiwatti](https://github.com/Mattiwatti) from the [issue 489](https://github.com/x64dbg/x64dbg/issues/489#issuecomment-265866033) discussion for x64dbg.

