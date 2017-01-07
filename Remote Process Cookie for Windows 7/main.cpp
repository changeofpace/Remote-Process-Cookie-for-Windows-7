#include <Windows.h>
#include <cstdio>
#include <Psapi.h>
#include <vector>
#include <algorithm> 

#define CREATE_PROCESS_FLAGS     DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE

struct POINTER_ENCODING
{
    const ULONG_PTR encoded;
    const ULONG_PTR decoded;
    POINTER_ENCODING(ULONG_PTR e, ULONG_PTR d) : encoded(e), decoded(d) {}
};

// debugger globals
PROCESS_INFORMATION processInformation = {};
ULONG_PTR ntdll = 0;
ULONG_PTR kernel32 = 0;



ULONG_PTR DereferenceRemotePointer(HANDLE ProcessHandle, ULONG_PTR Pointer)
{
    ULONG_PTR value = 0;
    if (ReadProcessMemory(ProcessHandle, LPVOID(Pointer), &value, sizeof(ULONG_PTR), NULL))
        return value;
    return 0;
}

// see ntdll.RtlDecodePointer
ULONG_PTR DecodeRemotePointer(ULONG_PTR EncodedPointer, ULONG Cookie)
{
    return (_rotr64(EncodedPointer, 0x40 - (Cookie & 0x3F)) ^ Cookie);
}

bool IsValidEncoding(const POINTER_ENCODING& EncodingMap, ULONG Cookie)
{
    return EncodingMap.decoded == DecodeRemotePointer(EncodingMap.encoded, Cookie);
}

// control 1:  ntdll.RtlpUnhandledExceptionFilter = EncodePointer(kernel32.UnhandledExceptionFilter)
// control 2:  kernel32.SingleHandle = EncodePointer(kernel32.DefaultHandler)
ULONG GetRemoteProcessCookie()
{
    // ntdll.RtlpUnhandledExceptionFilter value
    const ULONG_PTR RtlpUnhandledExceptionFilter = DereferenceRemotePointer(processInformation.hProcess, ntdll + 0x12D430);

    // kernel32.UnhandledExceptionFilter address
    const ULONG_PTR UnhandledExceptionFilter = kernel32 + 0x9BAB0;

    // kernel32.SingleHandler value
    const ULONG_PTR SingleHandler = DereferenceRemotePointer(processInformation.hProcess, kernel32 + 0x10A750);

    // kernel32.DefaultHandler address
    const ULONG_PTR DefaultHandler = kernel32 + 0x41340;

    if (!RtlpUnhandledExceptionFilter || !UnhandledExceptionFilter || !SingleHandler || !DefaultHandler)
        return 0;

    POINTER_ENCODING ueFilter = POINTER_ENCODING(RtlpUnhandledExceptionFilter, UnhandledExceptionFilter);
    POINTER_ENCODING consoleHandler = POINTER_ENCODING(SingleHandler, DefaultHandler);

    ULONG cookie = 0;
    for (int i = 64; i > 0; i--)
    {
        const ULONG guess = ULONG(_rotr64(ueFilter.encoded, i) ^ ueFilter.decoded);

        if (IsValidEncoding(ueFilter, guess) && IsValidEncoding(consoleHandler, guess))
        {
            // cookie collision, we're unable to determine which cookie is correct so return 0
            if (cookie)
                return 0;
            cookie = guess;
        }
    }
    return cookie;
}

void DebugLoop()
{
    bool ok = true;
    DEBUG_EVENT debugEvent;
    DWORD status = DBG_CONTINUE;

    while (ok)
    {
        WaitForDebugEvent(&debugEvent, INFINITE);

        switch (debugEvent.dwDebugEventCode)
        {
        case EXCEPTION_DEBUG_EVENT:
        {
            // system breakpoint
            if (debugEvent.u.Exception.ExceptionRecord.ExceptionCode == STATUS_BREAKPOINT)
            {
                ULONG processCookie = GetRemoteProcessCookie();
                printf("remote process cookie:  0x%X\n", processCookie);
                ok = false;
            }
        }
        break;

        case LOAD_DLL_DEBUG_EVENT:
        {
            // get ntdll and kernel32 imagebase
            if (!ntdll)
                ntdll = ULONG_PTR(debugEvent.u.LoadDll.lpBaseOfDll);
            else if (!kernel32)
                kernel32 = ULONG_PTR(debugEvent.u.LoadDll.lpBaseOfDll);
        }
        break;
        }

        if (!ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, status))
        {
            printf("ContinueDebugEvent failed %d.\n", GetLastError());
            break;
        }
    }
}

int main(int argc, char* argv[])
{
    OPENFILENAME ofn = {};
    char szFile[260] = "";

    ofn.lStructSize = sizeof(ofn);
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = sizeof(szFile);
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileName(&ofn))
    {
        STARTUPINFO si = {};
        si.cb = sizeof(si);

        if (CreateProcess(ofn.lpstrFile, NULL, NULL, NULL, FALSE, CREATE_PROCESS_FLAGS, NULL, NULL, &si, &processInformation))
        {
            DebugLoop();

            if (!DebugActiveProcessStop(processInformation.dwProcessId))
                printf("DebugActiveProcessStop failed %d.\n", GetLastError());

            CloseHandle(processInformation.hProcess);
            CloseHandle(processInformation.hThread);
        }
        else
            printf("CreateProcess failed %d.\n", GetLastError());
    }
    else
        printf("GetOpenFileName failed %d.\n", CommDlgExtendedError());

    getchar();
	return 0;
}
