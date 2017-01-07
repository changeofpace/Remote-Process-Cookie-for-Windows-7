#include <Windows.h>
#include <cstdio>

#define PROCESSINFOCLASS_PROCESS_COOKIE 0x24

typedef LONG NTSTATUS;
typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(HANDLE, ULONG, PVOID, ULONG, PULONG);


ULONG GetLocalProcessCookie()
{
    NtQueryInformationProcess_t NtQueryInformationProcess = (NtQueryInformationProcess_t)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationProcess");
    if (NtQueryInformationProcess)
    {
        ULONG cookie = 0;
        ULONG retlen = 0;
        if (!NtQueryInformationProcess(GetCurrentProcess(), PROCESSINFOCLASS_PROCESS_COOKIE, &cookie, sizeof(cookie), &retlen))
            return cookie;
    }
    return 0;

}

int main(int argc, char argv[])
{
    ULONG cookie = GetLocalProcessCookie();
    if (cookie)
        printf("local process cookie:  0x%X\n", cookie);
    else
        printf("GetLocalProcessCookie failed %d.\n", GetLastError());
    getchar();
	return 0;
}

