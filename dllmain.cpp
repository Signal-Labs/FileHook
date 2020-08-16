// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <winternl.h>
#include "detours.h"
#include <intrin.h>


struct FileHandleStruct {
    HANDLE hFile;
    ULONGLONG pos;
    BYTE* buf;
    WCHAR* fName;
    ULONGLONG bufLen;
    unsigned int type;
    BOOL async;
};

BOOL firstRead = FALSE;
HANDLE RealFakeWriteable = 0;
BOOL init = FALSE;
CONST unsigned int hFiles_sz = 20;
unsigned int hFiles_Elem = 0;
FileHandleStruct hFiles[hFiles_sz];

BOOL (WINAPI* fWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

BOOL(WINAPI* fReadFile)(
    HANDLE hFile,
    LPVOID lpBuffer,
    DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead,
    LPOVERLAPPED lpOverlapped
    );

BOOL(WINAPI* fCloseHandle)(
    HANDLE hObject
    );

HANDLE(WINAPI* fCreateFileW)(
    LPCWSTR               lpFileName,
    DWORD                 dwDesiredAccess,
    DWORD                 dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes,
    DWORD                 dwCreationDisposition,
    DWORD                 dwFlagsAndAttributes,
    HANDLE                hTemplateFile
);

// Target to intercept
#define HARDCODED_FILEPATH L"C:\\tmp\\test.blg\0\0\0\0"

// Copy we will memory-map
#define HARDCODED_FILEPATH2 L"C:\\tmp\\hey.blg\0\0\0\0"

// Something to fake writes for
#define HARDCODED_FILEPATH3 L"C:\\tmp\\junk.blg\0\0\0\0"

extern "C"
__declspec(dllexport)
DWORD FakeRead(LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, FileHandleStruct* fStruct, BOOL* retVal, BOOL async)
{
    DWORD bytesRead = nNumberOfBytesToRead;
    DWORD64 lpOverlapped_Offset = 0;
    if (lpOverlapped != 0)
    {
        if (lpOverlapped->Offset > 0 || lpOverlapped->OffsetHigh > 0)
            lpOverlapped_Offset = (DWORD64)lpOverlapped->OffsetHigh << 32 | (DWORD64)lpOverlapped->Offset;
        // Offset out-of-bounds
        if (lpOverlapped_Offset >= fStruct->bufLen) {
            SetLastError(ERROR_HANDLE_EOF);
            *retVal = FALSE;
            return -1;
        }
    }
    else
        lpOverlapped_Offset = 0;
    if (lpOverlapped > 0)
    {   // If LPOVERLAPPED
        HANDLE hEvent = lpOverlapped->hEvent;
        if (hEvent > 0) {
            ResetEvent(hEvent);
        }
        // If doing an offset read
        if (lpOverlapped != 0)
        {
            *retVal = TRUE;
            SetLastError(0);
            if ((lpOverlapped_Offset + nNumberOfBytesToRead) > fStruct->bufLen)
            {
                bytesRead = (fStruct->bufLen - lpOverlapped_Offset);
                SetLastError(ERROR_HANDLE_EOF);
                if (async) {
                    *retVal = FALSE;
                }
                else {
                    *retVal = TRUE;
                }
                
            }
            memcpy(lpBuffer, (byte*)fStruct->buf + lpOverlapped_Offset, bytesRead);
            //pos = lpOverlapped_Offset + bytesRead;

            if (hEvent > 0) {
                SetEvent(hEvent);
            }
            
            return bytesRead;
        }
        // If not doing an offset read
        if (fStruct->pos >= fStruct->bufLen)
        {
            SetLastError(ERROR_HANDLE_EOF);
            *retVal = FALSE;
            return -1;
        }
        if ((fStruct->pos + nNumberOfBytesToRead) > fStruct->bufLen)
        {
            bytesRead = (fStruct->bufLen - fStruct->pos);
            SetLastError(ERROR_HANDLE_EOF);
            *retVal = TRUE;
        }
        memcpy(lpBuffer, (byte*)fStruct->buf + fStruct->pos, bytesRead);
        fStruct->pos = fStruct->pos + bytesRead;

        if (hEvent > 0) {
            SetEvent(hEvent);
        }
        *retVal = TRUE;
        return bytesRead;
        

    }
    // IF NOT LPOVERLAPPED
    if ((fStruct->pos + nNumberOfBytesToRead) > fStruct->bufLen)
    {
        bytesRead = (fStruct->bufLen - fStruct->pos);
    }

    memcpy(lpBuffer, (byte*)fStruct->buf + fStruct->pos, bytesRead);
    fStruct->pos = fStruct->pos + bytesRead;
    SetLastError(0);
    *retVal = TRUE;
    return bytesRead;

}


// Faking writes to any file, we can ignore these in our fuzz case
extern "C"
__declspec(dllexport)
BOOL MyWriteFile(HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    if (firstRead != TRUE) {
        return fWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    // fakeit
    if (lpNumberOfBytesWritten > 0) {
        *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
    }
    return TRUE;
}

NTSTATUS(WINAPI* fNtCreateFile)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength);

BOOL ShouldHook = TRUE;



extern "C"
__declspec(dllexport)
BOOL WINAPI MyCloseHandle(HANDLE hObject)
{
    // Not closing it, just faking, fine for our fuzz case
    for (int i = 0; i < hFiles_Elem; i++) {
        if (hObject == hFiles[i].hFile) {
            ZeroMemory(&hFiles[i], sizeof(hFiles[i]));
            return fCloseHandle(hObject);
        }
    }
    if (hObject == RealFakeWriteable) {
        return TRUE;
    }
    // lets fake it
    //return TRUE;

    return fCloseHandle(hObject);

    
}





extern "C"
__declspec(dllexport)
HANDLE CreateFileHandle()
{
    // Fake "writable" handle
    RealFakeWriteable = CreateFileW(
        HARDCODED_FILEPATH3,
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (RealFakeWriteable == INVALID_HANDLE_VALUE) {
        int err = GetLastError();
        return INVALID_HANDLE_VALUE;
    }


    // handle for our in-mem copy
    struct FileHandleStruct fStruct;
    HANDLE hFile = CreateFileW(
        HARDCODED_FILEPATH2,
        GENERIC_ALL,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
    if (hFile == INVALID_HANDLE_VALUE) {
        int err = GetLastError();
        return INVALID_HANDLE_VALUE;
    }
    fStruct.type = 1;
    fStruct.hFile = hFile;
    fStruct.bufLen = GetFileSize(hFile, NULL);
    HANDLE hMap = CreateFileMappingA(
        hFile,
        NULL,
        PAGE_READONLY,
        0,
        0,
        NULL
    );
    
    fStruct.buf = (BYTE*)MapViewOfFile(
        hMap,
        FILE_MAP_READ,
        0,
        0,
        0
    );
    fStruct.fName = (WCHAR*)calloc(1, MAX_PATH);
    lstrcpyW(fStruct.fName,(WCHAR*)HARDCODED_FILEPATH);
    fStruct.pos = 0;

    // No length checks on hFiles_Elem
    hFiles[hFiles_Elem] = fStruct;
    hFiles_Elem = hFiles_Elem + 1;

    // Repeat above for any other files you want an in-mem only copy of
    


    return NULL;

}



extern "C"
__declspec(dllexport)
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
   
    for (int i = 0; i < hFiles_Elem; i++) {
        if (_wcsicmp(lpFileName, hFiles[i].fName) == 0) {
            // Lets clone it
            struct FileHandleStruct newStruct = {};
            if (dwFlagsAndAttributes & FILE_FLAG_OVERLAPPED) {
                newStruct.async = TRUE;
            }
            else {
                newStruct.async = FALSE;
            }
            newStruct.buf = hFiles[i].buf;
            newStruct.bufLen = hFiles[i].bufLen;
            newStruct.fName = (WCHAR*)calloc(1, MAX_PATH);
            lstrcpyW(newStruct.fName,hFiles[i].fName);
            
            HANDLE hFileTmp = fCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
            newStruct.hFile = hFileTmp;
            newStruct.pos = 0;
            newStruct.type = hFiles[i].type;
            
            
            hFiles[hFiles_Elem] = newStruct;
            hFiles_Elem = hFiles_Elem + 1;
        
            return hFileTmp;
        }
    }

    // Act normal if we haven't hit the start of our fuzzcase
    //if (firstRead != TRUE) {
        return fCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
   // }
    //return RealFakeWriteable;

}




NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    if (ShouldHook) {
        ShouldHook = FALSE;
        // first hit is going to be our target
        *FileHandle = hFiles[0].hFile;
        return 0x0;
    }
    return fNtCreateFile(FileHandle, DesiredAccess, ObjectAttributes, IoStatusBlock, AllocationSize, FileAttributes,
        ShareAccess, CreateDisposition, CreateOptions, EaBuffer, EaLength);
}




extern "C"
__declspec(dllexport)
BOOL WINAPI MyReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
           /* if (firstRead == FALSE) {
                firstRead = TRUE;
                int cpuinfo[4];
                __cpuid(cpuinfo, 0x7b3c3638);
                volatile ULONGLONG len = hFiles[i].bufLen;
                volatile PVOID buf2 = hFiles[i].buf;
            } */
            BOOL retVal = FALSE;

            DWORD bytesRead = FakeRead(lpBuffer, nNumberOfBytesToRead, lpOverlapped, &hFiles[i], &retVal, hFiles[i].async);
            if (lpNumberOfBytesRead != NULL)
            {
                *lpNumberOfBytesRead = bytesRead;
            }
            return retVal;
        }
    }

    // If handle is our fake handle
    /*if (hFile == RealFakeWriteable) {
        return FALSE;
    }*/
    return fReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    HANDLE hTest = 0;
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        if (init) {
            break;;
        }
        hTest = CreateFileHandle();
        if (hTest == INVALID_HANDLE_VALUE) {
            return FALSE;
        }
        DisableThreadLibraryCalls(hModule);
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        fReadFile = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernelbase.dll"), "ReadFile");
        DetourAttach(&(PVOID&)fReadFile, MyReadFile);
        fCreateFileW = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(LoadLibraryA("kernelbase.dll"), "CreateFileW");
       DetourAttach(&(PVOID&)fCreateFileW, MyCreateFileW);
        /*fNtCreateFile = (NTSTATUS(WINAPI*)(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
            ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength))GetProcAddress(LoadLibraryA("ntdll.dll"), "NtCreateFile");
        DetourAttach(&(PVOID&)fNtCreateFile, MyNtCreateFile);
        */
        fCloseHandle = (BOOL(WINAPI*)(HANDLE))GetProcAddress(LoadLibraryA("kernel32.dll"), "CloseHandle");
       DetourAttach(&(PVOID&)fCloseHandle, MyCloseHandle);
       //fWriteFile = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernel32.dll"), "WriteFile");
       //DetourAttach(&(PVOID&)fWriteFile, MyWriteFile);
       DetourTransactionCommit();

        init = TRUE;
        break;
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}
