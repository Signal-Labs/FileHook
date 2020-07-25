// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include "detours.h"
#include <intrin.h>


struct FileHandleStruct {
    HANDLE hFile;
    ULONGLONG pos;
    BYTE* buf;
    WCHAR* fName;
    ULONGLONG bufLen;
    int type;
};

BOOL firstRead = FALSE;
HANDLE RealFakeWriteable = 0;
BOOL init = FALSE;
CONST int hFiles_sz = 20;
int hFiles_Elem = 0;
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


#define HARDCODED_FILEPATH L"C:\\tmp\\myfiletest.thmx"

extern "C"
__declspec(dllexport)
DWORD FakeRead(LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, FileHandleStruct fStruct)
{
    DWORD bytesRead = nNumberOfBytesToRead;
    DWORD64 lpOverlapped_Offset = 0;
    if (lpOverlapped != 0)
    {
        if (lpOverlapped->Offset > 0 || lpOverlapped->OffsetHigh > 0)
            lpOverlapped_Offset = (DWORD64)lpOverlapped->OffsetHigh << 32 | (DWORD64)lpOverlapped->Offset;
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
        if (lpOverlapped_Offset > 0)
        {
            if ((lpOverlapped_Offset + nNumberOfBytesToRead) > fStruct.bufLen)
            {
                bytesRead = (fStruct.bufLen - lpOverlapped_Offset);
            }
            memcpy(lpBuffer, (byte*)fStruct.buf + lpOverlapped_Offset, bytesRead);
            //pos = lpOverlapped_Offset + bytesRead;

            if (hEvent > 0) {
                SetEvent(hEvent);
            }
            return bytesRead;
        }
        // If not doing an offset read
        if ((fStruct.pos + nNumberOfBytesToRead) > fStruct.bufLen)
        {
            bytesRead = (fStruct.bufLen - fStruct.pos);
        }
        memcpy(lpBuffer, (byte*)fStruct.buf + fStruct.pos, bytesRead);
        fStruct.pos = fStruct.pos + bytesRead;

        if (hEvent > 0) {
            SetEvent(hEvent);
        }
        return bytesRead;
        

    }
    // IF NOT LPOVERLAPPED
    if ((fStruct.pos + nNumberOfBytesToRead) > fStruct.bufLen)
    {
        bytesRead = (fStruct.bufLen - fStruct.pos);
    }

    memcpy(lpBuffer, (byte*)fStruct.buf + fStruct.pos, bytesRead);
    fStruct.pos = fStruct.pos + bytesRead;
    return bytesRead;

}

extern "C"
__declspec(dllexport)
BOOL MyWriteFile(HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped)
{
    // fakeit
    if (lpNumberOfBytesWritten > 0) {
        *lpNumberOfBytesWritten = nNumberOfBytesToWrite;
    }
    return TRUE;
}

extern "C"
__declspec(dllexport)
BOOL WINAPI MyCloseHandle(HANDLE hObject)
{
    // Not closing it, just faking, fine for our fuzz case
    for (int i = 0; i < hFiles_Elem; i++) {
        if (hObject == hFiles[i].hFile) {
            return TRUE;
        }
    }
    // lets fake it
    return TRUE;

    //return fCloseHandle(hObject);

    
}





extern "C"
__declspec(dllexport)
HANDLE CreateFileHandle()
{
    // Fake "writable" handle
    RealFakeWriteable = CreateFileW(
        HARDCODED_FILEPATH,
        GENERIC_READ | GENERIC_WRITE,
        0,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );


    // handle for our in-mem copy
    struct FileHandleStruct fStruct;
    HANDLE hFile = CreateFileW(
        HARDCODED_FILEPATH,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
    );
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
        if (lstrcmpiW(lpFileName, hFiles[i].fName) == 0) {
            // Lets clone it
            struct FileHandleStruct newStruct;
            newStruct.buf = hFiles[i].buf;
            newStruct.bufLen = hFiles[i].bufLen;
            newStruct.fName = (WCHAR*)calloc(1, MAX_PATH);
            lstrcpyW(newStruct.fName,hFiles[i].fName);
            newStruct.hFile = hFiles[i].hFile;
            newStruct.pos = 0;
            newStruct.type = hFiles[i].type;
            hFiles[hFiles_Elem] = newStruct;
            hFiles_Elem = hFiles_Elem + 1;
            return newStruct.hFile;
        }
    }
   
    return RealFakeWriteable;

}
extern "C"
__declspec(dllexport)
BOOL WINAPI MyReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped)
{
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
            if (firstRead == FALSE) {
                firstRead = TRUE;
                int cpuinfo[4];
                __cpuid(cpuinfo, 0x7b3c3638);
            }
            DWORD bytesRead = FakeRead(lpBuffer, nNumberOfBytesToRead, lpOverlapped, hFiles[i]);
            if (lpNumberOfBytesRead != NULL)
            {
                *lpNumberOfBytesRead = bytesRead;
            }
            return TRUE;
        }
    }
    
    return fReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    
}


BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
)
{
    
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH: 
        if (init) {
            break;;
        }
        DisableThreadLibraryCalls(hModule);
        CreateFileHandle();
        DetourRestoreAfterWith();
        DetourTransactionBegin();
        DetourUpdateThread(GetCurrentThread());
        fReadFile = (BOOL(WINAPI*)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernel32.dll"), "ReadFile");
        DetourAttach(&(PVOID&)fReadFile, MyReadFile);
        fCreateFileW = (HANDLE(WINAPI*)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE))GetProcAddress(LoadLibraryA("kernel32.dll"), "CreateFileW");
       DetourAttach(&(PVOID&)fCreateFileW, MyCreateFileW);
        fCloseHandle = (BOOL(WINAPI*)(HANDLE))GetProcAddress(LoadLibraryA("kernel32.dll"), "CloseHandle");
       DetourAttach(&(PVOID&)fCloseHandle, MyCloseHandle);
       fWriteFile = (BOOL(WINAPI*)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED))GetProcAddress(LoadLibraryA("kernel32.dll"), "WriteFile");
       DetourAttach(&(PVOID&)fWriteFile, MyWriteFile);
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
