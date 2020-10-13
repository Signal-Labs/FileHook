// dllmain.cpp : Defines the entry point for the DLL application.
#include <Windows.h>
#include <winternl.h>
#include "detours.h"
#include <intrin.h>
#include <shlwapi.h>


struct FileHandleStruct {
    HANDLE hFile;
    ULONGLONG pos;
    BYTE* buf;
    WCHAR* fName;
    DWORD64 bufLen;
    unsigned int type;
    BOOL async;
};

struct OverlappedResult {
    HANDLE hFile;
    LPOVERLAPPED lpOverlapped;
    LPDWORD lpNumberOfBytesTransferred;
    DWORD bytesTransferred;
    BOOL eof;
};

BOOL firstRead = FALSE;
HANDLE RealFakeWriteable = 0;
BOOL init = FALSE;
CONST unsigned int hFiles_sz = 0x2000;
LONGLONG hFiles_Elem;
LONGLONG hOverlapped_Elem;
CONST unsigned int hOverlapped_sz = 0x8000;
FileHandleStruct hFiles[hFiles_sz];
OverlappedResult hOverlapped[hOverlapped_sz];

DWORD(WINAPI* fSetFilePointer)(
    HANDLE       hFile,
    LONG         lDistanceToMove,
    PLONG        lpDistanceToMoveHigh,
    DWORD        dwMoveMethod
    );

BOOL(WINAPI* fSetFilePointerEx)(
    HANDLE       hFile,
    LARGE_INTEGER        liDistanceToMove,
    PLARGE_INTEGER       lpNewFilePointer,
    DWORD        dwMoveMethod
    );



BOOL (WINAPI* fWriteFile)(
    HANDLE       hFile,
    LPCVOID      lpBuffer,
    DWORD        nNumberOfBytesToWrite,
    LPDWORD      lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

BOOL (WINAPI* fFreeLibrary)(
    HMODULE hLibModule
);

BOOL (WINAPI* fGetOverlappedResult)(
    HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait
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

BOOL(WINAPI* fGetFileSizeEx)(
    HANDLE hFile,
    PLARGE_INTEGER lpFileSize
    );

DWORD(WINAPI* fGetFileSize)(
    HANDLE hFile,
    LPDWORD lpFileSizeHigh
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
#define HARDCODED_FILEPATH L"C:\\tmp\\target.png\0\0\0\0"
//#define HARDCODED_FILEPATH L"c:\\tmp\\test.blg\0\0\0\0"
// Copy we will memory-map
#define HARDCODED_FILEPATH2 L"C:\\tmp\\test.png\0\0\0\0"

// Something to fake writes for
#define HARDCODED_FILEPATH3 L"C:\\tmp\\junk.png\0\0\0\0"

extern "C"
__declspec(dllexport)
DWORD FakeRead(LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPOVERLAPPED lpOverlapped, FileHandleStruct* fStruct, BOOL* retVal, BOOL async)
{
    LONGLONG tmpOverlappedElem = hOverlapped_Elem;
    // Return false if opened ASYNC but not providing an overlapped struct
    if (async) {
        if (lpOverlapped == NULL) {
            *retVal = FALSE;
            return -1;
        }
    }
    DWORD bytesRead = nNumberOfBytesToRead;
    DWORD64 lpOverlapped_Offset = 0;
    if (lpOverlapped != 0)
    {
        if (lpOverlapped->Offset > 0 || lpOverlapped->OffsetHigh > 0)
            lpOverlapped_Offset = (DWORD64)lpOverlapped->OffsetHigh << 32 | (DWORD64)lpOverlapped->Offset;
        // Offset out-of-bounds case
        if (lpOverlapped_Offset >= fStruct->bufLen) {
            if (async) {

                SetLastError(ERROR_IO_PENDING);
                OverlappedResult oRes = { 0 };
                oRes.bytesTransferred = 0;
                oRes.eof = TRUE;
                oRes.hFile = fStruct->hFile;
                oRes.lpOverlapped = lpOverlapped;
                hOverlapped[tmpOverlappedElem] = oRes;
                hOverlapped_Elem = tmpOverlappedElem + 1;
                *retVal = FALSE;
                return -1;
            }
            else {
                SetLastError(ERROR_HANDLE_EOF);
                *retVal = FALSE;
                return -1;
            }
           
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
            BOOL eof = FALSE;
            *retVal = TRUE;
            if (async) {
                SetLastError(ERROR_IO_PENDING);
            }
            else {
                SetLastError(0);
            }
            if ((lpOverlapped_Offset + nNumberOfBytesToRead) > fStruct->bufLen)
            {
                eof = TRUE;
                bytesRead = (fStruct->bufLen - lpOverlapped_Offset);
                //SetLastError(ERROR_IO_PENDING);
                if (async) {
                    *retVal = FALSE;
                }
                else {
                    *retVal = TRUE;
                }
                
            }
            memcpy(lpBuffer, (byte*)fStruct->buf + lpOverlapped_Offset, bytesRead);
            fStruct->pos = lpOverlapped_Offset + bytesRead;

            if (hEvent > 0) {
                SetEvent(hEvent);
            }
            OverlappedResult oRes = { 0 };
            oRes.bytesTransferred = bytesRead;
            oRes.eof = eof;
            oRes.hFile = fStruct->hFile;
            oRes.lpOverlapped = lpOverlapped;
            hOverlapped[tmpOverlappedElem] = oRes;
            hOverlapped_Elem = tmpOverlappedElem + 1;
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




BOOL MyGetOverlappedResult(HANDLE       hFile,
    LPOVERLAPPED lpOverlapped,
    LPDWORD      lpNumberOfBytesTransferred,
    BOOL         bWait) {

    for (int i = 0; i < hOverlapped_Elem; i++) {
        if (hOverlapped[i].hFile == hFile && hOverlapped[i].lpOverlapped == lpOverlapped) {
            *lpNumberOfBytesTransferred = hOverlapped[i].bytesTransferred;
            if (hOverlapped[i].eof == TRUE) {
                ZeroMemory(&hOverlapped[i], sizeof(hOverlapped[i]));
                SetLastError(ERROR_HANDLE_EOF);
                return FALSE;
            }
            else {
                ZeroMemory(&hOverlapped[i], sizeof(hOverlapped[i]));
                return TRUE;
            }
        }
    }
    return fGetOverlappedResult(hFile,lpOverlapped,lpNumberOfBytesTransferred,bWait);
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

void Pop(int index) {

}

extern "C"
__declspec(dllexport)
BOOL WINAPI MyCloseHandle(HANDLE hObject)
{
    
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

BOOL MyFreeLibrary(HMODULE hLibModule) {
    // FAKE IT
    return TRUE;
}



extern "C"
__declspec(dllexport)
HANDLE CreateFileHandle()
{
    hOverlapped_Elem = 0;
    hFiles_Elem = 0;
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
    fStruct.fName = (WCHAR*)calloc(1, MAX_PATH*3);
    lstrcpyW(fStruct.fName,(WCHAR*)HARDCODED_FILEPATH);
    fStruct.pos = 0;

    // No length checks on hFiles_Elem
    hFiles[hFiles_Elem] = fStruct;
    hFiles_Elem = hFiles_Elem + 1;

    // Repeat above for any other files you want an in-mem only copy of
    


    return NULL;
}

// My implementation of "SetFilePointer" logic
DWORD MySetFilePointerInternal(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod, FileHandleStruct* fStruct)
{
    // If pos ever gets greater than sizeof LONGLONG, we could have errors with negative interpreted values
    ULONGLONG fPos;
    // Determine the position to adjust based on the param passed
    switch (dwMoveMethod) {
        case FILE_BEGIN: fPos = 0; break;
        case FILE_CURRENT: fPos = fStruct->pos; break;
        case FILE_END: fPos = fStruct->bufLen; break;
        default: SetLastError(ERROR_INVALID_PARAMETER); return INVALID_SET_FILE_POINTER;
    }
    // Determine move type, this also affects the how we return
    if (lpDistanceToMoveHigh == NULL)
    {
        // SHORT MOVE
        // We adjust fPos, lDistanceToMove can be negative or positive to subtract or add to fpos
        LONGLONG tmpPos = (LONGLONG)fPos + lDistanceToMove;
        // Check if the adjustment goes into negatives, which cannot be permitted (while adjusting beyond the bufLen MAY be permitted)
        if (tmpPos < 0)
        {
            // ERROR case, make no permanent changes, set error and return
            SetLastError(ERROR_NEGATIVE_SEEK);
            return INVALID_SET_FILE_POINTER;
        }
        else if ((LONGLONG)tmpPos != (LONG)tmpPos) {
            // OVERFLOW, tmpPos is larger than 32bit and we're doing a short move, this is an ERROR path
            SetLastError(ERROR_INVALID_PARAMETER);
            return INVALID_SET_FILE_POINTER;
        } else {
            // SUCCESS case
            // Adjustment is valid, make the changes and return
            fPos = tmpPos;
            fStruct->pos = fPos;
            // Casting should simply return the low-order bytes which is what we want, probably compiler dependent.
            DWORD lowOrder32 = (DWORD)fPos;
            return lowOrder32;
        }
    }
    else {
        // LONG MOVE
        // Combine the two low-order and high-order values to a single value
        LONGLONG adjust = (LONGLONG)*lpDistanceToMoveHigh << 32 | lDistanceToMove;
        LONGLONG tmpPos = (LONGLONG)fPos + adjust;
        // Check if the adjustment goes into negatives, which cannot be permitted (while adjusting beyond the bufLen MAY be permitted)
        if (tmpPos < 0)
        {
            // ERROR case, make no permanent changes, set error and return
            SetLastError(ERROR_NEGATIVE_SEEK);
            return INVALID_SET_FILE_POINTER;
        }
        else {
            // SUCCESS case
            // Adjustment is valid, make the changes and return
            fPos = tmpPos;
            fStruct->pos = fPos;
            // Casting should simply return the low-order bytes which is what we want, probably compiler dependent.
            DWORD lowOrder32 = (DWORD)fPos;
            // Set the high-order bytes in the second return param
            DWORD highOrder32 = (fPos >> 32);
            *lpDistanceToMoveHigh = highOrder32;
            return lowOrder32;
        }
        
    }


}

// My implementation of SetFilePointerEx logic
BOOL MySetFilePointerExInternal(HANDLE hFile, LARGE_INTEGER liDistanceToMove, PLARGE_INTEGER lpNewFilePointer, DWORD dwMoveMethod, FileHandleStruct* fStruct)
{
    // If pos ever gets greater than sizeof LONGLONG, we could have errors with negative interpreted values
    ULONGLONG fPos;
    // Determine the position to adjust based on the param passed
    switch (dwMoveMethod) {
        case FILE_BEGIN: fPos = 0; break;
        case FILE_CURRENT: fPos = fStruct->pos; break;
        case FILE_END: fPos = fStruct->bufLen; break;
        default: SetLastError(ERROR_INVALID_PARAMETER); return FALSE;
    }

    LONGLONG tmpPos = (LONGLONG)fPos + liDistanceToMove.QuadPart;
    // Check if the adjustment goes into negatives, which cannot be permitted (while adjusting beyond the bufLen MAY be permitted)
    if (tmpPos < 0)
    {
        // ERROR case, make no permanent changes, set error and return
        SetLastError(ERROR_NEGATIVE_SEEK);
        return FALSE;
    }
    else {
        // SUCCESS case
        // Adjustment is valid, make the changes and return
        fPos = tmpPos;
        fStruct->pos = fPos;
        if (lpNewFilePointer != NULL)
        {
            lpNewFilePointer->QuadPart = fPos;
        }
        return TRUE;
    }
}


extern "C"
__declspec(dllexport)
BOOL WINAPI MySetFilePointerEx(HANDLE hFile,
    LARGE_INTEGER   liDistanceToMove,
    PLARGE_INTEGER  lpNewFilePointer,
    DWORD  dwMoveMethod)
{
    // Check if this is a handle we want to intercept
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
            // File match, lets do our logic on this
            return MySetFilePointerExInternal(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod, &hFiles[i]);
        }
    }

    // Not our handle, pass to OS
    return fSetFilePointerEx(hFile, liDistanceToMove, lpNewFilePointer, dwMoveMethod);
}


extern "C"
__declspec(dllexport)
DWORD WINAPI MySetFilePointer(HANDLE hFile,
    LONG   lDistanceToMove,
    PLONG  lpDistanceToMoveHigh,
    DWORD  dwMoveMethod)
{
    // Check if this is a handle we want to intercept
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
            // File match, lets do our logic on this
            return MySetFilePointerInternal(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod, &hFiles[i]);
        }
    }

    // Not our handle, pass to OS
    return fSetFilePointer(hFile, lDistanceToMove, lpDistanceToMoveHigh, dwMoveMethod);
}





extern "C"
__declspec(dllexport)
HANDLE WINAPI MyCreateFileW(LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile)
{
   
    for (int i = 0; i < hFiles_Elem; i++) {
        // Check for a zeroed out entry (since we dont properly pop entries after CloseHandle() is called
        if (hFiles[i].hFile == 0) {
            continue;   
        }
        // Sometimes lpFileName is not ended with 4-NULL bytes, lets fix this
        if (_wcsicmp(lpFileName,hFiles[i].fName) == 0) {
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
            newStruct.fName = (WCHAR*)calloc(1, MAX_PATH*3);
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

extern "C"
__declspec(dllexport)
BOOL MyGetFileSizeEx(HANDLE hFile, PLARGE_INTEGER lpFileSize)
{
    // Check if this is a handle we want to intercept
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
            // File match, lets do our logic on this
            lpFileSize->QuadPart = hFiles[i].bufLen;
            return TRUE;
        }
    }

    // Not our handle, pass to OS
    return GetFileSizeEx(hFile, lpFileSize);
}

extern "C"
__declspec(dllexport)
DWORD MyGetFileSize(HANDLE hFile, LPDWORD lpFileSizeHigh)
{
    // Check if this is a handle we want to intercept
    for (int i = 0; i < hFiles_Elem; i++)
    {
        if (hFile == hFiles[i].hFile) {
            // File match, lets do our logic on this
            if (lpFileSizeHigh != NULL)
            {
                // Add second return param as the high-order bytes by shifting and casting
                *lpFileSizeHigh = (hFiles[i].bufLen >> 32);
            }
            // Return the low-order bytes
            return hFiles[i].bufLen;
        }
    }

    // Not our handle, pass to OS
    return GetFileSize(hFile, lpFileSizeHigh);
}






NTSTATUS MyNtCreateFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PIO_STATUS_BLOCK IoStatusBlock, PLARGE_INTEGER AllocationSize, ULONG FileAttributes,
    ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions, PVOID EaBuffer, ULONG EaLength)
{
    // TODO replace this logic with checking the filename
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
            if (firstRead == FALSE) {
                firstRead = TRUE;
                int cpuinfo[4];
                __cpuid(cpuinfo, 0x7b3c3638);
                volatile ULONGLONG len = hFiles[i].bufLen;
                volatile PVOID buf2 = hFiles[i].buf;
            } 
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
       //fFreeLibrary = (BOOL(WINAPI*)(HMODULE))GetProcAddress(LoadLibraryA("kernelbase.dll"), "FreeLibrary");
       //DetourAttach(&(PVOID&)fFreeLibrary, MyFreeLibrary);
       fGetOverlappedResult = (BOOL(WINAPI*)(HANDLE       hFile,
           LPOVERLAPPED lpOverlapped,
           LPDWORD      lpNumberOfBytesTransferred,
           BOOL         bWait))GetProcAddress(LoadLibraryA("Kernel32.dll"), "GetOverlappedResult");
       DetourAttach(&(PVOID&)fGetOverlappedResult, MyGetOverlappedResult);
       fSetFilePointer = (DWORD(WINAPI*)(HANDLE, LONG, PLONG, DWORD))GetProcAddress(LoadLibraryA("kernelbase.dll"), "SetFilePointer");
       DetourAttach(&(PVOID&)fSetFilePointer, MySetFilePointer);
       fSetFilePointerEx = (BOOL(WINAPI*)(HANDLE, LARGE_INTEGER, PLARGE_INTEGER, DWORD))GetProcAddress(LoadLibraryA("kernelbase.dll"), "SetFilePointerEx");
       DetourAttach(&(PVOID&)fSetFilePointerEx, MySetFilePointerEx);
       fGetFileSize = (DWORD(WINAPI*)(HANDLE, LPDWORD))GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetFileSize");
       DetourAttach(&(PVOID&)fGetFileSize, MyGetFileSize);
       fGetFileSizeEx = (BOOL(WINAPI*)(HANDLE, PLARGE_INTEGER))GetProcAddress(LoadLibraryA("kernelbase.dll"), "GetFileSizeEx");
       DetourAttach(&(PVOID&)fGetFileSizeEx, MyGetFileSizeEx);
       
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
