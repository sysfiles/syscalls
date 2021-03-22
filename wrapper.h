#include "stdafx.h"

namespace syscalls::wrapper {
    NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength);
    uint16_t NtUserGetAsyncKeyState(uint32_t virtual_key);
}