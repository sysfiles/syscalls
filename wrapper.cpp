#include "wrapper.h"
#include "syscall.h"

namespace syscalls::wrapper {
    // update the size each time
    std::mutex m_mutex[2];
    
    NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
        NTSTATUS return_ = 0;

        syscalls::syscall_context* context = syscalls::get_context("NtQueryVirtualMemory");
        if (context) {
            m_mutex[0].lock();
            syscalls::decrypt_context(context);

            return_ = ((NTSTATUS(*)(...))context->m_shellcode)(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);

            syscalls::encrypt_context(context);
            m_mutex[0].unlock();

            return return_;
        }

        return 1;
    }

    uint16_t NtUserGetAsyncKeyState(uint32_t virtual_key) {
        uint16_t return_ = 0;

        syscalls::syscall_context* context = syscalls::get_context("NtUserGetAsyncKeyState");
        if (context) {
            m_mutex[1].lock();
            syscalls::decrypt_context(context);

            return_ = ((uint16_t(*)(...))context->m_shellcode)(virtual_key);

            syscalls::encrypt_context(context);
            m_mutex[1].unlock();
        }

        return return_;
    }
}