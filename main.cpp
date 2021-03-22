#include "stdafx.h"
#include "syscall.h"
#include "wrapper.h"

int main() {
    bool init_ntdll = syscalls::generate({ "ntdll.dll" }, {
        "NtQueryVirtualMemory",
        "NtQueryInformationProcess",
        "NtOpenProcess",
        "NtResumeThread"
    });

    if (init_ntdll) {
        NTSTATUS status = 0;
		uint64_t current_scan_address = 0;
		MEMORY_BASIC_INFORMATION page_information = { 0 };
		SIZE_T out_length = 0;

        printf("==== TESTING NTDLL ====\n");
		while ((status = syscalls::wrapper::NtQueryVirtualMemory(GetCurrentProcess(), (void*)current_scan_address, 0, &page_information, sizeof(page_information), &out_length)) == 0) {
			printf("[Page] 0x%llx with size 0x%llx\n", page_information.BaseAddress, page_information.RegionSize);
			current_scan_address += page_information.RegionSize;
			memset(&page_information, 0, sizeof(page_information));
		}
    } else {
        printf("[!] Failed to initialize ntdll syscalls, last error: %s\n", syscalls::get_last_error_string().c_str());
    }

    bool init_win32u = syscalls::generate({ "C:\\Windows\\System32\\win32u.dll", true }, {
        "NtUserGetAsyncKeyState"        
    });

    if (init_win32u) {
        printf("==== TESTING WIN32U ====\n");

        CreateThread(0, 0, [](LPVOID) -> DWORD {
            while (true) {
                if (syscalls::wrapper::NtUserGetAsyncKeyState(VK_F1) & 0x1) {
                    printf("F1 is being pressed!\n");
                }
            }

            return 0;
        }, 0, 0, 0);
    } else {
        printf("[!] Failed to initialize win32u syscalls, last error: %s\n", syscalls::get_last_error_string().c_str());
    }

    // comment this in for your project!
    // syscalls::cleanup();

    return 0;
}