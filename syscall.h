#include "stdafx.h"

namespace syscalls {
#define RVA2VA(type, base, rva) (type)((uintptr_t)base + rva)
#define VA2RVA(type, base, va) (type)((uintptr_t)va - (uintptr_t)base)

    struct syscall_context {
        uint32_t m_shellcode_size;
        uint8_t* m_shellcode;

#ifdef USE_ENCRYPTION
        uint8_t m_encryption_key = 0;
        bool m_encrypted = false;
#endif
    };

    struct syscall_generation {
        std::string m_module_name = "";
        bool m_use_disk = false;

        syscall_generation(std::string name, bool disk = false) {
            m_module_name = name;
            m_use_disk = disk;
        }
    };
    
    enum eSyscallErrors {
        ERROR_MODULE_NAME_EMPTY,
        ERROR_GET_MODULE_HANDLE_FAILED,
        ERROR_GET_FILE_NAME_FAILED,
        ERROR_FAILED_TO_OPEN,
        ERROR_FAILED_DISK_ALLOC,
        ERROR_FAILED_HEADER_CHECK,
        ERROR_MODULE_NOT_LOADED,
        ERROR_NT_HEADER_FAILED,
        ERROR_DATA_DIR_FAILED,
    };

    class syscall {
    public:
        bool generate(syscall_generation module_info, std::vector<std::string> function_names);
        syscall_context* get_context(const char* function_name);
        void encrypt_context(syscall_context* context);
        void decrypt_context(syscall_context* context);
        void cleanup();

        eSyscallErrors get_last_error();
        std::string get_last_error_string();
    private:
        std::unordered_map<uint32_t, syscall_context> m_functions;
        eSyscallErrors m_last_error;
        uint32_t m_current_index = 0;

        #ifdef NO_WIN32_CALLS
        uint8_t m_page[0x1000];
        #else
        uint8_t* m_page;
        #endif

    private:
        uintptr_t find_raw(PIMAGE_NT_HEADERS nt, uintptr_t va);
        uint32_t create_hash(const char* string);
        uint32_t get_syscall_index(uintptr_t address);
        std::pair<uint8_t*, uint32_t> create_asm(uint32_t index);

        template<typename T>
		T find_raw_pointer(PIMAGE_NT_HEADERS nt, uint8_t* memory, uintptr_t va) {
			return (T)((uintptr_t)memory + find_raw(nt, va));
		}
    };

    syscall* get_syscall();

    inline bool generate(syscall_generation module_info, std::vector<std::string> function_names) {
        return get_syscall()->generate(module_info, function_names);
    }

    inline eSyscallErrors get_last_error() {
        return get_syscall()->get_last_error();
    }

    inline std::string get_last_error_string() {
        return get_syscall()->get_last_error_string();
    }

    inline syscall_context* get_context(const char* function_name) {
        return get_syscall()->get_context(function_name);
    }

    inline void encrypt_context(syscall_context* context) {
        return get_syscall()->encrypt_context(context);
    }

    inline void decrypt_context(syscall_context* context) {
        return get_syscall()->decrypt_context(context);
    }

    inline void cleanup() {
        get_syscall()->cleanup();
    }
}
