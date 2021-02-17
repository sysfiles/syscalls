#define _CRT_SECURE_NO_WARNINGS

#include <Windows.h>
#include <iostream>
#include <unordered_map>
#include <sstream>
#include <iomanip>

std::string convert_bytes_to_string(uint8_t* data, uint32_t length) {
	std::stringstream str;
	str.setf(std::ios_base::hex, std::ios::basefield);
	str.setf(std::ios_base::uppercase);
	str.fill('0');

	for (uint32_t i = 0; i < length; ++i) {
		str << std::setw(2) << (unsigned short)data[i];

		if (i != length - 1) {
			str << " ";
		}
	}

	return str.str();
}

namespace syscalls {
#define RVA2VA(type, base, rva) (type)((uintptr_t)base + rva)
#define VA2RVA(type, base, va) (type)((uintptr_t)va - (uintptr_t)base)

	struct SyscallContext {
		uint32_t m_index;
		uintptr_t m_shellcode;
	};

	class Syscalls {
	public:
		bool load_exports(bool use_disk = true, const char* direct_path = NULL) {
			uint8_t* memory = nullptr;

			if (use_disk) {
				char path[MAX_PATH];

				if (direct_path != NULL) {
					// using custom direct path
					strcpy_s(path, direct_path);
				} else {
					if (GetModuleHandleA("ntdll.dll") > 0) {
						if (!GetModuleFileNameA(GetModuleHandleA("ntdll.dll"), path, MAX_PATH)) {
							printf("GetModuleFileNameA() failed!\n");
							return false;
						}
					} else {
						printf("GetModuleHandleA() failed, and direct_path was NULL!\n");
						return false;
					}
				}

				FILE* fp;
				fopen_s(&fp, path, "rb");
				if (fp) {
					fseek(fp, 0, SEEK_END);
					long file_size = ftell(fp);
					fseek(fp, 0, SEEK_SET);

					memory = (uint8_t*)VirtualAlloc(0, file_size, MEM_COMMIT, PAGE_READWRITE);
					if (memory) {
						fread(memory, 1, file_size, fp);
						fclose(fp);

						// sanity
						if (memory[0] != 'M' || memory[1] != 'Z') {
							printf("Executable sanity failed!\n");
							return false;
						}
					} else {
						printf("VirtualAlloc() failed!\n");
						return false;
					}
				} else {
					printf("fopen_s() failed!\n");
					return false;
				}
			} else {
				if (GetModuleHandleA("ntdll.dll") > 0) {
					memory = (uint8_t*)GetModuleHandleA("ntdll.dll");
				} else {
					printf("GetModuleHandleA() failed, and direct_path was NULL!\n");
					return false;
				}
			}

			PIMAGE_NT_HEADERS nt = RVA2VA(PIMAGE_NT_HEADERS, memory, ((PIMAGE_DOS_HEADER)memory)->e_lfanew);
			if (!nt) {
				printf("Failed getting NT\n");
				return false;
			}

			PIMAGE_DATA_DIRECTORY data_directory = nt->OptionalHeader.DataDirectory;
			uint32_t export_va = data_directory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;

			if (use_disk) {
				PIMAGE_EXPORT_DIRECTORY exports = find_raw_pointer<PIMAGE_EXPORT_DIRECTORY>(nt, memory, export_va);
				if (exports) {
					uint16_t* name_ordinals = find_raw_pointer<uint16_t*>(nt, memory, exports->AddressOfNameOrdinals);
					uint32_t* functions = find_raw_pointer<uint32_t*>(nt, memory, exports->AddressOfFunctions);
					uint32_t* names = find_raw_pointer<uint32_t*>(nt, memory, exports->AddressOfNames);

					if (name_ordinals && functions && names) {
						for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
							const char* export_name = find_raw_pointer<const char*>(nt, memory, names[i]);
							if (export_name) {
								if (export_name[0] == 'Z' && export_name[1] == 'w') {
									uint32_t offset = functions[name_ordinals[i]];
									if (offset) {
										uintptr_t export_address = find_raw_pointer<uintptr_t>(nt, memory, offset);
										if (export_address) {
											printf("[Disk][%s]: %i\n", export_name, get_disk_index(export_address, export_name));
											m_syscall_exports.push_back({ create_hash(export_name), get_disk_index(export_address, export_name) });
										}
									}
								}
							}
						}
					}
				}
			} else {
				PIMAGE_EXPORT_DIRECTORY exports = RVA2VA(PIMAGE_EXPORT_DIRECTORY, memory, export_va);
				if (exports) {
					uint16_t* name_ordinals = RVA2VA(uint16_t*, memory, exports->AddressOfNameOrdinals);
					uint32_t* functions = RVA2VA(uint32_t*, memory, exports->AddressOfFunctions);
					uint32_t* names = RVA2VA(uint32_t*, memory, exports->AddressOfNames);

					if (name_ordinals && functions && names) {
						for (uint32_t i = 0; i < exports->NumberOfFunctions; i++) {
							const char* export_name = RVA2VA(const char*, memory, names[i]);
							if (export_name) {
								if (export_name[0] == 'Z' && export_name[1] == 'w') {
									uint32_t offset = functions[RVA2VA(uint16_t, memory, name_ordinals[i])];
									if (offset) {
										printf("[Memory][%s]: %i\n", export_name, get_disk_index((uintptr_t)memory + offset, export_name));
										m_syscall_exports.push_back({ create_hash(export_name), get_disk_index((uintptr_t)memory + offset, export_name) });
									}
								}
							}
						}
					}
				}
			}

			if (use_disk) VirtualFree(memory, 0, MEM_RELEASE);
			return true;
		}

		bool create_functions(std::vector<const char*> function_names) {
			uint32_t block_size = sizeof(SyscallContext) * function_names.size();

			m_page = (uint8_t*)VirtualAlloc(0, block_size, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
			if (m_page) {
				memset(m_page, 0, block_size);

				int current_index = 0;
				for (auto& name : function_names) {
					uint32_t hash = create_hash(get_translated_name(name));

					auto vit = std::find_if(begin(m_syscall_exports), end(m_syscall_exports), [=](std::pair<uint32_t, uint32_t> p) { return p.first == hash; });
					if (vit != end(m_syscall_exports)) {
						// create
						std::pair<const char*, int> syscall = create_syscall(vit->second);

						SyscallContext context;
						context.m_index = vit->second;
						context.m_shellcode = (uintptr_t)&m_page[current_index++ * block_size];
						memcpy((void*)context.m_shellcode, syscall.first, syscall.second);
						m_functions[hash] = context;

						printf("[Create]: %s - %s\n", name, convert_bytes_to_string((uint8_t*)context.m_shellcode, syscall.second).c_str());

						delete[] syscall.first;
						continue;
					}

					printf("Failed to find ordinal for %s\n", name);
				}

				return true;
			}
			
			return false;
		}

		std::pair<char*, int> create_syscall(int index) {
			// TODO: version checks

			// for now, windows10...
			std::pair<char*, int> context;
			context.second = 11;
			context.first = new char[11];
			memcpy(context.first, "\x4C\x8B\xD1\xB8\xFF\xFF\xFF\xFF\x0F\x05\xC3", 11);
			*(uint32_t*)(&context.first[4]) = index;

			return context;
		}

		uint32_t get_disk_index(uintptr_t address, const char* export_name) {
			// TODO: version checks
			if (address) {
				// for now, windows10...
				if (*(uint8_t*)address == 0x49 || *(uint8_t*)address == 0x4C) {
					return *(uint32_t*)(address + 0x4);
				}
			}

			return 0;
		}

		void cleanup() {
			if (m_page) {
				VirtualFree(m_page, 0, MEM_RELEASE);
			}
		}

		uintptr_t get_function(const char* function_name) {
			return m_functions[create_hash(get_translated_name(function_name))].m_shellcode;
		}

		std::vector<std::pair<uint32_t, uint32_t>>& get_syscall_exports() {
			return m_syscall_exports;
		}

		std::unordered_map<uint32_t, SyscallContext>& get_functions() {
			return m_functions;
		}
	private:
		std::vector<std::pair<uint32_t, uint32_t>> m_syscall_exports;
		std::unordered_map<uint32_t, SyscallContext> m_functions;
		uint8_t* m_page;

		uint32_t create_hash(const char* string) {
			uint32_t hash = 0x811c9dc5;

			for (int i = 0; i < strlen(string); ++i) {
				uint8_t value = string[i];
				hash = hash ^ value;
				hash *= 0x1000193;
			}

			return hash;
		}

		uintptr_t find_raw(PIMAGE_NT_HEADERS nt, uintptr_t va) {
			PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt);
			for (uint16_t i = 0; i < nt->FileHeader.NumberOfSections; i++) {
				if (va >= section->VirtualAddress && va <= (section->VirtualAddress + section->Misc.VirtualSize)) {
					uintptr_t offset = va - section->VirtualAddress;
					uintptr_t raw_address = section->PointerToRawData + offset;
					return raw_address;
				}

				section++;
			}

			return 0;
		}

		template<typename T>
		T find_raw_pointer(PIMAGE_NT_HEADERS nt, uint8_t* memory, uintptr_t va) {
			return (T)((uintptr_t)memory + find_raw(nt, va));
		}

		const char* get_translated_name(const char* function_name) {
			static char name[0x50];
			if (function_name) {
				if (function_name[0] == 'N' && function_name[1] == 't') {
					strcpy_s(name, function_name);
					name[0] = 'Z';
					name[1] = 'w';
					return name;
				}
			}

			return function_name;
		}
	};

	Syscalls* get_syscalls() {
		static Syscalls instance;
		return &instance;
	}

	// f**k using get_syscalls everywhere
	bool load_exports(bool use_disk, const char* direct_path = NULL) {
		return get_syscalls()->load_exports(use_disk, direct_path);
	}

	bool create_functions(std::vector<const char*> function_names) {
		return get_syscalls()->create_functions(function_names);
	}

	void cleanup() {
		get_syscalls()->cleanup();
	}

	uintptr_t get_function(const char* function_name) {
		return get_syscalls()->get_function(function_name);
	}

	std::vector<std::pair<uint32_t, uint32_t>>& get_syscall_exports() {
		return get_syscalls()->get_syscall_exports();
	}

	std::unordered_map<uint32_t, SyscallContext>& get_functions() {
		return get_syscalls()->get_functions();
	}

	// example functions
	NTSTATUS NtQueryVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, int MemoryInformationClass, PVOID MemoryInformation, SIZE_T MemoryInformationLength, PSIZE_T ReturnLength) {
		return ((NTSTATUS(*)(...))get_function("NtQueryVirtualMemory"))(ProcessHandle, BaseAddress, MemoryInformationClass, MemoryInformation, MemoryInformationLength, ReturnLength);
	}
}

int main() {
	if (syscalls::load_exports(true, "C://Windows//System32//ntdll.dll")) {
		printf("Total: %i\n", syscalls::get_syscall_exports().size());

		bool success = syscalls::create_functions({
			"NtQueryVirtualMemory",
			"NtQueryInformationProcess",
			"NtOpenProcess",
			"NtResumeThread"
		});
		
		printf("Create: %i\n", success);

		printf("=== NtQueryVirtualMemory ===\n");

		NTSTATUS status = 0;
		uint64_t current_scan_address = 0;
		MEMORY_BASIC_INFORMATION page_information = { 0 };
		SIZE_T out_length = 0;

		while ((status = syscalls::NtQueryVirtualMemory(GetCurrentProcess(), (void*)current_scan_address, 0, &page_information, sizeof(page_information), &out_length)) == 0) {
			printf("[Page] 0x%llx with size 0x%llx\n", page_information.BaseAddress, page_information.RegionSize);
			current_scan_address += page_information.RegionSize;
			memset(&page_information, 0, sizeof(page_information));
		}
	}

	syscalls::cleanup();
	system("pause");
}