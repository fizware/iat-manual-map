#include <iostream>
#include <io.h>

#include "mmap.h"
#include "mem.h"
#include "proc.h"
#include "xor.h"
#include "api_hook.h"

PIMAGE_SECTION_HEADER get_enclosing_section_header(uint64_t rva, PIMAGE_NT_HEADERS nt_header)
{
	
	IMAGE_SECTION_HEADER* section;
	int i = 0;

	section = IMAGE_FIRST_SECTION(nt_header);

	for (i = 0; i < nt_header->FileHeader.NumberOfSections; i++, section++)
	{
		uint64_t size = 0;

		size = section->Misc.VirtualSize;

		if (!size)
			size = section->SizeOfRawData;

		if ((rva >= section->VirtualAddress) && (rva < (section->VirtualAddress + size)))
			return section;
	}
	
	return 0;
}

uint64_t* get_ptr_from_rva(uint64_t rva, IMAGE_NT_HEADERS* nt_header, uint8_t* image_base)
{
	
	IMAGE_SECTION_HEADER* section_header;
	long long delta = 0;

	section_header = get_enclosing_section_header(rva, nt_header);

	if (!section_header)
		return 0;

	delta = (long long)(section_header->VirtualAddress - section_header->PointerToRawData);
	
	return (uint64_t*)(image_base + rva - delta);
}

uint64_t get_proc_address(const char* module_name, const char* func)
{
	
	uint64_t remote_module = 0;
	uint64_t local_module = 0;
	uint64_t delta = 0;

	remote_module = get_module_base(module_name);
	local_module = (uint64_t)GetModuleHandle(module_name);
	delta = (uint64_t)(remote_module - local_module);
	
	return ((uint64_t)GetProcAddress((HMODULE)local_module, func) + delta);
}

void solve_imports(uint8_t* base, IMAGE_NT_HEADERS* nt_header, IMAGE_IMPORT_DESCRIPTOR* import_descriptor)
{
	
	char* module;

	while ((module = (char*)get_ptr_from_rva((uint64_t)(import_descriptor->Name), nt_header, base)))
	{
		HMODULE local_module;
		IMAGE_THUNK_DATA* thunk_data;

		local_module = LoadLibrary(module);

		thunk_data = (IMAGE_THUNK_DATA*)get_ptr_from_rva((uint64_t)(import_descriptor->FirstThunk), nt_header, base);

		while (thunk_data->u1.AddressOfData)
		{
			IMAGE_IMPORT_BY_NAME* iibn;

			iibn = (IMAGE_IMPORT_BY_NAME*)get_ptr_from_rva((uint64_t)((thunk_data->u1.AddressOfData)), nt_header, base);

			thunk_data->u1.Function = (uint64_t)(get_proc_address(module, (char*)iibn->Name));
			thunk_data++;
		}

		import_descriptor++;
	}
	
	return;
}

void solve_relocations(uint64_t base, uint64_t relocation_base, IMAGE_NT_HEADERS* nt_header, IMAGE_BASE_RELOCATION* reloc, size_t size)
{
	
	uint64_t image_base = 0;
	uint64_t delta = 0;
	unsigned int bytes = 0;

	image_base = nt_header->OptionalHeader.ImageBase;
	delta = (uint64_t)(relocation_base - image_base);

	while (bytes < size)
	{
		uint64_t* reloc_base;
		uint64_t num_of_relocations = 0;
		uint16_t* reloc_data;
		unsigned int i = 0;

		reloc_base = (uint64_t*)get_ptr_from_rva((uint64_t)(reloc->VirtualAddress), nt_header, (uint8_t*)base);
		num_of_relocations = (reloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
		reloc_data = (uint16_t*)((uint64_t)reloc + sizeof(IMAGE_BASE_RELOCATION));

		for (i = 0; i < num_of_relocations; i++)
		{
			if (((*reloc_data >> 12) & IMAGE_REL_BASED_HIGHLOW))
				*(uint64_t*)((uint64_t)reloc_base + ((uint64_t)(*reloc_data & 0x0FFF))) += delta;

			reloc_data++;
		}

		bytes += reloc->SizeOfBlock;
		reloc = (IMAGE_BASE_RELOCATION*)reloc_data;
	}
	
	return;
}

void map_pe_sections(uint64_t base, IMAGE_NT_HEADERS* nt_header, inject_info* ptr)
{
	
	IMAGE_SECTION_HEADER* header;
	size_t virtual_size = 0;
	size_t bytes = 0;

	header = IMAGE_FIRST_SECTION(nt_header);

	while (nt_header->FileHeader.NumberOfSections && (bytes < nt_header->OptionalHeader.SizeOfImage))
	{
		write_memory(base + header->VirtualAddress, (uint64_t)(ptr->buf + header->PointerToRawData), header->SizeOfRawData);
		virtual_size = header->VirtualAddress;
		virtual_size = (++header)->VirtualAddress - virtual_size;
		bytes += virtual_size;

		// virtual_protect((uint64_t)(base + header->VirtualAddress), virtual_size, header->Characteristics & 0x00FFFFFF, &old);
	}
	
	return;
}

BOOL inject(inject_info* ptr, BOOL erase_pe_headers)
{
	
	IMAGE_DOS_HEADER* dos_header;
	IMAGE_NT_HEADERS* nt_headers;
	uint64_t base = 0;
	uint64_t stub_base = 0;
	uint64_t function_copy = 0;
	IMAGE_IMPORT_DESCRIPTOR* import_descriptor;
	IMAGE_BASE_RELOCATION* base_relocation;
	uint64_t entry_point = 0;
	uint64_t function_addr = 0;
	char* str;
	ULONG old_protection = 0;
	ULONG prot = 0;
	uint64_t target_base = 0;
	int i = 0;
	void* copied_func = NULL;
	uint8_t* stub_heap = NULL;
	mem* m;
	uint64_t iat_function_ptr = 0;
	IMAGE_SECTION_HEADER* section_header;
	ULONG old = 0;

	uint8_t stub[157] = { 0x51, 0x52, 0x55, 0x56, 0x53, 0x57, 0x41, 0x50, 0x41, 0x51, 0x41, 0x52, 0x41
, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x31, 0xc9, 0x48, 0x31, 0xf6, 0x48,
0x31, 0xff, 0x48, 0xb9, 0xcc, 0xbb, 0xff, 0xaa, 0xbb, 0xee, 0xdd, 0xcc, 0x48, 0xbe, 0xbb, 0xaa, 0xff, 0xee, 0xdd, 0xcc, 0xbb, 0xaa, 0x48, 0xbf, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0xaa, 0xbb, 0xa4
, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0xa4, 0x48, 0x31, 0xc9,
0x48, 0x31, 0xc0, 0x48, 0xb9, 0xaa, 0xbb, 0xcc, 0xdd, 0xbb, 0xaa, 0xff, 0xee, 0x48, 0xb8, 0xdd, 0xaa, 0xcc, 0xbb, 0xaa, 0xff, 0xee, 0xdd, 0x48, 0x31, 0xd2, 0x48, 0x83, 0xc2, 0x01, 0x4d, 0x31, 0xc0
, 0x49, 0xb8, 0xaa, 0xee, 0xbb, 0xcc, 0xff, 0xdd, 0xbb, 0xaa, 0x48, 0x83, 0xec, 0x28, 0xff, 0xd0,
0x48, 0x83, 0xc4, 0x28, 0x41, 0x5f, 0x41, 0x5e, 0x41, 0x5d, 0x41, 0x5c, 0x41, 0x5b, 0x41, 0x5a, 0x41, 0x59, 0x41, 0x58, 0x5f, 0x5b, 0x5e, 0x5d, 0x5a, 0x59, 0x48, 0x31, 0xc0, 0xc3 };


	target_base = get_module_base(ptr->target_mod); // Retrieve the target base
	if (!target_base)
	{
		return FALSE;
	}

	dos_header = (IMAGE_DOS_HEADER*)ptr->buf;

	if (dos_header->e_magic != IMAGE_DOS_SIGNATURE)
	{
		return FALSE;
	}

	nt_headers = (IMAGE_NT_HEADERS*)(ptr->buf + dos_header->e_lfanew);

	if (nt_headers->Signature != IMAGE_NT_SIGNATURE)
	{
		return FALSE;
	}

	section_header = IMAGE_FIRST_SECTION(nt_headers);

	base = virtual_alloc(nt_headers->OptionalHeader.SizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL);
	if (!base)
	{
		return FALSE;
	}

	import_descriptor = (IMAGE_IMPORT_DESCRIPTOR*)get_ptr_from_rva((uint64_t)(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress), nt_headers, ptr->buf);

	if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		solve_imports(ptr->buf, nt_headers, import_descriptor);

	base_relocation = (IMAGE_BASE_RELOCATION*)get_ptr_from_rva(nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_headers, ptr->buf);

	if (nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size)
		solve_relocations((uint64_t)ptr->buf, base, nt_headers, base_relocation, nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size);

	function_addr = get_proc_address(ptr->target_lib, ptr->target_func);
	if (!function_addr)
	{
		return FALSE;
	}

	// Copy the original bytes of the function
	copied_func = copy_func((void*)function_addr);
	if (!copied_func) // Copy failed?
	{
		return FALSE;
	}

	m = (mem*)copied_func;

	function_copy = virtual_alloc(m->size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL);
	if (!function_copy)
	{
		free(copied_func);
		return FALSE;
	}

	write_memory(function_copy, (uint64_t)m->buf, (size_t)m->size); // Write the copied memory to the allocated location

	stub_base = virtual_alloc(sizeof(stub), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE, NULL);
	if (!stub_base)
	{
		free(copied_func);
		return FALSE;
	}

	for (i = 0; i < nt_headers->FileHeader.NumberOfSections; i++)
	{
		uint8_t* str;

		str = _unxor((uint8_t*)"\x0c\x50\x47\x4e\x4d\x41", 6); // .reloc

		if (memcmp(section_header->Name, str, 6) == 0) // Dont map .reloc
		{
			continue;
		}

		free(str);

		printf("section %s\n", section_header->Name);

		write_memory((uint64_t)(base + section_header->VirtualAddress), (uint64_t)(ptr->buf + section_header->PointerToRawData), (size_t)section_header->SizeOfRawData);

		section_header++;
	}

	entry_point = (uint64_t)(base + nt_headers->OptionalHeader.AddressOfEntryPoint); // Retrieve the entry point address of the DLL that we previously mapped into memory.

	printf("[+] Entry point -> 0x%X\n", nt_headers->OptionalHeader.AddressOfEntryPoint);

	*(uint64_t*)(stub + 0x1f + 2) = (uint64_t)m->size; // Write the size of the restore buffer
	*(uint64_t*)(stub + 0x29 + 2) = (uint64_t)function_copy;
	*(uint64_t*)(stub + 0x33 + 2) = function_addr;

	*(uint64_t*)(stub + 0x51 + 2) = (uint64_t)base;
	*(uint64_t*)(stub + 0x5b + 2) = (uint64_t)entry_point;

	*(uint64_t*)(stub + 0x6f + 2) = 0x12402b997a8c5149;

	write_memory(stub_base, (uint64_t)stub, sizeof(stub));

	virtual_protect((uint64_t)function_addr, 14, PAGE_EXECUTE_READWRITE, &old);

	hook_func((void*)function_addr, (void*)stub_base); // Hook the function

	Sleep(5000); // Free the memory after 5 seconds

	virtual_protect((uint64_t)function_addr, 14, old, &old);

	// Free the allocated mem in the remote process
	free_mem((void*)function_copy, (size_t)m->size);
	free_mem((void*)stub_base, sizeof(stub));

	free(copied_func); // Free the copied memory.
	
	return TRUE;
}
