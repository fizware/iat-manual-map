#include <windows.h>
#include <stdint.h>
#include <string>

#include "mem.h"
#include "proc.h"
#include "mem_struct.h"
#include "xor.h"
#include <iostream>

static void call_hook(mem* m)
{
	
	uint64_t faddress = 0;
	uint8_t* str = NULL;
	uint8_t* str2 = NULL;
	uint64_t lib = 0;

	// win32u.dll
	str = _unxor((uint8_t*)"\x55\x4b\x4c\x11\x10\x57\x0c\x46\x4e\x4e\x22", 11);
	lib = (uint64_t)LoadLibraryA("win32u.dll");
	free(str);

	if (!lib)
	{
		return;
	}

	// NtTokenManagerConfirmOutstandingAnalogToken
	str2 = _unxor((uint8_t*)"\x6c\x56\x76\x4d\x49\x47\x4c\x6f\x43\x4c\x43\x45\x47\x50\x61\x4d\x4c\x44\x4b\x50\x4f\x6d\x57\x56\x51\x56\x43\x4c\x46\x4b\x4c\x45\x63\x4c\x43\x4e\x4d\x45\x76\x4d\x49\x47\x4c\x22", 44);
	faddress = (uint64_t)GetProcAddress((HMODULE)lib, "NtTokenManagerConfirmOutstandingAnalogToken");
	free(str2);

	//free(str);
	//free(str2);

	if (!faddress)
		return;

	void(__stdcall * func)(mem*) = (void(__stdcall*)(mem*))faddress;

	func(m);
	
	return;
}

void clear_pid_cache(void)
{
	

	if (CleanPIDDBCacheTable())
	{
		std::cout << "Cache cleared.\n";
	}
	else
	{

	}

	
	return;
}

uint64_t virtual_alloc(size_t size, uint32_t allocation_type, uint32_t protect, uint64_t addr)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.valloc = TRUE;
	ms.valloc_base = (void*)addr;
	ms.valloc_size = size;
	ms.valloc_type = allocation_type;
	ms.valloc_protect = protect;

	call_hook(&ms);

	if (ms.valloc_base > 0)
		return (uint64_t)ms.valloc_base;

	
	return 0;
}

void virtual_protect(uint64_t address, size_t size, uint32_t protect, ULONG* old_page_protection)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.vprotect = TRUE;
	ms.vprotect_address = (void*)address;
	ms.vprotect_size = size;
	ms.vprotect_type = protect;

	call_hook(&ms);

	*old_page_protection = ms.vprotect_type;
	
	return;
}

void write_memory(uint64_t dst, uint64_t src, size_t size)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.address = (void*)dst;
	ms.write = TRUE;
	ms.size = size;
	ms.buf = (void*)src;

	call_hook(&ms);


	
	return;
}

void read_mem(uint64_t src, uint64_t dst, size_t size)
{
	
	mem ms;
	char buf[4096];

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.address = (void*)src;
	ms.size = size;
	ms.buf = buf;
	ms.read = TRUE;

	call_hook(&ms);

	memcpy((void*)dst, buf, size);
	
	return;
}

uint64_t get_module_base(const char* name)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.request_base = TRUE;
	ms.module_name = name;

	call_hook(&ms);

	if (ms.base_address > 0)
		return (uint64_t)ms.base_address;


	
	return 0;
}

BOOL check_active_driver(void)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.request_active = TRUE;
	ms.active = FALSE;

	call_hook(&ms);
	
	return ms.active;
}

void free_mem(void* address, size_t size)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.process_id = retrieve_target_pid();
	ms.free = TRUE;
	ms.free_address = address;
	ms.free_size = size;

	call_hook(&ms);
	
	return;
}
static BOOLEAN CleanPIDDBCacheTable() {
	
	mem m;
	m.ClearPIDCache = TRUE;
	m.read = FALSE;
	m.write_string = FALSE;
	m.write = FALSE;
	m.request_base = FALSE;
	m.read_string = FALSE;
	call_hook(&m);
	
	return m.PIDCacheCleared;
}

void unhook_func(void)
{
	
	mem ms;

	ZeroMemory(&ms, sizeof(mem));

	ms.unhook_func = TRUE;

	call_hook(&ms);

	//printf("[+] Func unhooked\n");
	
	return;
}