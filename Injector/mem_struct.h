#pragma once

#include <windows.h>

struct mem
{
	void* buf_address;
	int process_id;
	void* address;
	SIZE_T size;
	SIZE_T size_copied;
	void* buf;
	BOOLEAN write;
	BOOLEAN request_base;
	ULONG64 base_address;
	BOOLEAN ClearPIDCache;
	BOOLEAN PIDCacheCleared;
	BOOLEAN read;
	BOOLEAN read_string;
	BOOLEAN write_string;
	const char* module_name;
	int pid_source;
	BOOLEAN request_image_size;
	ULONG64 mod_size;
	BOOLEAN valloc;
	SIZE_T valloc_size;
	void* valloc_base;
	ULONG valloc_type;
	ULONG valloc_protect;
	BOOLEAN unsafe_read;
	BOOLEAN unsafe_write;
	BOOLEAN request_active;
	BOOLEAN active;
	BOOLEAN vprotect;
	void* vprotect_address;
	size_t vprotect_size;
	ULONG vprotect_type;
	BOOLEAN free;
	void* free_address;
	size_t free_size;
	BOOLEAN unhook_func;
};