#pragma once

#include <windows.h>
#include <thread>
#include <chrono>
#include <fstream>
#include <string>
#include <sstream>
#include <map>

template <typename type>
type read_memory(uint64_t src, uint64_t size = sizeof(type))
{
	type ret;
	read_mem(src, (uint64_t)&ret, size);
	return ret;
}

enum INJECTION_TYPE
{
	KERNEL,
	USERMODE
};

struct inject_info
{
	std::map<std::string, uint64_t> imports;
	uint8_t type;
	uint8_t* buf;
	size_t buf_size;
	const char* target_lib;
	const char* target_func;
	const char* target_mod;
};

BOOL inject(inject_info*, BOOL);