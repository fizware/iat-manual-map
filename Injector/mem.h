#pragma once

uint64_t virtual_alloc(size_t, uint32_t, uint32_t, uint64_t);
void virtual_protect(uint64_t, size_t, uint32_t, ULONG*);
void write_memory(uint64_t, uint64_t, size_t);
void read_mem(uint64_t, uint64_t, size_t);
uint64_t get_module_base(const char*);
void clear_pid_cache(void);
BOOL check_active_driver(void);
void free_mem(void*, size_t);
void unhook_func(void);
BOOLEAN CleanPIDDBCacheTable();