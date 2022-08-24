#pragma once

#include <windows.h>

VOID __stdcall stop_service(const char*);
void __stdcall disable_service(const char*);
void __stdcall enable_service(const char*);
void __stdcall delete_service(const char*);
void __stdcall start_service(const char*);
