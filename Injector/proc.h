#pragma once

#include <windows.h>

DWORD retrieve_target_pid(void);
DWORD retrieve_pid_via_name(const char*);
HANDLE retrieve_driver_handle(void);
