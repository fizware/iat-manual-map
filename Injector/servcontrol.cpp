#include <windows.h>
#include <stdio.h>

static BOOL __stdcall stop_dependent_services(SC_HANDLE serv, SC_HANDLE sc_manager)
{

    DWORD bytes_needed = 0;
    DWORD count = 0;
    LPENUM_SERVICE_STATUS dependencies = NULL;
    ENUM_SERVICE_STATUS ess;
    SC_HANDLE dep_service;
    SERVICE_STATUS_PROCESS ssp;
    DWORD start_time = 0;
    DWORD timeout = 30 * 1000; // 30-second time-out
    DWORD i = 0;

    start_time = GetTickCount();

    // Pass a zero-length buffer to get the required buffer size.
    if (EnumDependentServices(serv, SERVICE_ACTIVE, dependencies, 0, &bytes_needed, &count))
    {
        // If the Enum call succeeds, then there are no dependent
        // services, so do nothing.
        return TRUE;
    }

    if (GetLastError() != ERROR_MORE_DATA)
        return FALSE;

    // Allocate a buffer for the dependencies.
    dependencies = (LPENUM_SERVICE_STATUS)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bytes_needed);

    if (!dependencies)
        return FALSE;

    __try
    {
        // Enumerate the dependencies.
        if (!EnumDependentServices(serv, SERVICE_ACTIVE, dependencies, bytes_needed, &bytes_needed, &count))
            return FALSE;

        for (i = 0; i < count; i++)
        {
            ess = *(dependencies + i);

            // Open the service.
            dep_service = OpenService(sc_manager, ess.lpServiceName, SERVICE_STOP | SERVICE_QUERY_STATUS);

            if (!dep_service)
                return FALSE;

            __try
            {
                if (!ControlService(dep_service, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
                    return FALSE;

                while (ssp.dwCurrentState != SERVICE_STOPPED)
                {
                    //                    Sleep(ssp.dwWaitHint);
                    Sleep(1000);

                    if (!QueryServiceStatusEx(dep_service, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
                        return FALSE;

                    if (ssp.dwCurrentState == SERVICE_STOPPED)
                        break;

                    if (GetTickCount() - start_time > timeout)
                        return FALSE;
                }
            }
            __finally
            {
                CloseServiceHandle(dep_service);
            }
        }
    }
    __finally
    {
        HeapFree(GetProcessHeap(), 0, dependencies);
    }
    
    return TRUE;
}

VOID __stdcall stop_service(const char* service_name)
{
    
    SERVICE_STATUS_PROCESS ssp;
    DWORD start_time = 0;
    DWORD bytes_needed = 0;
    DWORD timeout = 30 * 1000; // 30-second time-out
    SC_HANDLE sc_manager;
    SC_HANDLE serv;
    BOOL done = FALSE;

    start_time = GetTickCount();

    sc_manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!sc_manager)
    {
        return;
    }

    serv = OpenService(sc_manager, service_name, SERVICE_STOP | SERVICE_QUERY_STATUS | SERVICE_ENUMERATE_DEPENDENTS);
    if (!serv)
    {
        CloseServiceHandle(sc_manager);
        return;
    }

    if (!QueryServiceStatusEx(serv, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
    {
        CloseServiceHandle(serv);
        CloseServiceHandle(sc_manager);
        return;
    }

    if (ssp.dwCurrentState == SERVICE_STOPPED)
    {
        //        printf("[+] Service has already been stopped -> %s\n", service_name);

        CloseServiceHandle(serv);
        CloseServiceHandle(sc_manager);
        return;
    }

    while (ssp.dwCurrentState == SERVICE_STOP_PENDING)
    {
        Sleep(1000);

        if (!QueryServiceStatusEx(serv, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
        {
            done = TRUE;
            break;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            //            printf("[+] Service has been stopped -> %s\n", service_name);
            done = TRUE;
            break;
        }

        if (GetTickCount() - start_time > timeout)
        {
            done = TRUE;
            break;
        }
    }

    if (done)
    {
        CloseServiceHandle(serv);
        CloseServiceHandle(sc_manager);
        return;
    }

    stop_dependent_services(serv, sc_manager);

    if (!ControlService(serv, SERVICE_CONTROL_STOP, (LPSERVICE_STATUS)&ssp))
    {
        CloseServiceHandle(serv);
        CloseServiceHandle(sc_manager);
        return;
    }

    while (ssp.dwCurrentState != SERVICE_STOPPED)
    {
        Sleep(1000);

        if (!QueryServiceStatusEx(serv, SC_STATUS_PROCESS_INFO, (LPBYTE)&ssp, sizeof(SERVICE_STATUS_PROCESS), &bytes_needed))
        {
            break;
        }

        if (ssp.dwCurrentState == SERVICE_STOPPED)
        {
            //            printf("[+] Service has been stopped -> %s\n", service_name);
            break;
        }

        if (GetTickCount() - start_time > timeout)
        {
            break;
        }
    }

    CloseServiceHandle(serv);
    CloseServiceHandle(sc_manager);
    
    return;
}

void __stdcall disable_service(const char* service_name)
{
    
    SC_HANDLE manager;
    SC_HANDLE service;
    BOOL ret = FALSE;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager)
        return;

    service = OpenService(manager, service_name, SERVICE_CHANGE_CONFIG);
    if (!service)
        return;

    //    printf("[+] Disabling service -> %s\n", service_name);

    ret = ChangeServiceConfigA(service, SERVICE_NO_CHANGE, SERVICE_DISABLED, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    if (!ret)
    {
        //        printf("[-] Failed to disable service -> %s\n", service_name);
    }

    if (ret)
    {
        //        printf("[+] Successfully disabled service -> %s\n", service_name);
    }

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    
    return;
}

void __stdcall enable_service(const char* service_name)
{
    
    SC_HANDLE manager;
    SC_HANDLE service;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager)
        return;

    service = OpenService(manager, service_name, SERVICE_CHANGE_CONFIG);
    if (!service)
        return;

    ChangeServiceConfig(service, SERVICE_NO_CHANGE, SERVICE_AUTO_START, SERVICE_NO_CHANGE, NULL, NULL, NULL, NULL, NULL, NULL, NULL);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    
    return;
}

void __stdcall delete_service(const char* service_name)
{
    
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS status;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager)
        return;

    service = OpenService(manager, service_name, DELETE);
    if (!service)
        return;

    DeleteService(service);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    
    return;
}

void __stdcall start_service(const char* service_name)
{
    
    SC_HANDLE manager;
    SC_HANDLE service;
    SERVICE_STATUS status;
    BOOL started = FALSE;

    manager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
    if (!manager)
        return;

    service = OpenService(manager, service_name, DELETE);
    if (!service)
        return;

    started = StartServiceA(service, 0, NULL);

    CloseServiceHandle(service);
    CloseServiceHandle(manager);
    
    return;
}