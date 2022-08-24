#include "kdmapper.hpp"
#include "version.h"
#include "../Injector/Injectormain.h"
#include "exports.h"
#define EXPORT extern "C" __declspec(dllexport)
//#define GAME_EXE E("EscapeFromTarkov.exe")

void DebugWait(int seconds)
{
	
	printf("Waiting... ");
	for (int i = 1; i <= seconds; i++)
	{
		Sleep(1000);
		printf("%i ", i);
	}
	printf("\n");
	
}
int kdmappermain()
{
	
	printf("Checking version...\n");
	auto version = GetRealOSVersion();
	printf("Build: %lu Major: %lu Minor: %lu\n", version.dwBuildNumber, version.dwMajorVersion, version.dwMinorVersion);
	HANDLE iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << "Failed To Load Vulnerable Driver" << std::endl;
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, 0, 0, false, false, false))
	{
		std::cout << "Failed To Map " << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << "Success" << std::endl;

	
	return 0;
}
