#pragma once

using namespace std;


DWORD target_pid = 0;
HANDLE driver_handle;

const char* ProcName;


// Always add 1 to ur total byte array size.
unsigned long long DLL_Length = 2;

/* Store ur DLL Byte Array here. 
Tutorial: 
1. Open your .dll file in HxD
2. Go to edit on the top left > Copy as > C
3. Paste it under here and rename it DLL_Array
4. Change DLL_Length to the size of your dll array + 1
*/
unsigned char DLL_Array[1] = { 0x0 };

int main(const int argc, char** argv);