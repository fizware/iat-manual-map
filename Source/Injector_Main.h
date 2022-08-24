#pragma once
#include "../Extra Headers/Global_Includes.h"
using namespace std;

HWND hWnd;
DWORD procID;
HANDLE hProc;

// Randomize Program Name
string chars{ "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*()`~-_=+[{]{|;:'\",<.>/?" };
random_device rd;
mt19937 generator(rd());
string rand_str(size_t length)
{
	const size_t char_size = chars.size();
	uniform_int_distribution<> random_int(0, char_size - 1);
	string output;
	for (size_t i = 0; i < length; ++i)
		output.push_back(chars[random_int(generator)]);
	return output;
}