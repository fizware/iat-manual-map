#include <string>
#include "xor.h"

//static const char alpha[32] = "it0j7f14cepomdlgbn39a58sukrhq26";

// Simple function to generate a random string for us
std::string rand_str(int len)
{
	int h = len;
	std::string str;
	std::string alpha;

	// it0j7f14cepomdlgbn39a58sukrhq26
	alpha = "it0j7f14cepomdlgbn39a58sukrhq26░░░░░░░░░░░░";

	while (h-- > 0)
	{
		char tmp;

		tmp = alpha[rand() % 43];

		str += tmp;
	}


	return str;
}