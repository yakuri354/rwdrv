#pragma once
#include "../host/hoster.hpp"

namespace g
{
	extern hoster* host;
}

#define printf(fmt, ...) {char cad[512]; sprintf_s(cad, xs(fmt), ##__VA_ARGS__); LI_FN(OutputDebugStringA)(cad);}(1)

void cheat(hoster& host);