#pragma once
#include "../loader/xorstr.hpp"
#include "../loader/lazy_importer.hpp"
#include <Windows.h>

#define log(...) {char cad[512]; sprintf_s(cad, __VA_ARGS__); LI_FN(OutputDebugStringA)(cad);}(1)