#pragma once
#include "framework.h"
#include "../loader/xorstr.hpp"
#include "../loader/lazy_importer.hpp"

#ifdef _DEBUG
#define dbgLog log
#define marker() LI_FN(OutputDebugStringA)("CALLING " __FUNCTION__ "\n")
#else
#define dbgLog(...)
#define marker(...) 
#endif

#define log(fmt, ...) {char cad[512]; sprintf_s(cad, xs(fmt "\n"), ##__VA_ARGS__); LI_FN(OutputDebugStringA)(cad);}(1)
// #define log(...) printf_s(__VA_ARGS__)