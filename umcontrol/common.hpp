#pragma once
#include "../loader/xorstr.hpp"
#include "../loader/lazy_importer.hpp"
#include <Windows.h>

#ifdef _DEBUG
#define logD log
#define marker() LI_FN(OutputDebugStringA)("[umc] " __FUNCTION__ "\n")
#else
#define logD(...)
#define marker(...) 
#endif

#define log(fmt, ...) {char cad[512]; sprintf_s(cad, xs("[umc] " fmt "\n"), ##__VA_ARGS__); LI_FN(OutputDebugStringA)(cad);}(1)
// #define log(...) printf_s(__VA_ARGS__)