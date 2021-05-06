#pragma once

#ifdef _DEBUG
#define dbgLog ___log
#define marker() LI_FN(OutputDebugStringA)("[umc] " __FUNCTION__ "\n")
#else
#define dbgLog(...)
#define marker(...) 
#endif

#define ___log(fmt, ...) {char cad[512]; sprintf_s(cad, xs("[dbg] " fmt "\n"), ##__VA_ARGS__); LI_FN(OutputDebugStringA)(cad);}(1)