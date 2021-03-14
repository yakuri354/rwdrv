#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <PsApi.h>
#include <string>
#include <cstdint>
#include <string>

#define GAME_NAME L"RainbowSix.exe"

namespace util
{
	uint32_t process_id(const std::wstring& name);
}
