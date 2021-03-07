﻿// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "lazy_importer.hpp"
#include "../rwdrv/comms.hpp"
#include <iostream>
#include <Windows.h>
#include "../loader/xorstr.hpp"
#include "thread.hpp"

#define log(...) {char cad[512]; sprintf_s(cad, __VA_ARGS__);  LI_FN(OutputDebugStringA)(cad);}

// typedef long NTSTATUS;
//
// constexpr bool NT_SUCCESS(NTSTATUS status)
// {
// 	return status >= 0;
// }

namespace g
{
	FILE* ConOut{};
};

// template <typename A>
// __forceinline void log(const char *fmt, A args...)
// {
// #ifdef DEBUG
// 	if (g::ConOut == nullptr)
// 	{
//         AllocConsole();
//         freopen_s(&g::ConOut, "CONIN$", "r", stdin);
//         freopen_s(&g::ConOut, "CONOUT$", "w", stderr);
//         freopen_s(&g::ConOut, "CONOUT$", "w", stdout);
// 	}
//     printf(fmt, args);
//     printf("\n");
// #endif
// }

// __forceinline void log(const char* fmt)
// {
// #ifdef DEBUG
//     if (g::ConOut == nullptr)
//     {
//         AllocConsole();
//         freopen_s(&g::ConOut, "CONIN$", "r", stdin);
//         freopen_s(&g::ConOut, "CONOUT$", "w", stderr);
//         freopen_s(&g::ConOut, "CONOUT$", "w", stdout);
//     }
//     printf(fmt);
//     printf("\n");
// #endif
// }
//
// TODO Rework shit

PHookFn* _DriverCtl = nullptr;

__forceinline uint64_t DriverCall(uint64_t a1)
{
	return (*_DriverCtl)(a1);
}


__forceinline uint64_t DriverCtl(CTLTYPE controlCode)
{
	return DriverCall(UINT64(CTL_MAGIC) << 32 | UINT64(controlCode));
}

struct State
{
	void* Memory;
	DWORD MainThread;
};

namespace g
{
	::State State = {};
}

bool InitDriver()
{
	log(xs("[umc] Initializing driver\n"));

	log(xs("[umc] Making init call, Va [%p]\n"), g::State.Memory);

	const auto status = DriverCall(uint64_t(g::State.Memory));

	if (!NT_SUCCESS(status))
	{
		log(xs("[umc] Init call failed with status %llu\n"), status);
		return false;
	}

	if (!(*static_cast<uint32_t*>(g::State.Memory) == CTL_MAGIC))
	{
		log(xs("[umc] Probe write failed"));
		return false;
	}

	log(xs("[umc] Driver successfully initialized\n"));

	return true;
}

DWORD WINAPI RealMain(void* param)
{
	log(xs("[umc] Starting initialization\n"));

	g::State.Memory = LI_FN(VirtualAlloc)(nullptr, SHMEM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (g::State.Memory == nullptr)
	{
		log(xs("[umc] Allocating shared buffer failed\n"));
		return false;
	}

	log(xs("[umc] Allocated shared buffer at [%p]\n"), g::State.Memory);

	RtlZeroMemory(g::State.Memory, SHMEM_SIZE);

	log(xs("[umc] Retrieving hooked fn\n"));

	// _DriverCtl = LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn*).in(LI_MODULE(HOOKED_FN_MODULE).get());

	__debugbreak();

	if (_DriverCtl == nullptr)
	{
		log(xs("[umc] Could not find function %s\n"), "FindThreadPointerData");
		return -1;
	}

	log(xs("[umc] Found hooked fn %s at [0x%p]\n"), "FindThreadPointerData", PVOID(_DriverCtl));

	if (!InitDriver())
	{
		log(xs("[umc] Driver initialization failed\n"));
		return -1;
	}

	while (true)
	{
		log(xs("[umc] Loop\n"));
		LI_FN(Sleep)(10000);
	}

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
)
{
	// log(xs("[umc] DllMain called\n"));

	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		log(xs("[umc] Launching thread\n"));
		LI_FN(CreateThread)(nullptr, NULL, LPTHREAD_START_ROUTINE(RealMain), nullptr, NULL, &g::State.MainThread);
		// SpoofThread(RealMain, hModule);
	}

	return TRUE;
}
