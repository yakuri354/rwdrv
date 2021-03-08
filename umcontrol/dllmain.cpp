// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "lazy_importer.hpp"
#include "../rwdrv/comms.hpp"
#include <iostream>
#include <Windows.h>
#include "../loader/xorstr.hpp"
#include "thread.hpp"

#define log(...) {char cad[512]; sprintf_s(cad, __VA_ARGS__);  LI_FN(OutputDebugStringA)(cad);}

#define CTL_IS_ERROR(status) ((status) != CTL_SUCCESS && (status) >= CTL_GENERIC_ERROR)

PHookFn _DriverCtl = nullptr;

__forceinline uint64_t DriverCall(uint32_t a1, uint16_t a2, uint32_t a3)
{
	return _DriverCtl(a1, a2, a3);
}


__forceinline uint64_t DriverCtl(CTLTYPE controlCode, uint32_t additionalParam = 0)
{
	return DriverCall(controlCode, CTL_MAGIC, additionalParam);
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

	LARGE_INTEGER lint;

	lint.QuadPart = int64_t(g::State.Memory);

	const auto status = DriverCall(lint.LowPart, CTL_MAGIC, lint.HighPart);

	if (CTL_IS_ERROR(status))
	{
		log(xs("[umc] Init call failed with status 0x%llx\n"), status);
		return false;
	}

	if (!status)
	{
		log(xs("[umc] Init call returned null handle. Looks like the hook does not work, check kernel logs\n"));
		return false;
	}

	if (*static_cast<uint16_t*>(g::State.Memory) != CTL_MAGIC)
	{
		log(xs("[umc] Probe write failed\n"));
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

	auto* dll = LI_MODULE(HOOKED_FN_MODULE).safe();

	if (dll == nullptr)
	{
		log(xs("[umc] Module %s not loaded, attempting to load it\n"), xs(HOOKED_FN_MODULE));

		dll = LI_FN(LoadLibraryA)(xs(HOOKED_FN_MODULE));

		if (dll == nullptr || dll == INVALID_HANDLE_VALUE)
		{
			log(xs("[umc] Could not load module, aborting\n"));
			return false;
		}
	}

	_DriverCtl = LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn).in_safe(dll);

	if (_DriverCtl == nullptr)
	{
		log(xs("[umc] Could not find function %s\n"), xs(HOOKED_FN_NAME));
		return -1;
	}

	log(xs("[umc] Found hooked fn %s at [0x%p]\n"), xs(HOOKED_FN_NAME), PVOID(_DriverCtl));
	
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
