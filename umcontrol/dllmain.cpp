// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "lazy_importer.hpp"
#include "../rwdrv/comms.hpp"
#include <iostream>
#include "thread.hpp"
#include "common.hpp"
#include "../apex/cheat.h"
#include "memory.hpp"

PHookFn HookedFn = nullptr;

__forceinline uint64_t DriverCall(uint32_t a1, uint16_t a2, uint32_t a3)
{
	return HookedFn(a1, a2, a3);
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
	log("Initializing driver, Va [%p]", g::State.Memory);

	LARGE_INTEGER lint;

	lint.QuadPart = int64_t(g::State.Memory);

	const auto status = DriverCall(lint.LowPart, INIT_MAGIC, lint.HighPart);

	if (!status || HANDLE(status) == INVALID_HANDLE_VALUE)
	{
		log("Init call returned invalid value. Looks like the hook does not work, check kernel logs");
		return false;
	}

	if (!NT_SUCCESS(status))
	{
		log("Init call failed with status 0x%llx", status);
		return false;
	}

	if (*static_cast<uint16_t*>(g::State.Memory) != INIT_MAGIC)
	{
		log("Probe write failed");
		return false;
	}

	log("Driver successfully initialized");

	return true;
}

DWORD WINAPI RealMain(void* param)
{
	log("Starting initialization");

	g::State.Memory = LI_FN(VirtualAlloc)(nullptr, SHMEM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (g::State.Memory == nullptr)
	{
		log("Allocating shared buffer failed");
		return false;
	}

	log("Allocated shared buffer at [%p]", g::State.Memory);

	RtlZeroMemory(g::State.Memory, SHMEM_SIZE);

	log("Retrieving hooked fn");

	auto* dll = LI_MODULE(HOOKED_FN_MODULE).safe();

	if (dll == nullptr)
	{
		log("Module " HOOKED_FN_MODULE " not loaded, attempting to load it");

		dll = LI_FN(LoadLibraryA)(xs(HOOKED_FN_MODULE));

		if (dll == nullptr || dll == INVALID_HANDLE_VALUE)
		{
			log("Could not load module, aborting");
			return false;
		}
	}

	HookedFn = LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn).in_safe(dll);

	if (HookedFn == nullptr)
	{
		log("Could not find function " HOOKED_FN_NAME "");
		return -1;
	}

	log("Found hooked fn " HOOKED_FN_NAME " at [0x%p]", PVOID(HookedFn));

	if (!InitDriver())
	{
		log("Driver initialization failed");
		return -1;
	}

	const driver_handle drv{ &DriverCtl };
	vmem_driver mem{ g::State.Memory, SHMEM_SIZE, drv };

	cheat::run(mem);

	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved
)
{
	if (ul_reason_for_call == DLL_PROCESS_ATTACH)
	{
		log("Launching thread");
		LI_FN(CreateThread)(nullptr, NULL, LPTHREAD_START_ROUTINE(RealMain), nullptr, NULL, &g::State.MainThread);
	}

	return TRUE;
}
