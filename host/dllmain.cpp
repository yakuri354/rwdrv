// dllmain.cpp : Определяет точку входа для приложения DLL.
#include "pch.h"
#include "lazy_importer.hpp"
#include "../rwdrv/comms.hpp"
#include <iostream>
#include "common.hpp"
#include "../apexbot/apexbot.hpp"
#include "memory.hpp"

struct host_state
{
	void* memory;
	PHookFn hooked_fn;
	DWORD main_thread;
};

namespace g
{
	host_state state = {};
}

__forceinline uint64_t driver_call(uint32_t a1, uint16_t a2, uint32_t a3)
{
	return g::state.hooked_fn(a1, a2, a3);
}

__forceinline uint64_t driver_ctl(CTLTYPE controlCode, uint32_t additionalParam = 0)
{
	return driver_call(controlCode, CTL_MAGIC, additionalParam);
}

bool init_driver()
{
	log("Initializing driver, Va [%p]", g::state.memory);

	LARGE_INTEGER lint;

	lint.QuadPart = int64_t(g::state.memory);

	const auto status = driver_call(lint.LowPart, INIT_MAGIC, lint.HighPart);

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

	if (*static_cast<uint16_t*>(g::state.memory) != INIT_MAGIC)
	{
		log("Probe write failed");
		return false;
	}

	log("Driver successfully initialized");

	return true;
}

DWORD WINAPI real_main(void* param)
{
	log("Starting initialization");

	g::state.memory = LI_FN(VirtualAlloc)(nullptr, SHMEM_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (g::state.memory == nullptr)
	{
		log("Allocating shared buffer failed");
		return false;
	}

	log("Allocated shared buffer at [%p]", g::state.memory);

	RtlZeroMemory(g::state.memory, SHMEM_SIZE);

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

	g::state.hooked_fn = LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn).in_safe(dll);

	if (g::state.hooked_fn == nullptr)
	{
		log("Could not find function " HOOKED_FN_NAME "");
		return -1;
	}

	log("Found hooked fn " HOOKED_FN_NAME " at [0x%p]", PVOID(g::state.hooked_fn));

	if (!init_driver())
	{
		log("Driver initialization failed");
		return -1;
	}

	log("Starting cheat");

	const driver_handle drv{ &driver_ctl };
	vmem_driver mem{ g::state.memory, SHMEM_SIZE, drv };

	hoster host{mem, [](char* str)
	{
		LI_FN(OutputDebugStringA)(str);
	}};
	
	cheat(host);

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
		LI_FN(CreateThread)(nullptr, NULL, LPTHREAD_START_ROUTINE(real_main), nullptr, NULL, &g::state.main_thread);
	}

	return TRUE;
}
