#include "pch.h"
#include "thread.hpp"

void SpoofThread(void* thread, HMODULE& hModule)
{
	uintptr_t spoofedAddress = NULL;

	const auto defaultThreadSize = 1000;

	std::default_random_engine generator(std::chrono::system_clock::now().time_since_epoch().count());
	const std::uniform_int_distribution<int> distribution{};

	for (auto i = 1; i < 4; i++)
	{
		spoofedAddress |= UINT64(distribution(generator) & 0xFF) << i * 8; // we store it in the lowest bytes
		spoofedAddress |= UINT64(distribution(generator) & 0xFF) << i * 8;
		spoofedAddress |= UINT64(distribution(generator) & 0xFF) << i * 8;
		//returns spoofed address
	}
	while (spoofedAddress > 0x7FFFFFFF)
	{
		spoofedAddress -= 0x1000;
	}
	VirtualProtect(PVOID(spoofedAddress), defaultThreadSize, PAGE_EXECUTE_READWRITE, nullptr);

	CONTEXT tContext;
	HANDLE pHandle = nullptr;

	// const auto keThread = _RtlCreateUserThread(GetProcAddress(GetModuleHandle(L"ntdll"), "RtlCreateUserThread"));

	LI_FN(RtlCreateUserThread).in(LI_MODULE("ntdll").get())(GetCurrentProcess(), nullptr, TRUE, NULL, nullptr, nullptr,
	                           PTHREAD_START_ROUTINE(spoofedAddress), hModule, &pHandle, nullptr);
	//create a thread & stop init everything

	tContext.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;
	GetThreadContext(pHandle, &tContext);

#ifdef _WIN64
	tContext.Rcx = ULONG64(thread);
#else
	tContext.Eax = ULONG32(thread);
#endif

	tContext.ContextFlags = CONTEXT_INTEGER | CONTEXT_CONTROL;

	SetThreadContext(pHandle, &tContext);

	ResumeThread(pHandle);
}
