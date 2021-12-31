#pragma once
#include "framework.h"
#include <cstdint>
#include <string>
#include <TlHelp32.h>
#include <Psapi.h>

namespace util
{
	inline uint32_t process_id(const wchar_t* name)
	{
		PROCESSENTRY32 process_info;
		process_info.dwSize = sizeof(process_info);

		auto* const proc_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
		if (proc_snapshot == INVALID_HANDLE_VALUE)
		{
			return 0;
		}

		Process32First(proc_snapshot, &process_info);
		do
		{
			if (wcscmp(name, process_info.szExeFile) == 0)
			{
				CloseHandle(proc_snapshot);
				return process_info.th32ProcessID;
			}
		}
		while (Process32Next(proc_snapshot, &process_info));

		CloseHandle(proc_snapshot);
		throw ex::process_not_found();
	}

	inline uintptr_t base_addr(uint32_t pid)
	{
		auto hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
		if (hProcess == NULL)
			return NULL; // No access to the process

		HMODULE lphModule[1024]; // Array that receives the list of module handles
		DWORD lpcbNeeded(NULL);
		// Output of EnumProcessModules, giving the number of bytes requires to store all modules handles in the lphModule array

		if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
			return NULL; // Impossible to read modules

		TCHAR szModName[MAX_PATH];
		if (!GetModuleFileNameEx(hProcess, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR)))
			return NULL; // Impossible to get module info

		return uintptr_t(lphModule[0]); // Module 0 is apparently always the EXE itself, returning its address
	}

	template <class T>
	constexpr
	std::string_view
	type_name()
	{
		using namespace std;
		const string_view p = __FUNCSIG__;
		return string_view(p.data() + 84, p.size() - 84 - 7);
	}
}
