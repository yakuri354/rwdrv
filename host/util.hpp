#pragma once
#include "framework.h"
#include <cstdint>
#include <string>
#include <TlHelp32.h>

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
		} while (Process32Next(proc_snapshot, &process_info));

		CloseHandle(proc_snapshot);
		throw ex::process_not_found();
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
