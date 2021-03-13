#include "util.h"

uint32_t util::process_id(const std::wstring& name)
{
	PROCESSENTRY32 process_info;
	process_info.dwSize = sizeof(process_info);

	auto* const proc_snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (proc_snapshot == INVALID_HANDLE_VALUE)
	{
		return 0;
	}

	Process32First(proc_snapshot, &process_info);
	if (name == process_info.szExeFile)
	{
		CloseHandle(proc_snapshot);
		return process_info.th32ProcessID;
	}

	while (Process32Next(proc_snapshot, &process_info))
	{
		if (name == process_info.szExeFile)
		{
			CloseHandle(proc_snapshot);
			return process_info.th32ProcessID;
		}
	}

	CloseHandle(proc_snapshot);
	return 0;
}
