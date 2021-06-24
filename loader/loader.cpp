#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <iostream>
#include <Windows.h>
#include <locale>
#include <codecvt>
#include <random>
#include <string>
#include "../kdmapper/kdmapper.hpp"
#include "xorstr.hpp"
#include "ShlObj.h"
#include "../rwdrv/comms.hpp"
#include "../host/lazy_importer.hpp"

DWORD GetProcessByNameW(std::wstring name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walk through all processes.
	if (Process32First(snapshot, &process))
	{
		do
		{
			// Compare process.szExeFile based on format of name, i.e., trim file path
			// trim .exe if necessary, etc.
			if (std::wstring(process.szExeFile) == name)
			{
				pid = process.th32ProcessID;
				break;
			}
		}
		while (Process32Next(snapshot, &process));
	}

	return pid;
}


std::string GenRandStr(std::default_random_engine& engine, int low, int high)
{
	std::string tmp_s;
	const char* alphanum = xs(
		"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	);

	const std::uniform_int_distribution<> len_d(low, high);
	const auto len = len_d(engine);

	tmp_s.reserve(len);

	const std::uniform_int_distribution<> idx_d(0, 62);

	for (auto i = 0; i < len; ++i)
		tmp_s += alphanum[idx_d(engine)];

	return tmp_s;
}

std::string ExePath()
{
	CHAR buffer[MAX_PATH] = {0};
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of(xs("\\/"));
	return std::string(buffer).substr(0, pos);
}

std::wstring ExePathW()
{
	wchar_t buffer[MAX_PATH] = {0};
	GetModuleFileNameW(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::wstring(buffer).find_last_of(xs(L"\\/"));
	return std::wstring(buffer).substr(0, pos);
}

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::string GetLastErrorAsString()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
	{
		return std::string(); //No error message has been recorded
	}

	LPSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageA(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		LPSTR(&messageBuffer), 0, nullptr);

	//Copy the error message into a std::string.
	std::string message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
std::wstring GetLastErrorAsStringW()
{
	//Get the error message ID, if any.
	DWORD errorMessageID = ::GetLastError();
	if (errorMessageID == 0)
	{
		return std::wstring(); //No error message has been recorded
	}

	LPWSTR messageBuffer = nullptr;

	//Ask Win32 to give us the string version of that message ID.
	//The parameters we pass in, tell Win32 to create the buffer that holds the message for us (because we don't yet know how long the message string will be).
	size_t size = FormatMessageW(
		FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		nullptr, errorMessageID, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT),
		LPWSTR(&messageBuffer), 0, nullptr);

	//Copy the error message into a std::string.
	std::wstring message(messageBuffer, size);

	//Free the Win32's string's buffer.
	LocalFree(messageBuffer);

	return message;
}

bool InjectDll(std::wstring* process)
{
	// TODO Embed encrypted dll in loader

	// PROCESS_INFORMATION pInfo{};
	STARTUPINFO sInfo{};

	// if (!CreateProcessW(
	// 	//xs(L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe"),
	// 	L"C:\\Windows\\System32\\notepad.exe",
	// 	nullptr,
	// 	nullptr,
	// 	nullptr,
	// 	false,
	// 	DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_UNICODE_ENVIRONMENT,
	// 	nullptr,
	// 	// xs(L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application"),
	// 	nullptr,
	// 	&sInfo,
	// 	&pInfo))
	// {
	// 	std::cout << xs("[!] Error while creating process: ") << GetLastErrorAsString() << std::endl;
	// 	return false;
	// }
	std::wstring* proc;
	std::wstring name{};

	if (process == nullptr)
	{
		std::cout << xs("[?] Where to host the dll: ");
		std::wcin >> name;
		proc = &name;
	}
	else proc = process;

	auto* const hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_HEAP_SEG_ALLOC, false,
	                                GetProcessByNameW(*proc));

	if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[-] Failed to open the process: ") << GetLastErrorAsString() << std::endl;
		return false;
	}

	std::cout << xs("[>] Injecting DLL with LoadLibrary") << std::endl;

	char temp_path[MAX_PATH] = {};

	const auto path_size = GetTempPathA(MAX_PATH, temp_path);
	if (!path_size)
	{
		std::cout << xs("[!] Failed to get temp path: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	const auto temp = std::filesystem::temp_directory_path();

	std::default_random_engine rng(std::random_device{}());

	const auto dll_name = GenRandStr(rng, 20, 30) + xs(".dll");

	const auto real_dll_path = temp / dll_name;

	std::filesystem::copy(std::filesystem::path(ExePath()) / xs("host.dll"), real_dll_path);


	auto* const memory = VirtualAllocEx(hProc, nullptr,
	                                    real_dll_path.native().size() * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memory)
	{
		std::cout << xs("[!] Failed to allocate path in target process: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	if (!WriteProcessMemory(hProc, memory, real_dll_path.c_str(), real_dll_path.native().size() * 2, nullptr))
	{
		std::cout << xs("[!] Failed to copy path into target process: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}


	const auto h_thread = CreateRemoteThread(
		hProc,
		nullptr,
		NULL,
		LPTHREAD_START_ROUTINE(LoadLibraryW),
		memory,
		NULL,
		nullptr
	);

	if (!h_thread || h_thread == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[!] Failed to launch LoadLibrary routine: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	WaitForSingleObject(h_thread, INFINITE);
	DWORD exitCode;
	if (!GetExitCodeThread(h_thread, &exitCode) || exitCode == 0)
	{
		std::cout << xs("[!] LoadLibrary failed: ") << std::hex << exitCode << std::dec << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		CloseHandle(h_thread);
		return false;
	}

	std::cout << xs("[+] Successfully injected usermode controller dll") << std::endl;

	CloseHandle(h_thread);
	// CloseHandle(pInfo.hThread);
	CloseHandle(hProc);
	return true;
}

bool load_driver()
{
	std::cout << xs("[>] Loading driver") << std::endl;

	auto* const iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[-] Failed to load driver iqvw64e.sys") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return false;
	}

	if (!intel_driver::ClearPiDDBCacheTable(iqvw64e_device_handle)
		|| !intel_driver::ClearMmUnloadedDrivers(iqvw64e_device_handle)
		|| !intel_driver::ClearKernelHashBucketList(iqvw64e_device_handle))
	{
		std::cout << xs("[-] Cleaning up failed") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return false;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, ExePath() + xs("\\rwdrv.sys")))
	{
		std::cout << xs("[-] Failed to map rwdrv") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return false;
	}


	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << xs("[>] Successfully loaded driver") << std::endl;
	return true;
}

bool check_serivice()
{
	DWORD servicesBufSize{};
	DWORD servicesCount{};
	DWORD resumeHandle{};

	std::cout << xs("[>] Checking for AC services") << std::endl; 

	const auto sc_handle = OpenSCManagerA(nullptr,
	                                      nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!sc_handle)
	{
		std::cout << xs("[-] Error occured while loading service manager: ") << GetLastErrorAsString() << std::
			endl;
		return false;
	}

	(void)EnumServicesStatusExW(
		sc_handle,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_ACTIVE,
		nullptr,
		0,
		&servicesBufSize,
		&servicesCount,
		&resumeHandle,
		nullptr
	);

	if (GetLastError() != ERROR_MORE_DATA)
	{
		std::cout << xs("[-] Unexpected error in EnumServicesStatusEx") << std::endl;
		return false;
	}

	auto* const svcBuf = new BYTE[servicesBufSize];

	if (!EnumServicesStatusExW(
		sc_handle,
		SC_ENUM_PROCESS_INFO,
		SERVICE_WIN32,
		SERVICE_ACTIVE,
		svcBuf,
		servicesBufSize,
		&servicesBufSize,
		&servicesCount,
		&resumeHandle,
		nullptr
	))
	{
		std::wcout << xs(L"[-] Failed to enumerate all services: ") << GetLastError() << std::endl;
		return false;
	}

	for (DWORD i = 0; i < servicesCount; i++)
	{
		if (wcsstr(LPENUM_SERVICE_STATUS_PROCESSW(svcBuf)[i].lpServiceName, xs(L"BEService")))
		{
			std::cout << xs("[-] BE is running, close all protected games before loading the cheat.") << std::endl;
			return false;
		}
		if (wcsstr(LPENUM_SERVICE_STATUS_PROCESSW(svcBuf)[i].lpServiceName, xs(L"EasyAntiCheat")))
		{
			std::cout << xs("[-] EAC is running, close all protected games before loading the cheat.") << std::endl;
			return false;
		}
	}

	return true;
}

PHookFn get_hook_fn()
{
	auto* dll = LI_MODULE(HOOKED_FN_MODULE).safe();

	if (dll == nullptr)
	{
		std::cout << xs("[W] Module ") << xs(HOOKED_FN_MODULE) << xs(" not loaded, attempting to load it") << std::endl;

		dll = LI_FN(LoadLibraryA)(xs(HOOKED_FN_MODULE));

		if (dll == nullptr || dll == INVALID_HANDLE_VALUE)
		{
			std::cout << xs("[-] Could not load module, aborting") << std::endl;
			return nullptr;
		}
	}

	return LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn).in_safe(dll);
}

bool check_driver()
{
	const auto sysCall = get_hook_fn();
	if (!sysCall)
	{
		std::cout << xs("[-] Failed to obtain hooked syscall") << std::endl;
		return 1;
	}

	std::cout << xs("[+] Found syscall -> 0x") << static_cast<void*>(sysCall) << std::endl;

	Control ctl{};
	ctl.CtlCode = Ctl::PING;

	LARGE_INTEGER lint{};
	lint.QuadPart = uintptr_t(&ctl);

	return sysCall(lint.HighPart, CTL_MAGIC, lint.LowPart) == CTLSTATUSBASE;
}

int load(bool forceReloadDrv = false, std::wstring* process = nullptr)
{
	std::cout << xs("[>] Loading rwdrv") << std::endl;

	if (!IsUserAnAdmin())
	{
		std::cout << xs("[!] Loader must be launched with administrative privileges") << std::endl;
		return 1;
	}

	srand(static_cast<unsigned>(time(nullptr)) * GetCurrentProcessId());

	if (!check_serivice())
	{
		std::cout << xs("[-] AC check failed") << std::endl;
		return 1;
	}

	std::cout << xs("[+] AC service not found") << std::endl;

	if (!forceReloadDrv && check_driver())
	{
		std::cout << xs("[+] Driver already loaded, injecting dll") << std::endl;
	}
	else if (!load_driver()) // TODO Custom mapper
	{
		std::cout << xs("[-] Failed to load driver") << std::endl;
		return 1;
	}

	if (!InjectDll(process))
	{
		std::cout << xs("[-] Failed to load usermode dll component") << std::endl;
		return 1;
	}

	std::cout << xs("[+] Loader finished successfully; exiting") << std::endl;

	return 0;
}

int main(int argc, char* argv[])
{
	bool force_reload = false;
	std::wstring proc;
	std::wstring* p_proc = nullptr;

	for (auto i = 0; i < argc; i++)
	{
		if (!strcmp(argv[i], xs("--forcereload")))
		{
			force_reload = true;
		}
		else if (!strcmp(argv[i], xs("--process")) && argc >= i + 2)
		{
			std::wstring_convert<std::codecvt_utf8_utf16<wchar_t>> converter{};
			proc = converter.from_bytes(argv[i + 1]);
			p_proc = &proc;
			i++;
		}
	}

	const auto result = load(force_reload, p_proc);

	if (GetConsoleProcessList(nullptr, 0) == 1)
	{
		system(xs("pause"));
	}

	return result;
}