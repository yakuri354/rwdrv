#define _SILENCE_CXX17_CODECVT_HEADER_DEPRECATION_WARNING
#include <iostream>
#include <Windows.h>
#include <locale>
#include <string>
#include "../kdmapper/kdmapper.hpp"
#include "xorstr.hpp"
#include "ShlObj.h"
#include "../rwdrv/comms.hpp"
#include "../umcontrol/lazy_importer.hpp"

DWORD GetProcessByNameW(std::wstring name)
{
	DWORD pid = 0;

	// Create toolhelp snapshot.
	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 process;
	ZeroMemory(&process, sizeof(process));
	process.dwSize = sizeof(process);

	// Walkthrough all processes.
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


std::string GenRandStr(const int len)
{
	std::string tmp_s;
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
		"abcdefghijklmnopqrstuvwxyz";

	srand(static_cast<unsigned>(time(nullptr)) * _getpid());

	tmp_s.reserve(len);

	for (auto i = 0; i < len; ++i)
		tmp_s += alphanum[rand() % (sizeof(alphanum) - 1)];


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

bool InjectDll()
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

	std::wstring name{};
	std::cout << "[?] Where to host the dll: ";
	std::wcin >> name;

	const auto hProc = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_VM_WRITE | PROCESS_HEAP_SEG_ALLOC, false,
	                               GetProcessByNameW(name));

	if (hProc == nullptr || hProc == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[-] Failed to open the process: ") << GetLastErrorAsString() << std::endl;
		return false;
	}

	std::cout << xs("[>] Injecting DLL with LoadLibrary") << std::endl;

	char tempPath[MAX_PATH] = {};

	const auto pathSize = GetTempPathA(MAX_PATH, tempPath);
	if (!pathSize)
	{
		std::cout << xs("[!] Failed to get temp path: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	const auto temp = std::filesystem::temp_directory_path();

	const auto dllName = GenRandStr(10) + ".dll";

	const auto realDllPath = temp / dllName;

	copy(std::filesystem::path(ExePath()) / xs("host.dll"), realDllPath);


	const auto memory = VirtualAllocEx(hProc, nullptr,
	                                   realDllPath.native().size() * 2, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!memory)
	{
		std::cout << xs("[!] Failed to allocate path in target process: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	// FUCK WIDE STRINGS

	if (!WriteProcessMemory(hProc, memory, realDllPath.c_str(), realDllPath.native().size() * 2, nullptr))
	{
		std::cout << xs("[!] Failed to copy path into target process: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}


	auto hThread = CreateRemoteThread(
		hProc,
		nullptr,
		NULL,
		LPTHREAD_START_ROUTINE(LoadLibraryW),
		memory,
		NULL,
		nullptr
	);

	if (!hThread || hThread == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[!] Failed to launch LoadLibrary routine: ") << GetLastErrorAsString() << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		return false;
	}

	WaitForSingleObject(hThread, INFINITE);
	DWORD exitCode;
	if (!GetExitCodeThread(hThread, &exitCode) || exitCode == 0)
	{
		std::cout << xs("[!] LoadLibrary failed: ") << std::hex << exitCode << std::dec << std::endl;
		// CloseHandle(pInfo.hThread);
		CloseHandle(hProc);
		CloseHandle(hThread);
		return false;
	}

	std::cout << xs("[+] Successfully injected usermode controller dll") << std::endl;

	CloseHandle(hThread);
	// CloseHandle(pInfo.hThread);
	CloseHandle(hProc);
	return true;
}

bool load_driver()
{
	std::cout << "[>] Loading driver" << std::endl;
	
	auto* const iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << xs("[-] Failed to load driver iqvw64e.sys") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return false;
	}

	if (!intel_driver::ClearPiDDBCacheTable(iqvw64e_device_handle))
	{
		std::cout << xs("[-] Failed to ClearPiDDBCacheTable") << std::endl;
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

	std::cout << xs("[>] Checking for BattlEye service") << std::endl;

	const auto sc_handle = OpenSCManagerA(nullptr,
	                                      nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!sc_handle)
	{
		std::cout << xs("[-] Error occured while loading service manager: ") << GetLastErrorAsString() << std::
			endl;
		return false;
	}

	const auto dummy = EnumServicesStatusExW(
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

	assert(!dummy);

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
			std::cout << xs("[-] BEService is running, close the game before loading the cheat.") << std::endl;
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
		std::cout << "[W] Module " << xs(HOOKED_FN_MODULE) << " not loaded, attempting to load it" << std::endl;

		dll = LI_FN(LoadLibraryA)(xs(HOOKED_FN_MODULE));

		if (dll == nullptr || dll == INVALID_HANDLE_VALUE)
		{
			std::cout << "[-] Could not load module, aborting" << std::endl;
			return nullptr;
		}
	}

	return LI_FN_MANUAL(HOOKED_FN_NAME, PHookFn).in_safe(dll);
}

int load(bool forceReloadDrv = false)
{
	std::cout << xs("[>] Loading rwdrv") << std::endl;

	if (!IsUserAnAdmin())
	{
		std::cout << xs("[!] Loader must be launched with administrative privileges") << std::endl;
		return 1;
	}

	srand(static_cast<unsigned>(time(nullptr)) * _getpid());

	if (!check_serivice())
	{
		std::cout << xs("[-] Battleye check failed") << std::endl;
		return 1;
	}

	std::cout << xs("[+] BE service not found") << std::endl;

	const auto sysCall = get_hook_fn();
	if (!sysCall)
	{
		std::cout << xs("[-] Failed to obtain hooked syscall") << std::endl;
		return 1;
	}

	std::cout << xs("[+] Found syscall -> 0x") << static_cast<void*>(sysCall) << std::endl;

	if (sysCall(Ctl::PING, CTL_MAGIC, NULL) == CTLSTATUSBASE && !forceReloadDrv)
	{
		std::cout << xs("[+] Driver already loaded, injecting dll") << std::endl;
	}
	else if (!load_driver())
	{
		std::cout << xs("[-] Failed to load driver") << std::endl;
		return 1;
	}

	if (!InjectDll())
	{
		std::cout << xs("[-] Failed to load usermode dll component") << std::endl;
		return 1;
	}

	std::cout << xs("[+] Loader finished successfully; exiting") << std::endl;

	return 0;
}

int main(int argc, char* argv[])
{
	const auto result = load(argc >= 2 && !strcmp(argv[1], xs("--forcereload")));

	if (GetConsoleProcessList(nullptr, 0) == 1)
	{
		system("pause");
	}

	return result;
}
