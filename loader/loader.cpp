// loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include "../kdmapper/kdmapper.hpp"
#include "xorstr.hpp"

#define BUF_SIZE (1024 * 10)

struct SHARED_MEM
{
	HANDLE hFile;
	PVOID buf;
};

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

auto ExePath() -> std::string
{
	CHAR buffer[MAX_PATH] = {0};
	GetModuleFileNameA(NULL, buffer, MAX_PATH);
	std::string::size_type pos = std::string(buffer).find_last_of(xorstr_("\\/"));
	return std::string(buffer).substr(0, pos);
}

//Returns the last Win32 error, in string format. Returns an empty string if there is no error.
auto GetLastErrorAsString() -> std::string
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

bool OpenSharedMemory(SHARED_MEM* mem)
{
	auto hFile = OpenFileMappingA(FILE_MAP_ALL_ACCESS, FALSE, xorstr_("Global\\SharedMem"));
	if (!hFile || hFile == INVALID_HANDLE_VALUE)
	{
		std::cout << xorstr_("[-] OpenFileMappingA(write) failed; Error:") << GetLastError() << std::endl;
		return false;
	}

	auto buf = MapViewOfFile(hFile, // handle to map object
		FILE_MAP_ALL_ACCESS,  // read/write permission
		0,
		0,
		BUF_SIZE);

	if (buf == nullptr)
	{
		_tprintf(TEXT("[-] Could not map view of file (%d).\n"),
			GetLastError());

		CloseHandle(hFile);

		return false;
	}

	mem->buf = buf;
	mem->hFile = hFile;
	
	printf("[-] Shared memory successfully initialized\n");
	SetConsoleTextAttribute(GetStdHandle(STD_OUTPUT_HANDLE), 0xA);
	return true;
}


int main()
{
	std::cout << "[>] Loading rwdrv" << std::endl;
	auto sc_handle = OpenSCManagerA(nullptr,
	                                nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!sc_handle)
	{
		std::cout << xorstr_("[-] Error occured while loading service manager: ") << GetLastErrorAsString() << std::endl;
		return 1;
	}

	// DWORD servicesBufSize;
	// DWORD servicesCount;
	// DWORD resumeHandle;
	//
	// std::cout << xorstr_("[>] Checking for BattlEye service") << std::endl;
	//
	// EnumServicesStatusA(
	// 	sc_handle,
	// 	SERVICE_WIN32,
	// 	SERVICE_ACTIVE,
	// 	NULL,
	// 	0,
	// 	&servicesBufSize,
	// 	&servicesCount,
	// 	&resumeHandle
	// );
	//
	// auto svcBuf = new BYTE[servicesBufSize];
	// if (!EnumServicesStatusA(
	// 	sc_handle,
	// 	SERVICE_WIN32,
	// 	SERVICE_ACTIVE,
	// 	LPENUM_SERVICE_STATUSA(svcBuf),
	// 	servicesBufSize,
	// 	&servicesBufSize,
	// 	&servicesCount,
	// 	&resumeHandle
	// ))
	// {
	// 	std::cout << xorstr_("[-] Failed to enumerate all services: ") << GetLastErrorAsString() << std::endl;
	// 	return 1;
	// }
	//
	// for (DWORD i = 0; i < servicesCount; i++)
	// {
	// 	if (strcmp(LPENUM_SERVICE_STATUSA(svcBuf)[i].lpServiceName, "BEService") == 0)
	// 	{
	// 		std::cout << xorstr_("[-] BEService is running, close the game before loading the cheat.") << std::endl;
	// 		return 1;
	// 	}
	// }

	if (intel_driver::IsRunning())
	{
		std::cout << xorstr_("[-] \\Device\\Nal already exists, unload iqwv64e.sys to proceed");
		return 1;
	}

	const auto intel_drv_handle = intel_driver::Load();

	if (!intel_drv_handle || intel_drv_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << xorstr_("[-] Failed to load vulnerable intel driver\n");
		return 1;
	}

	std::cout << xorstr_("[>] Mapping driver and calling DriverEntry") << std::endl;

	if (!kdmapper::MapDriver(intel_drv_handle, (ExePath() + xorstr_("\\rwdrv.sys"))))
	{
		std::cout << xorstr_("[-] Failed to map rwdrv") << std::endl;
		intel_driver::Unload(intel_drv_handle);
		return 1;
	}

	std::cout << xorstr_("[>] Unloading vulnerable driver");
	intel_driver::Unload(intel_drv_handle);

	SHARED_MEM mem = {};

	std::cout << xorstr_("[>] Opening shared memory") << std::endl;
	if (!OpenSharedMemory(&mem) || mem.buf == nullptr)
	{
		std::cout << xorstr_("[-] Failed to open shared memory") << std::endl;
		return 1;
	}

	std::cout << xorstr_("[>] Signaling cleanup stage start") << std::endl;
	*PULONGLONG(mem.buf) = ULONGLONG(0xDEADBEEF);
	
	return 0;
}
