#include <iostream>
#include <Windows.h>
#include "../kdmapper/kdmapper.hpp"
#include "xorstr.hpp"

typedef UINT (*PHookFn)(UINT, UINT, UINT);

PHookFn DriverControl;

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


int main()
{
	std::cout << "[>] Loading rwdrv" << std::endl;

	srand(static_cast<unsigned>(time(nullptr)) * _getpid());

	auto sc_handle = OpenSCManagerA(nullptr,
	                                nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!sc_handle)
	{
		std::cout << xorstr_("[-] Error occured while loading service manager: ") << GetLastErrorAsString() << std::
			endl;
		return 1;
	}

	// DWORD servicesBufSize;
	// DWORD servicesCount;
	// DWORD resumeHandle;
	//
	//std::cout << xorstr_("[>] Checking for BattlEye service") << std::endl;
	//
	//EnumServicesStatusA(
	//	sc_handle,
	//	SERVICE_WIN32,
	//	SERVICE_ACTIVE,
	//	NULL,
	//	0,
	//	&servicesBufSize,
	//	&servicesCount,
	//	&resumeHandle
	//);
	//
	//auto svcBuf = new BYTE[servicesBufSize];
	//if (!EnumServicesStatusA(
	//	sc_handle,
	//	SERVICE_WIN32,
	//	SERVICE_ACTIVE,
	//	LPENUM_SERVICE_STATUSA(svcBuf),
	//	servicesBufSize,
	//	&servicesBufSize,
	//	&servicesCount,
	//	&resumeHandle
	//))
	//{
	//	std::cout << xorstr_("[-] Failed to enumerate all services: ") << GetLastErrorAsString() << std::endl;
	//	return 1;
	//}
	//
	//for (DWORD i = 0; i < servicesCount; i++)
	//{
	//	if (strcmp(LPENUM_SERVICE_STATUSA(svcBuf)[i].lpServiceName, "BEService") == 0)
	//	{
	//		std::cout << xorstr_("[-] BEService is running, close the game before loading the cheat.") << std::endl;
	//		return 1;
	//	}
	//}

	const auto iqvw64e_device_handle = intel_driver::Load();

	if (!iqvw64e_device_handle || iqvw64e_device_handle == INVALID_HANDLE_VALUE)
	{
		std::cout << xorstr_("[-] Failed to load driver iqvw64e.sys") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	if (!intel_driver::ClearPiDDBCacheTable(iqvw64e_device_handle))
	{
		std::cout << xorstr_("[-] Failed to ClearPiDDBCacheTable") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	if (!kdmapper::MapDriver(iqvw64e_device_handle, ExePath() + xorstr_("\\rwdrv.sys")))
	{
		std::cout << xorstr_("[-] Failed to map rwdrv") << std::endl;
		intel_driver::Unload(iqvw64e_device_handle);
		return -1;
	}

	intel_driver::Unload(iqvw64e_device_handle);
	std::cout << xorstr_("[>] Successfully loaded kernel mode component, initializing") << std::endl;

	const auto mod = GetModuleHandleA(xorstr_("User32.dll"));

	if (!mod)
	{
		std::cout << xorstr_("[-] Failed to load User32.dll") << std::endl;
		return 1;
	}

	DriverControl = PHookFn(GetProcAddress(
		mod,
		xorstr_("OpenInputDesktop")
	));

	if (!DriverControl)
	{
		std::cout << xorstr_("[-] Failed to obtain the address of the hooked routine") << std::endl;
		return 1;
	}

	std::cout << xorstr_("[>] Spoofing disk serials and clearing BigPoolTable") << std::endl;
	const auto rv = DriverControl(0xDEADBEEF, NULL, NULL);
	if (!NT_SUCCESS(rv))
	{
		std::cout << xorstr_("[-] Spoofing disks / clearing BigPoolTable failed. See kernel debug log for more details") << std::endl;
		return 1;
	}
	std::cout << xorstr_("[+] Successfully spoofed disk serials") << std::endl;
	std::cout << xorstr_("[+] Successfully cleared BigPoolTable") << std::endl;
}
