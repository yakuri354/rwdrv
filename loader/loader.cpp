// loader.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>

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

int main()
{
	auto sc_handle = OpenSCManagerA(nullptr,
	                              nullptr, SC_MANAGER_ENUMERATE_SERVICE);
	if (!sc_handle)
	{
		std::cout << "Error occured while loading service manager: " << GetLastErrorAsString() << std::endl;
		return 1;
	}

	auto be_svc = OpenServiceA(sc_handle, "BEService", GENERIC_READ);

	if (!be_svc)
	{
		std::cout << "Error while opening BE service: " << GetLastErrorAsString() << std::endl;
		return 1;
	}

	DWORD buf_size;

	if (!QueryServiceStatusEx(be_svc, SC_STATUS_PROCESS_INFO, nullptr, 0, &buf_size))
	{
		std::cout << "Error while determining process status structure buffer size: " << GetLastErrorAsString() << std::endl;
		return 1;
	}

	auto buf = new BYTE[buf_size];

	if (!QueryServiceStatusEx(be_svc, SC_STATUS_PROCESS_INFO, buf, buf_size, &buf_size))
	{
		std::cout << "Error while retrieving BattlEye service status: " << GetLastErrorAsString() << std::endl;
		return 1;
	}

	auto state = reinterpret_cast<LPSERVICE_STATUS_PROCESS>(buf)->dwCurrentState;

	if (state != SERVICE_STOPPED)
	{
		std::cout << "BattlEye service is running! Close the game before loading the driver" << std::endl;
		return 2;
	}

	delete[] buf;
}
