#include "pch.h"
#include "provider.hpp"

driver::driver(const driver_handle& driver): drv(driver), ctl()
{
	log("Initializing memory");
}

uintptr_t driver::base()
{
	ctl.CtlCode = Ctl::GET_BASE_ADDR;
	if (!CTL_SUCCESS(
		send_req()
	))
	{
		log("Could not get base address of process %u", ctl.Pid);
		throw std::exception("could not get base address");
	}
	return ctl.Result;
}

bool driver::attach(uint32_t pid)
{
	log("Attached to process %u", pid);
	ctl.Pid = pid;
	return true; // TODO Test for validity
}

bool driver::read_raw(const void* addr, void* buf, const size_t size) // TODO Unified memcpy
{
	ctl.CtlCode = Ctl::VIRT_READ;
	ctl.Source = const_cast<void*>(addr);
	ctl.Target = buf;
	ctl.Size = size;
	
	const auto status = send_req();
	if (!CTL_SUCCESS(status))
	{
		log("Read at [0x%p] failed: 0x%x", addr, NTSTATUS(status));
		return false;
	}

	return true;
}

bool driver::write_raw(void* addr, const void* buf, const size_t size)
{
	ctl.CtlCode = Ctl::VIRT_WRITE;
	ctl.Source = const_cast<void*>(buf);
	ctl.Target = addr;
	ctl.Size = size;

	const auto status = send_req();
	if (!CTL_SUCCESS(status))
	{
		log("Write at [0x%p] failed: 0x%x", addr, NTSTATUS(status));
		return false;
	}

	return true;
}
