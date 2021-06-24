#include "pch.h"
#include "common.hpp"
#include "memory.hpp"

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

void driver::attach(uint32_t pid)
{
	if (pid == 0)
	{
		throw ex::process_not_found();
	}
	log("Attached to process %u", pid);
	ctl.Pid = pid;
	// TODO Test for validity
}

void driver::read_raw(const void* addr, void* buf, const size_t size)
{
	ctl.CtlCode = Ctl::VIRT_READ;
	ctl.Source = const_cast<void*>(addr);
	ctl.Target = buf;
	ctl.Size = size;

	if (const auto status = send_req(); !CTL_SUCCESS(status))
	{
		//log("Read at [0x%p] failed: 0x%x", addr, NTSTATUS(status));
		switch (NTSTATUS(status))
		{
		case Err::MEM_ERROR:
			throw ex::invalid_memory_access{ addr };
		case Err::NOT_FOUND:
			throw ex::process_not_found();
		case Err::UNKNOWN:
		default:
			throw ex::driver_error(NTSTATUS(status));
		}
	}
}

void driver::write_raw(void* addr, const void* buf, const size_t size)
{
	ctl.CtlCode = Ctl::VIRT_WRITE;
	ctl.Source = const_cast<void*>(buf);
	ctl.Target = addr;
	ctl.Size = size;

	if (const auto status = send_req(); !CTL_SUCCESS(status))
	{
		//log("Write at [0x%p] failed: 0x%x", addr, NTSTATUS(status));
		switch (NTSTATUS(status))
		{
		case Err::MEM_ERROR:
			throw ex::invalid_memory_access{ addr };
		case Err::NOT_FOUND:
			throw ex::process_not_found();
		case Err::UNKNOWN:
		default:
			throw ex::driver_error(NTSTATUS(status));
		}
	}
}
