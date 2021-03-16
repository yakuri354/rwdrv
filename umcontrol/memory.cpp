#include "pch.h"
#include "memory.hpp"

vmem_driver::vmem_driver(void* _shmem, size_t _shmem_size, const driver_handle driver):
	shmem(_shmem), shmem_size(_shmem_size), drv(driver)
{
}

uintptr_t vmem_driver::base(uint32_t pid)
{
	if (!NT_SUCCESS(
		drv.ctl(Ctl::GET_BASE_ADDR, pid)
	))
	{
		log("Could not get base address of process %u", pid);
		throw std::exception("could not get base address");
	}
	return *static_cast<uintptr_t*>(shmem);
}

bool vmem_driver::attach(uint32_t pid)
{
	return NT_SUCCESS(
		drv.ctl(Ctl::SET_TARGET, pid)
	);
}

bool vmem_driver::read_raw(void* addr, const size_t size)
{
	if (size > shmem_size - 8 || size > UINT32_MAX)
	{
		log("Read size too big");
		return false;
	}

	*PUINT64(shmem) = UINT64(addr);

	const auto status = drv.ctl(Ctl::READ_VIRTUAL, uint32_t(size));

	if (!NT_SUCCESS(status))
	{
		log("Read failed: 0x%x", NTSTATUS(status));
		return false;
	}

	return true;
}

bool vmem_driver::write_raw(void* addr, const size_t size)
{
	if (size > shmem_size - 8 || size > UINT32_MAX)
	{
		log("Write size too big");
		return false;
	}

	*PUINT64(shmem) = UINT64(addr);

	const auto status = drv.ctl(Ctl::WRITE_VIRTUAL, uint32_t(size));

	if (!NT_SUCCESS(status))
	{
		log("Write failed: 0x%x", NTSTATUS(status));
		return false;
	}

	return true;
}

std::pair<void*, size_t> vmem_driver::buf()
{
	return { PVOID(UINT64(shmem) + 8), shmem_size - 8 };
}
