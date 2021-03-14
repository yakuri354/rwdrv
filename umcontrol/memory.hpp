#pragma once
#include <cstdint>
#include <iostream>
#include "common.hpp"
#include "../rwdrv/comms.hpp"

typedef uint64_t(drv_ctl_t)(CTLTYPE ctl_code, uint32_t param);

struct vmem_driver;

struct driver_handle
{
	friend vmem_driver;
	
	driver_handle(drv_ctl_t* p_ctl) : ctl(p_ctl) {}
private:
	drv_ctl_t* ctl;
};

struct memory
{
	virtual bool attach(uint32_t pid) = 0;
	virtual uintptr_t base(uint32_t pid) = 0;
	virtual bool read_raw(void* addr, size_t size) = 0;
	virtual bool write_raw(void* addr, size_t size) = 0;

	template <typename T>
	T read(void* addr);

	template <typename T>
	T read(uintptr_t addr);

	template <typename T>
	void write(void* addr, T value);

	template <typename T>
	void write(uintptr_t addr, T value);
	
	virtual std::pair<void*, size_t> buf() = 0;
	virtual ~memory() = default;
};

struct vmem_driver : memory
{
	vmem_driver(void* shmem, size_t shmem_size, driver_handle driver);

	uintptr_t base(uint32_t pid) override;
	bool attach(uint32_t pid) override;
	bool read_raw(void* addr, size_t size) override;
	bool write_raw(void* addr, size_t size) override;
	std::pair<void*, size_t> buf() override;

private:
	void* shmem;
	size_t shmem_size;
	driver_handle drv;
};

template <typename T>
T memory::read(void* addr)
{
	auto [buffer, size] = buf();

	if (sizeof(T) > size)
	{
		log("Value too big");
		throw std::exception("value too big");
	}

	if (!read_raw(addr, sizeof(T)))
	{
		log("Value read failed");
		throw std::exception("read failed");
	}

	return *static_cast<T*>(buffer);
}

template <typename T>
T memory::read(const uintptr_t addr)
{
	return read<T>(PVOID(addr));
}

template <typename T>
void memory::write(void* addr, T value)
{
	auto [buffer, size] = buf();

	if (sizeof(T) > size)
	{
		log("Value too big");
		throw std::exception("value too big");
	}

	*static_cast<T*>(buffer) = value;
	
	if (!write_raw(addr, sizeof(T)))
	{
		log("Value read failed");
		throw std::exception("write failed");
	}
}

template <typename T>
void memory::write(uintptr_t addr, T value)
{
	write(PVOID(addr), value);
}
