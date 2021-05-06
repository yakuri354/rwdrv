#pragma once
#include <cstdint>
#include <exception>
#include "pch.h"
#include "../rwdrv/comms.hpp"

typedef uint64_t (drv_ctl_t)(uint32_t a1, uint32_t a2);	
typedef MEMORY_BASIC_INFORMATION mem_info;

struct driver;

struct driver_handle
{
	friend driver;

	driver_handle(drv_ctl_t* p_ctl) : ctl(p_ctl)
	{
	}

private:
	drv_ctl_t* ctl;
};

struct provider
{
	virtual bool attach(uint32_t pid) = 0;
	virtual uintptr_t base() = 0;
	virtual bool read_raw(const void* addr, void* buf, size_t size) = 0;
	virtual bool write_raw(void* addr, const void* buf, size_t size) = 0;

	template <typename T>
	T read(void* addr);

	template <typename T>
	T read(uintptr_t addr);

	template <typename T>
	void write(void* addr, const T& value);

	template <typename T>
	void write(uintptr_t addr, const T& value);
	
	virtual ~provider() = default;
};

struct driver : provider
{
	driver(const driver_handle& driver);

	uintptr_t base() override;
	bool attach(uint32_t pid) override;
	bool read_raw(const void* addr, void* buf, size_t size) override;
	bool write_raw(void* addr, const void* buf, size_t size) override;

private:
	uint64_t send_req()
	{
#pragma warning(suppress : 4311)
#pragma warning(suppress : 4302)
		return drv.ctl(uint32_t(uint64_t(&ctl) >> 32), uint32_t(&ctl));  // NOLINT(clang-diagnostic-pointer-to-int-cast)
	}

	const driver_handle& drv;
	Control ctl;
};

template <typename T>
T provider::read(void* addr)
{
	T local;
	
	if (!read_raw(addr, &local, sizeof(T)))
	{
		throw std::exception("read failed");
	}

	return local;
}

template <typename T>
T provider::read(const uintptr_t addr)
{
	return read<T>(PVOID(addr));
}

template <typename T>
void provider::write(void* addr, const T& value)
{
	if (!write_raw(addr, reinterpret_cast<const void*>(&value), sizeof(T)))
	{
		throw std::exception("write failed");
	}
}

template <typename T>
void provider::write(uintptr_t addr, const T& value)
{
	write(PVOID(addr), value);
}
