#pragma once
#include <cstdint>
#include <fmt/printf.h>
#include "common.hpp"
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
	virtual mem_info virtual_query(void* addr) = 0;
	virtual bool read_raw(void* addr, void* buf, size_t size) = 0;
	virtual bool write_raw(void* addr, void* buf, size_t size) = 0;

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
	mem_info virtual_query(void* addr) override;
	bool attach(uint32_t pid) override;
	bool read_raw(void* addr, void* buf, size_t size) override;
	bool write_raw(void* addr, void* buf, size_t size) override;

private:
	uint64_t send_req()
	{
		return drv.ctl(uint32_t(uint64_t(&ctl) >> 32), uint32_t(&ctl));
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
		log("Value read failed");
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
#ifdef _DEBUG
	fmt::memory_buffer out;
	if constexpr (std::is_same<T, int>::value
		|| std::is_same<T, uintptr_t>::value
		|| std::is_same<T, float>::value)
	{
		format_to(out, "\t\tWriting {} to {}\n", value, addr);
	}
	else
	{
		format_to(out, "\t\tWriting a {} to {}\n", typeid(T).name(), addr);
	}
	LI_FN(OutputDebugStringA)(out.data());
#endif

	if (!write_raw(addr, &value, sizeof(T)))
	{
		log("Value write failed");
		throw std::exception("write failed");
	}

#ifdef DEBUG
	if (read<T>(addr) != value)
	{
		log("Write assertion failed");
		throw std::exception("write assertion failed");
	}
#endif
}

template <typename T>
void provider::write(uintptr_t addr, const T& value)
{
	write(PVOID(addr), value);
}
