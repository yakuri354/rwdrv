#pragma once
#include <cstdint>
#include <fmt/printf.h>
#include "common.hpp"
#include "../rwdrv/comms.hpp"

typedef uint64_t (drv_ctl_t)(CTLTYPE ctl_code, uint32_t param);

struct vmem_driver;

struct driver_handle
{
	friend vmem_driver;

	driver_handle(drv_ctl_t* p_ctl) : ctl(p_ctl)
	{
	}

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
	void write(void* addr, const T& value);

	template <typename T>
	void write(uintptr_t addr, const T& value);

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
void memory::write(void* addr, const T& value)
{
	auto [buffer, size] = buf();

	if (sizeof(T) > size)
	{
		log("Value too big");
		throw std::exception("value too big");
	}

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

	memcpy(buffer, &value, sizeof(T));

	if (!write_raw(addr, sizeof(T)))
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
void memory::write(uintptr_t addr, const T& value)
{
	write(PVOID(addr), value);
}
