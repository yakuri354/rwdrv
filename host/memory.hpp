#pragma once
#include <cstdint>
#include <exception>
#include "pch.h"
#include "../rwdrv/comms.hpp"

typedef uint64_t (drv_ctl_t)(uint32_t a1, uint32_t a2);
typedef MEMORY_BASIC_INFORMATION mem_info;

struct rwdrv;

struct driver_handle
{
	friend rwdrv;

	driver_handle(drv_ctl_t* p_ctl) : ctl(p_ctl)
	{
	}

private:
	drv_ctl_t* ctl;
};

struct memory
{
	virtual void attach(uint32_t pid) = 0;
	virtual uintptr_t base() = 0;
	virtual void read_raw(const void* addr, void* buf, size_t size) = 0;
	virtual void write_raw(void* addr, const void* buf, size_t size) = 0;

	template <typename T>
	T read(void* addr);

	template <typename T>
	T read(uintptr_t addr);

	template <typename T>
	void write(void* addr, const T& value);

	template <typename T>
	void write(uintptr_t addr, const T& value);

	virtual ~memory() = default;
};

namespace ex
{
	struct host_exception : std::exception {};
	struct process_not_found : host_exception
	{
		char const* what() const override
		{
			return "process not found";
		}
	};

	struct invalid_memory_access : host_exception
	{
		explicit invalid_memory_access(const void* ref): addr(ref), buf{0}
		{
			snprintf(const_cast<char*>(buf), 64, "invalid memory referenced: [0x%p]", addr);
		}
		char const* what() const override
		{
			return buf;
		}

	private:
		const void* addr;
		const char buf[64];
	};

	struct driver_error : host_exception
	{
		explicit driver_error(NTSTATUS status): status_(status), buf{0}
		{
			snprintf(const_cast<char*>(buf), 64, "unknown driver error: 0x%lX", status_);
		}
		char const* what() const override
		{
			return buf;
		}
	private:
		const NTSTATUS status_;
		const char buf[64];
	};
}

struct rwdrv : memory
{
	rwdrv(const driver_handle& driver);

	uintptr_t base() override;
	void attach(uint32_t pid) override;
	void read_raw(const void* addr, void* buf, size_t size) override;
	void write_raw(void* addr, const void* buf, size_t size) override;

private:
	uint64_t send_req()
	{
#pragma warning(suppress : 4311)
#pragma warning(suppress : 4302)
		return drv.ctl(uint32_t(uint64_t(&ctl) >> 32), uint32_t(&ctl)); // NOLINT(clang-diagnostic-pointer-to-int-cast)
	}

	const driver_handle& drv;
	Control ctl;
};

struct winapi : memory
{
	[[deprecated("Winapi selected")]] // A compile time warning
	winapi() = default;
	
	uintptr_t base() override;
	void attach(uint32_t pid) override;
	void read_raw(const void* addr, void* buf, size_t size) override;
	void write_raw(void* addr, const void* buf, size_t size) override;

private:
	HANDLE h_proc = nullptr;
	uint32_t pid = 0;
};

template <typename T>
T memory::read(void* addr)
{
	T local;

	read_raw(addr, &local, sizeof(T));

	return local;
}

template <typename T>
T memory::read(const uintptr_t addr)
{
	return read<T>(PVOID(addr));
}

template <typename T>
void memory::write(void* addr, const T& value)
{
	write_raw(addr, reinterpret_cast<const void*>(&value), sizeof(T));
}

template <typename T>
void memory::write(uintptr_t addr, const T& value)
{
	write(PVOID(addr), value);
}
