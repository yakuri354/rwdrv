#pragma once

typedef unsigned CTLTYPE;
#define CTLSTATUSTYPE unsigned __int64
#define CTLSTATUSBASE 0xFFFEFFFF00000000u
#define CTLCODE constexpr CTLTYPE

#define HOOKED_FN_NAME "OpenInputDesktop"
#define HOOKED_FN_MODULE "User32.dll"

constexpr unsigned __int16 CTL_MAGIC = 0xFFAB;

typedef unsigned __int64 (__fastcall *PHookFn)(unsigned __int32, unsigned __int16, unsigned __int32);
typedef unsigned __int64 (__fastcall *_WmiTraceMessage)(unsigned __int64, unsigned __int64, unsigned __int64,
                                                        unsigned __int64, unsigned __int64);
struct Control
{
	CTLTYPE CtlCode;
	void* Source;
	void* Target;
	size_t Size;
	int Pid;

	unsigned __int64 Result;
};

namespace Ctl
{
	CTLCODE PING = 0x01;
	CTLCODE CLEAN = 0x02;
	CTLCODE UNLOAD = 0x0F;
	CTLCODE GET_BASE_ADDR = 0x21;
	CTLCODE VIRT_READ = 0x30;
	CTLCODE VIRT_WRITE = 0x31;
	CTLCODE VIRT_QUERY = 0x3F;
	CTLCODE PHYS_MEMCPY = 0x40;
}

inline unsigned __int64 NT2CTL(unsigned long status)
{
	return CTLSTATUSBASE + status;
}

inline bool CTL_SUCCESS(CTLSTATUSTYPE status)
{
	// Reset last 32 bit and check if status is valid
	return (status >> 32) << 32 == CTLSTATUSBASE && int(status) >= 0;
}