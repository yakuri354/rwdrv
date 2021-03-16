#pragma once

typedef unsigned CTLTYPE;
#define CTLSTATUSTYPE unsigned __int64
#define CTLSTATUSBASE 0xFFFEFFFF00000000u
#define CTLCODE constexpr CTLTYPE

#define HOOKED_FN_NAME "OpenInputDesktop"
#define HOOKED_FN_MODULE "User32.dll"

constexpr unsigned __int16 CTL_MAGIC = 0xFFAB; // Special calls for initialization
constexpr unsigned __int16 INIT_MAGIC = 0xFFAC;

typedef unsigned __int64 (__fastcall *PHookFn)(unsigned __int32, unsigned __int16, unsigned __int32);
typedef unsigned __int64 (__fastcall *_WmiTraceMessage)(unsigned __int64, unsigned __int64, unsigned __int64, unsigned __int64, unsigned __int64);

constexpr size_t SHMEM_SIZE = 1024 * 4;

namespace Ctl
{
	CTLCODE PING = 0x01;
	CTLCODE STATUS = 0x10;
	CTLCODE UNLOAD = 0x0F;
	CTLCODE SET_TARGET = 0x20;
	CTLCODE GET_BASE_ADDR = 0x21;
	CTLCODE READ_VIRTUAL = 0x30;
	CTLCODE READ_PHYSICAL = 0x31;
	CTLCODE WRITE_VIRTUAL = 0x40;
	CTLCODE WRITE_PHYSICAL = 0x41;
}

inline unsigned __int64 NT2CTL(unsigned long status)
{
	return CTLSTATUSBASE + status;
}
