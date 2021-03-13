#pragma once

typedef unsigned CTLTYPE;
#define CTLSTATUSTYPE unsigned __int64
#define CTLSTATUSBASE 0xFFFEFFFF00000000u
#define CTLCODE constexpr CTLTYPE

#define HOOKED_FN_NAME "OpenInputDesktop"
#define HOOKED_FN_MODULE "User32.dll"

constexpr UINT16 CTL_MAGIC = 0xFFAB; // Special calls for initialization
constexpr UINT16 INIT_MAGIC = 0xFFAC;

typedef UINT64 (__fastcall *PHookFn)(UINT32, UINT16, UINT32);
typedef UINT64 (__fastcall *_WmiTraceMessage)(UINT64, UINT64, UINT64, UINT64, UINT64);

constexpr size_t SHMEM_SIZE = 1024 * 4;

namespace Ctl
{
	CTLCODE PING = 0x01;
	CTLCODE STATUS = 0x10;
	CTLCODE UNLOAD = 0x0F;
	CTLCODE SET_TARGET = 0x20;
	CTLCODE GET_BASE_ADDR = 0x21;
	CTLCODE READ_TARGET_MEM = 0x30;
	CTLCODE READ_PHYS_MEM = 0x31;
	CTLCODE WRITE_TARGET_MEM = 0x40;
	CTLCODE WRITE_PHYS_MEM = 0x41;
}

inline unsigned __int64 NT2CTL(NTSTATUS status)
{
	return CTLSTATUSBASE + ULONG(status);
}
