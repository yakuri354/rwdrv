#pragma once

typedef unsigned short CTLTYPE;
#define CTLCODE constexpr CTLTYPE

#define HOOKED_FN_NAME "OpenInputDesktop"
#define HOOKED_FN_MODULE "User32.dll"

constexpr UINT32 CTL_MAGIC = 0xDEADBEEF;;

typedef UINT64(__fastcall *PHookFn)(UINT32, UINT16, UINT32);
typedef UINT64(__fastcall *_WmiTraceMessage)(UINT64, UINT64, UINT64, UINT64, UINT64);

constexpr size_t SHMEM_SIZE = 1024 * 4;

namespace Ctl
{
	CTLCODE PING			 = 0x01;
	CTLCODE INIT			 = 0x10;
	CTLCODE SET_TARGET		 = 0x20;
	CTLCODE READ_TARGET_MEM  = 0x30;
	CTLCODE READ_PHYS_MEM	 = 0x31;
	CTLCODE WRITE_TARGET_MEM = 0x40;
	CTLCODE WRITE_PHYS_MEM	 = 0x41;
}

struct GenericReadWrite
{
	void* Addr;
	unsigned char buffer[SHMEM_SIZE - sizeof(void*)];
};