#pragma once

typedef unsigned short CTLTYPE;
#define CTLCODE constexpr CTLTYPE

#define HOOKED_FN_NAME "FindThreadPointerData"
#define HOOKED_FN_MODULE "User32.dll"

constexpr UINT64 CTL_MAGIC = 0xDEADBEEFFEEBDAED;
CTLCODE CTL_INIT_MAGIC = 'I';

typedef UINT64(__fastcall *PHookFn)(UINT64 a1, UINT16 a2);
typedef UINT64(__fastcall* _WmiTraceMessage)(UINT64, UINT64, UINT64, UINT64, UINT64, UINT64, UINT64);

constexpr size_t SHMEM_SIZE = 1024 * 4;

namespace Ctl
{
	CTLCODE PING = 0x01;
	CTLCODE INIT_FINAL = 0x10;
	CTLCODE SET_TARGET = 0x20;
	CTLCODE READ_TARGET_MEM = 0x21;
	CTLCODE WRITE_TARGET_MEM = 0x22;
}

struct GenericReadWrite
{
	void* Va;
	unsigned char buffer[SHMEM_SIZE - sizeof(void*)];
};