#pragma once
#define CTLCODE constexpr unsigned

constexpr char HOOKED_FN_NAME[] = "OpenInputDesktop";
constexpr char HOOKED_FN_MODULE[] = "User32.dll";

CTLCODE CTL_MAGIC = 0xDEADBEEF;

typedef UINT(*PHookFn)(UINT, UINT, UINT);

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