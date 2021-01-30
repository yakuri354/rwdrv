#pragma once
#include "struct.h"
#define log(format, ...) DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, format, __VA_ARGS__)
#define BB_POOL_TAG 'enoB'


typedef struct _POOL_TRACKER_BIG_PAGES
{
	volatile ULONGLONG Va;                                                  //0x0
	ULONG Key;                                                              //0x8
	ULONG Pattern;                                                        //0xc
	ULONG PoolType;                                                      //0xc
	ULONG SlushSize;                                                     //0xc
	ULONGLONG NumberOfBytes;                                                //0x10
} POOL_TRACKER_BIG_PAGES, * PPOOL_TRACKER_BIG_PAGES;