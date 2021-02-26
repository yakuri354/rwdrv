#pragma once
#include "pch.h"
#include "../loader/lazy_importer.hpp"
#include <ctime>
#include <chrono>
#include <random>

NTSTATUS NTAPI RtlCreateUserThread(
	HANDLE ProcessHandle,
	PSECURITY_DESCRIPTOR SecurityDescriptor,
	BOOLEAN CreateSuspend,
	ULONG StackZeroBits,
	PULONG StackReserved,
	PULONG StackCommit,
	void* StartAddress,
	void* StartParameter,
	PHANDLE ThreadHandle,
	void* ClientID
);


void SpoofThread(void* thread, HMODULE& hModule);