#include "util.hpp"

__forceinline NTSTATUS ALL_SUCCESS(NTSTATUS status)
{
	return status;
}

template <typename ...A>
__forceinline NTSTATUS ALL_SUCCESS(NTSTATUS status, A ...args)
{
	if (NT_SUCCESS(status))
	{
		return ALL_SUCCESS(args...);
	}
	return status;
}