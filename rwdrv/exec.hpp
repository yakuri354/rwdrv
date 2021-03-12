#pragma once
#include <intrin.h>
#include "clear.hpp"
#include "physmem.hpp"
#include "common.hpp"
#include "comms.hpp"

NTSTATUS ExecuteRequest(UINT32 ctlCode, UINT32 param, DriverState *driverState);