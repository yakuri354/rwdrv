#pragma once
#include <intrin.h>
#include "clear.hpp"
#include "physmem.hpp"
#include "common.hpp"
#include "comms.hpp"
#include "config.hpp"

NTSTATUS ExecuteRequest(UINT32 ctlCode, UINT16 magic, UINT32 param, DriverState *driverState);