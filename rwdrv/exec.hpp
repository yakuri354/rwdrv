#pragma once
#include <intrin.h>
#include "clear.hpp"
#include "physmem.hpp"
#include "common.hpp"
#include "comms.hpp"
#include "config.hpp"

NTSTATUS ExecuteRequest(Control* ctl, DriverState *driverState);