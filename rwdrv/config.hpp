#pragma once

// TODO Extensive config

// --- RWDRV ---

// Use PhysMem instead of MmCopyVirtualMemory
#define USE_PHYSMEM false

// --- HOST ---

// TODO Memory access provider for the host [ winapi / rwdrv ]
#define MEMORY_ENGINE rwdrv