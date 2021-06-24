#pragma once

// TODO Extensive config

// --- RWDRV ---

// Use PhysMem instead of MmCopyVirtualMemory
#define USE_PHYSMEM false

// --- MAPPER ---

// Backing driver for the mapper. [ intel / mhyprot ]
#define MAPPER_BACKEND mhyprot

// --- HOST ---

// Memory access provider for the cheat [ winapi / rwdrv / mhyprot ]
#define MEMORY_ENGINE rwdrv