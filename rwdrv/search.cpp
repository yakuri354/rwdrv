#include "search.hpp"
#include "skcrypt.hpp"

PVOID Search::KernelBase = nullptr;
ULONG Search::KernelSize = 0;
PVOID Search::Win32kBase = nullptr;
ULONG Search::Win32kSize = 0;
PVOID Search::RtBase = nullptr;
ULONG Search::RtSize = 0;
