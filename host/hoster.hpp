#pragma once
#include "memory.hpp"
#include "lazy_importer.hpp"

#undef RGB

struct hoster
{
	using logger_t = void __fastcall(char*);

	explicit hoster(memory& _mem, logger_t *_logger): mem(_mem), logger(_logger) {}

	memory& mem;
	logger_t* logger;
};
