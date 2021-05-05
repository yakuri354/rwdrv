#pragma once
#include "provider.hpp"
#include "lazy_importer.hpp"

#undef RGB

struct hoster
{
	using logger_t = void __fastcall(const char*);

	explicit hoster(provider& _mem, logger_t *_logger): mem(_mem), logger(_logger) {}

	provider& mem;
	logger_t* logger;
};
