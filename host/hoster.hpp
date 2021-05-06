#pragma once
#include "provider.hpp"
#include "lazy_importer.hpp"

#undef RGB

struct hoster
{
	using logger_t = void __fastcall(const char*);

	explicit hoster(provider& _mem, logger_t *_logger): mem(_mem), logger(_logger) {}

	template <typename ...A>
	void logH(const char* fmt, A... args) const
	{
		auto const needed = snprintf(nullptr, 0, fmt, args...);
		const auto cad = PCHAR(_malloca(needed + 1));
		if (cad == nullptr) throw std::exception("not enough stack space for string formatting");
		snprintf(cad, needed + 1, fmt, args...); 
		logger(cad);
	}

	provider& mem;
	logger_t* logger;
};
