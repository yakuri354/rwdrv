#pragma once
#include "memory.hpp"
#include "lazy_importer.hpp"

#undef RGB

struct hoster
{
	using logger_t = void __fastcall(const char*);

	explicit hoster(memory& _mem, logger_t *_logger): mem(_mem), logger(_logger) {}

	template <typename ...A>
	void logH(const char* fmt, A... args) const
	{
		auto const needed = snprintf(nullptr, 0, fmt, args...);
		const auto cad = PCHAR(_malloca(size_t(needed) + 2Ui64));
		if (cad == nullptr) throw std::exception("not enough stack space for string formatting");
		snprintf(cad, size_t(needed) + 1Ui64, fmt, args...);
		cad[needed] = '\n';
		cad[needed + 1] = NULL;
		logger(cad);
	}

	memory& mem;
	logger_t* logger;
};
