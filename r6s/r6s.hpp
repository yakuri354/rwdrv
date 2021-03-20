#pragma once
#include <cstdint>
#include "../umcontrol/memory.hpp"
#include "util.h"

namespace r6s
{
	namespace offsets // TODO
	{
		constexpr auto game_manager = 0x7154CF0;
		constexpr auto profile_manager = 0x715C5A8;
		constexpr auto round_manager = 0x732D020;

		constexpr auto entity_list = 0xE0;
		constexpr auto entity_count = 0xE8;
	}

	class game
	{
		uintptr_t game_manager() const;
		uintptr_t glow_manager() const;
		uintptr_t round_manager() const;
		uintptr_t entity_list() const;
		uintptr_t profile_manager() const;
		uintptr_t profile() const;
		uintptr_t local_player() const;
		uint32_t entity_count() const;
		uintptr_t entity_info(uintptr_t entity) const;
		uint32_t game_state() const;

		memory& mem;
		uintptr_t base;

	public:
		explicit game(memory& _mem);

		void cav_esp(bool active) const;
		void glow(bool active) const;
	};
}
