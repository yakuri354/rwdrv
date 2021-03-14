#pragma once
#include <cstdint>
#include "../umcontrol/memory.hpp"
#include "util.h"

namespace r6s
{	
	namespace offsets
	{
		constexpr auto game_manager = 0x6E444A0;
		constexpr auto glow_manager = 0x5E10620;
		constexpr auto fov_manager = 0xE39BCCD3;
		constexpr auto profile_manager = 0x5E380E0;
		constexpr auto network_manager = 0x2B1319B;
		constexpr auto round_manager = 0x70D6810;

		constexpr auto content_manager = 0x5E20A90;
		constexpr auto vt_marker = 0x3938bb0;
		constexpr auto noclip_manager = 0x5AFC450;
		constexpr auto enviroment_manager = 0x5E10620;
		constexpr auto spoof_spectate_manager = 0x6D1E278;

		constexpr auto cav = 0x220;
		constexpr auto rgb = 0xD0;
		constexpr auto spoof = 0x5D;
	}

	class game
	{
		[[nodiscard]] uintptr_t game_manager() const;
		[[nodiscard]] uintptr_t glow_manager() const;
		[[nodiscard]] uintptr_t round_manager() const;
		[[nodiscard]] uintptr_t entity_list() const;
		[[nodiscard]] uint32_t entity_count() const;
		[[nodiscard]] uintptr_t entity_info(uintptr_t entity) const;
		[[nodiscard]] bool game_state() const;

		memory& mem;
		void* base;

	public:
		explicit game(memory& _mem);
		
		void cav_esp(bool active) const;
		void glow(bool active) const;
	};
}
