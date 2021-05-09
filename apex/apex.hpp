#pragma once
// #include "../umcontrol/hostframework.h"
#include "cheat.hpp"
#include "../host/dbg.hpp"
#include "entity.hpp"
#include <cstdint>
#include <memory>

#define APEX_NAME xs(L"EasyAntiCheat_launcher.exe")

namespace apex {
	constexpr auto entity_count = 100; // 0x10000 ?

	struct glow_mode
	{
		uint8_t
			general_glow,
			border_glow,
			border_size,
			transparent_level;
	};

	struct color
	{
		float r, g, b;
	};

	struct fade
	{
		int a, b;
		float c, d, e, f;
	};
	
	struct game
	{
		explicit game(provider& mem);
		
		uintptr_t entity_list() const;
		uintptr_t local_player() const;
		uintptr_t get_entity_by_id(uint32_t id) const;
		void process_entities(const entity& local_player) const;
		void highlight_entity(uintptr_t entity, color col, glow_mode mode) const;

		uintptr_t base;
	
	private:
		
		provider& mem;
	};
}