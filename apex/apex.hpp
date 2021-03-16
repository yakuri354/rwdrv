#pragma once
// #include "../umcontrol/hostframework.h"
#include "../umcontrol/memory.hpp"
#include "../umcontrol/util.hpp"
#include "entity.h"
#include <cstdint>

namespace apex {

	constexpr auto name = L"EasyAntiCheat_launcher.exe"; // r5apex
	constexpr auto entity_count = 100;

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
		explicit game(memory& mem);

		uintptr_t entity_list() const;
		uintptr_t local_player() const;
		uintptr_t get_entity_by_id(uint32_t id) const;
		void process_entities(uintptr_t entity_list, const entity& local_player) const;
		void highlight_entity(uintptr_t entity, color col, apex::glow_mode mode) const;

	private:
		memory& memory_;
		uintptr_t base;
	};
}