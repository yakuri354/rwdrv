#pragma once
#include "../host/provider.hpp"
#include "offsets.hpp"
#include "math.hpp"

namespace apex
{
	struct entity
	{
		entity(uintptr_t pointer, provider& mem);
		
		uintptr_t ptr;
		uint8_t buffer[offsets::entity_size];

		vector get_position();
		bool is_player();
		int get_health();
	};
}
