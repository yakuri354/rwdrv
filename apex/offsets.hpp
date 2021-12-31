#pragma once
#include <cstdint>

namespace apex
{
	namespace offsets
	{
		constexpr auto version = "v3.0.4.257"; // Updated
		
		constexpr uintptr_t entity_list = 0x18eda78; // cl_entitylist
		constexpr uintptr_t local_player = 0x1c9d198; // LocalPlayer

		constexpr uint32_t item_glow_val = 1363184265;

		namespace entity
		{
			constexpr auto size = 0x4610;
			constexpr auto origin = 0x14C;
			constexpr auto entries = 0x10000;
		}

		namespace player
		{
			constexpr auto team = 0x0448; // m_iTeamNum
			constexpr auto health = 0x0438; // m_iHealth
			constexpr auto name = 0x0589; // m_iName
			constexpr auto sig_name = 0x0580; // m_iSignifierName
			constexpr auto shield = 0x0170; // m_shieldHealth
			constexpr auto max_shield = 0x0174; // m_shieldHealth +0x4
		}

		namespace glow
		{
			constexpr auto context = 0x3C8;
			constexpr auto lifetime = 0x3A4;
			constexpr auto distance = 0x3B4;
			constexpr auto type = 0x2C4;
			constexpr auto color = 0x1D0;
			constexpr auto visible_type = 0x3d0;
			constexpr auto h_function_bits = 0x2c0;
		}

		namespace etc
		{
			constexpr uintptr_t name_list = 0x81af640;
			constexpr uintptr_t view_render = 0x40bf468;
			constexpr uintptr_t view_matrix = view_render + 0x1b3bd0;
		}
	}
}
