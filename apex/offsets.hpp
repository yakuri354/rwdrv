#pragma once
#include <cstdint>

namespace apex
{
	namespace offsets
	{
		constexpr auto entity_size = 0x4410;

		constexpr auto entity_list = 0x18DB438; // cl_entitylist
		constexpr auto local_player = 0x1C8AA98; // LocalPlayer

		constexpr auto item_glow_val = 0x51408A89;

		namespace entity
		{
			constexpr auto origin = 0x14C;
		}

		namespace player
		{
			constexpr auto team = 0x0450; // m_iTeamNum
			constexpr auto health = 0x0440; // m_iHealth
			constexpr auto name = 0x0589; // m_iName
			constexpr auto sig_name = 0x0580; // m_iSignifierName
			constexpr auto shield = 0x0170; // m_shieldHealth
			constexpr auto max_shield = 0x0174; // m_shieldHealth +0x4
			constexpr auto visible_time = 0x1A4C; // m_visibletime
		}

		namespace glow
		{
			constexpr auto context = 0x3C8;
			constexpr auto lifetime = 0x3A4;
			constexpr auto distance = 0x3B4;
			constexpr auto type = 0x2C4;
			constexpr auto color = 0x1D0;
			constexpr auto visible_type = 0x3d0;
			constexpr auto fade = 0x388;

			constexpr auto item_glow = 0x2c0;
		}
	}
}
