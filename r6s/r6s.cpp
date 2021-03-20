#include "r6s.hpp"

r6s::game::game(memory& _mem): mem(_mem)
{
	const auto name = std::wstring(xs(GAME_NAME));
	const auto pid = util::process_id(name);
	const auto status = mem.attach(pid);

	if (!pid || !status)
	{
		log("Could not find R6S");
		throw std::exception("could not find r6s");
	}

	base = mem.base(pid);
	dbgLog("Game object initialized");
}

uintptr_t r6s::game::game_manager() const
{
	marker();
	auto var = mem.read<uintptr_t>(base + offsets::game_manager);
	var -= 0x51;
	var = _rotl64(var, 0xC);
	var -= 0x5Bi64;
	return var;
}

uintptr_t r6s::game::glow_manager() const // TODO update
{
	marker();
	return mem.read<uintptr_t>(base + offsets::glow_manager);
}

uintptr_t r6s::game::round_manager() const
{
	marker();
	auto enc = mem.read<uintptr_t>(base + offsets::round_manager);
	
}

uintptr_t r6s::game::profile_manager() const
{
	marker();
	return mem.read<uint64_t>(base + offsets::profile_manager);
}

uintptr_t r6s::game::profile() const
{
	marker();
	auto var = mem.read<uint64_t>(profile_manager() + 0x28);
	var -= 6;
	var = _rotl64(var, 1);
	var ^= 0x1527809D30772AFC;
	return var;
}

uintptr_t r6s::game::local_player() const
{
	marker();
	auto enc = mem.read<uint64_t>(profile() + 0x58);
	enc ^= 0x44CBF16C96879DE8;
	enc += 0x87523D08B19E922B;
	enc = _rotl64(enc, 0x23);
	return enc;
}


uint32_t r6s::game::entity_count() const
{
	marker();
	auto count = mem.read<uintptr_t>(game_manager() + offsets::entity_count);
	count -= 0x52;
	count = ((count >> 29 | count << 35) ^ 0xC9B8147FF443FC5F) & 0x3FFFFFFF;

	return static_cast<uint32_t>(count);
}

uint64_t r6s::game::entity_list() const
{
	auto list = mem.read<uintptr_t>(game_manager() + offsets::entity_list);
	list -= 0x52;
	list = ((list >> 29) | (list << 35)) ^ 0xC9B8147FF443FC5F;

	return list;
}

uintptr_t r6s::game::entity_info(uintptr_t entity) const
{
	marker();
	auto info = mem.read<uintptr_t>(entity + 0x50);
	info = _rotl64(info, 1);
	info -= 0x53;
	return info ^ 0x84B4E3BD4F9014AF;
}

uint32_t r6s::game::game_state() const
{
	marker();
	auto var = mem.read<uint32_t>(round_manager() + 0x90);
	var += 0x4AF93094;
	var ^= 0x9A96FFCF;
	return _rotl(var, 7);
}

void r6s::game::cav_esp(bool active) const
{
	const auto count = entity_count();

	for (uint32_t player = 0; player < count; player++)
	{
		auto entity_object = mem.read<uint64_t>(entity_list() + uint64_t(player) * 0x8);
		entity_object = entity_info(entity_object);

		auto entity_info = mem.read<uint64_t>(entity_object + 0x18);
		entity_info = mem.read<uint64_t>(entity_info + 0xD8);

		for (uint32_t current = 0x80; current < 0xF0; current += 4)
		{
			const auto marker_icon = mem.read<uint64_t>(entity_info + current);

			if (marker_icon == 0)
				continue;

			const auto check_for_invalid = mem.read<uint64_t>(marker_icon);
			
			if (check_for_invalid != (uintptr_t(base) + offsets::vt_marker)) continue;

			const auto state = game_state();

			if (state && active)
				mem.write<uint8_t>(marker_icon + 0x220, 0x85);
			else
				mem.write<uint8_t>(marker_icon + 0x220, 0x84);
		}
	}
}

void r6s::game::glow(bool active) const
{
	
}
