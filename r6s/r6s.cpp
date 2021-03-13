#include "r6s.hpp"

r6s::game::game(memory& _mem): mem(_mem)
{
	const auto name = std::wstring(xs(L"RainbowSix.exe"));
	const auto pid = util::process_id(name);
	const auto status = mem.attach(pid);

	if (!status)
	{
		log(xs("[umc] Could not find R6S"));
		throw std::exception("could not find r6s");
	}

	base = PVOID(mem.base(pid));
}

uintptr_t r6s::game::game_manager() const
{
	return mem.read<uintptr_t>(uint64_t(base) + (offsets::game_manager));
}

uintptr_t r6s::game::round_manager() const
{
	return mem.read<uintptr_t>(uint64_t(base) + (offsets::round_manager));
}

uintptr_t r6s::game::entity_list() const
{
	auto el = game_manager();
	el = mem.read<uintptr_t>(el + 0xE0);

	el ^= 0x53;
	el += 0xEEBD43B91E3D5D54;
	el ^= 0x1FEC13843E78A654;

	return el;
}

uint32_t r6s::game::entity_count() const
{
	auto ec = mem.read<uintptr_t>(game_manager() + 0xE8);

	ec ^= 0x53;
	ec += 0xEEBD43B91E3D5D54;
	ec ^= 0x1FEC13843E78A654;

	return uint32_t(ec ^ 0x18C0000000);
}

uintptr_t r6s::game::entity_info(uintptr_t entity) const
{
	auto info = mem.read<uintptr_t>(entity + 0x50);
	info = _rotl64(info, 1);
	info -= 0x53;
	return info ^ 0x84B4E3BD4F9014AF;
}

bool r6s::game::game_state() const
{
	const auto phase = mem.read<uint8_t>(round_manager() + 0x300);

	return phase == 2 || phase == 3;
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

	return;
}
