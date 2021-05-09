#include "apex.hpp"

apex::game::game(provider& mem): base(0), mem(mem)
{
	mem.attach(util::process_id(APEX_NAME));

	base = mem.base();
	dbgLog("Game object initialized, base: [0x%llx]", base);
}

uintptr_t apex::game::entity_list() const
{
	return base + offsets::entity_list;
}

uintptr_t apex::game::local_player() const
{
	return mem.read<uintptr_t>(base + offsets::local_player);
}

uintptr_t apex::game::get_entity_by_id(const uint32_t id) const
{
	return mem.read<uintptr_t>(entity_list() + (uint64_t(id) << 5));
}

void apex::game::process_entities(const entity& local_player) const
{
	for (auto i = 0; i < entity_count; i++)
	{
		auto entity_ptr = get_entity_by_id(i);
		// dbgLog("Found entity [0x%llx]", entity_ptr);
		if (entity_ptr == 0 /*|| entity_ptr == local_player.ptr*/) continue;

		dbgLog("Processing entity [0x%llx]", entity_ptr);
		mem.read<uintptr_t>(entity_ptr);
		dbgLog("Read ent");
		//auto entity = std::make_unique<apex::entity>(entity_ptr, mem);
		auto entity = apex::entity(entity_ptr, mem); // TODO Fix
		dbgLog("Read entS");
		const auto health = entity.get_health();
		const auto player = entity.is_player();
		const auto [x, y, z] = entity.get_position();
		mem.write(entity_ptr + offsets::entity::origin, vector{ x, y, 0.5f });

		dbgLog("health %d, player %d", health, player);
		dbgLog("x %.6f, y %.6f, z %.6f", x, y, z);

		if (!player)
		{
			mem.write(entity_ptr + offsets::glow::item_glow, offsets::item_glow_val);
			continue;
		}
		// else if (!player || health < 0 || health > 100)
		// {
		// 	dbgLog("Invalid entity, continuing");
		// 	continue;
		// }

		// TODO Something more

		highlight_entity(entity.ptr, {61.f, 2.f, 2.f}, {101, 101, 46, 90});
	}
}

void apex::game::highlight_entity(uintptr_t entity, color col, glow_mode mode) const
{
	dbgLog("Highlighting entity [0x%llx]", entity);

	// auto glow_time = 5000.f;

	mem.write(entity + offsets::glow::type, mode);
	mem.write(entity + offsets::glow::color, col);

	// mem.write(entity + offsets::glow::distance, 40000.f);
	//mem.write(entity + offsets::glow::lifetime, glow_time);
	mem.write(entity + offsets::glow::context, 7);
	mem.write(entity + offsets::glow::visible_type, 2);

	// glow_time -= 1.f;
	// mem.write<fade>(entity + offsets::glow::fade,
	//                     {0x34000000, 0x34000000, glow_time, glow_time, glow_time, glow_time});
}
