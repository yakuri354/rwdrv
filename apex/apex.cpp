#include "apex.hpp"

apex::game::game(memory& mem): base(0), mem(mem)
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

uintptr_t apex::game::get_entity_ptr_by_id(const uint32_t id) const
{
	return mem.read<uintptr_t>(entity_list() + (uint64_t(id) << 5));
}

void apex::game::process_entities(const entity& local_player) const
{
	for (auto i = 0; i < offsets::entity::entries; i++)
	{
		auto entity_ptr = get_entity_ptr_by_id(i);
		if (entity_ptr == 0 /*|| entity_ptr == local_player.ptr*/) continue;

		dbgLog("Processing entity [0x%llx]", entity_ptr);
		mem.read<uintptr_t>(entity_ptr);
		auto entity = std::make_unique<apex::entity>(entity_ptr, mem);
		auto cl = client_class::get(mem, entity_ptr);
		const auto health = entity->get_health();
		const auto player = entity->is_player();
		const auto [x, y, z] = entity->get_position();
		mem.write(entity_ptr + offsets::entity::origin, vector{x, y, 0.2f});


		dbgLog("health %d, player %d class %s", health, player, cl->name(mem).c_str());
		dbgLog("x %.4f, y %.4f, z %.4f", x, y, z);

		highlight_entity(*entity, {61.f, 2.f, 2.f}, {101, 101, 60, 90});
	}
}

void apex::game::highlight_entity(entity& entity, color col, glow_mode mode) const
{
	if (entity.is_player())
	{
		mem.write(entity.ptr + offsets::glow::type, mode);
		mem.write(entity.ptr + offsets::glow::color, col);
		mem.write(entity.ptr + offsets::glow::context, 1);
		mem.write(entity.ptr + offsets::glow::visible_type, 2);
	} else if (entity.is_item())
		mem.write(entity.ptr + offsets::glow::h_function_bits, offsets::item_glow_val);
}
