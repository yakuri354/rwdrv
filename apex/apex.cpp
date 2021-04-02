#include "apex.hpp"

apex::game::game(provider& mem): memory_(mem), base(0)
{
	const auto name = std::wstring(apex::name);
	const auto pid = util::process_id(name);
	const auto status = mem.attach(pid);

	if (!pid || !status)
	{
		log("Could not find Apex");
		throw std::exception("could not find the process");
	}

	base = mem.base(pid);
	dbgLog("Game object initialized, base: [0x%llx]", base);
}

uintptr_t apex::game::entity_list() const
{
	return base + offsets::entity_list;
}

uintptr_t apex::game::local_player() const
{
	return memory_.read<uintptr_t>(base + offsets::local_player);
}

uintptr_t apex::game::get_entity_by_id(const uint32_t id) const
{
	return memory_.read<uintptr_t>(entity_list() + (uint64_t(id) << 5));
}

void apex::game::process_entities(const entity& local_player) const
{
	for (auto i = 0; i < entity_count; i++)
	{
		auto entity_ptr = get_entity_by_id(i);
		// dbgLog("Found entity [0x%llx]", entity_ptr);
		if (entity_ptr == 0 /*|| entity_ptr == local_player.ptr*/) continue;

		dbgLog("Processing entity [0x%llx]", entity_ptr);

		auto entity = std::make_unique<apex::entity>(entity_ptr, memory_);

		const auto health = entity->get_health();
		const auto player = entity->is_player();
		const auto pos = entity->get_position();
		
		dbgLog("health %d, player %d", health, player);
		dbgLog("x %.6f, y %.6f, z %.6f", pos.x, pos.y, pos.z);

		if (!entity->is_player() || health < 0 || health > 100) {
			dbgLog("Invalid entity, continuing");
			continue;
		}

		// TODO Something more

		highlight_entity(entity->ptr, { 0.f, 3.f, 0.f }, { 101, 102, 96, 90 });
	}
}

void apex::game::highlight_entity(uintptr_t entity, color col, glow_mode mode) const
{
	dbgLog("Highlighting entity [0x%llx]", entity);

	auto glow_time = 5000.f;

	memory_.write(entity + offsets::glow::type, mode);
	memory_.write(entity + offsets::glow::color, col);

	memory_.write(entity + offsets::glow::distance, 40000.f);
	memory_.write(entity + offsets::glow::lifetime, glow_time);
	memory_.write(entity + offsets::glow::context, 1);
	memory_.write(entity + offsets::glow::visible_type, 1);

	glow_time -= 1.f;
	memory_.write<fade>(entity + offsets::glow::fade,
	                    { 0x34000000, 0x34000000, glow_time, glow_time, glow_time, glow_time });
}