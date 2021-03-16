#include "apex.hpp"

apex::game::game(memory& mem): memory_(mem), base(0)
{
	const auto name = std::wstring(xs(apex::name));
	const auto pid = util::process_id(name);
	const auto status = mem.attach(pid);

	if (!pid || !status)
	{
		log("Could not find Apex");
		throw std::exception("could not find the process");
	}

	base = mem.base(pid);
	logD("Game object initialized");
}

uintptr_t apex::game::entity_list() const
{
	return base + offsets::entity_list;
}

uintptr_t apex::game::local_player() const
{
	return memory_.read<uintptr_t>(base + offsets::local_entity);
}

uintptr_t apex::game::get_entity_by_id(const uint32_t id) const
{
	return memory_.read<uintptr_t>(base + offsets::entity_list + (uint64_t(id) << 5));
}

void apex::game::process_entities(uintptr_t entity_list, const entity& local_player) const
{
	for (auto i = 0; i < entity_count; i++)
	{
		auto entity_ptr = get_entity_by_id(i);
		if (entity_ptr == 0 || entity_ptr == local_player.ptr) continue;

		auto entity = std::make_unique<apex::entity>(entity_ptr, memory_);

		const auto health = entity->get_health();

		if (!entity->is_player() || health < 0 || health > 100
			|| entity->ptr == local_player.ptr)
			continue;

		// TODO Something more

		highlight_entity(entity->ptr, { 3.f, 0.f, 0.f }, { 101, 102, 96, 75 });
	}
}

void apex::game::highlight_entity(uintptr_t entity, apex::color col, apex::glow_mode mode) const
{
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
