#include "entity.hpp"

apex::entity::entity(uintptr_t pointer, memory& mem): ptr(pointer), buffer{ 0 }, cl_class(client_class::get(mem, pointer)), mem(mem)
{
	if (pointer == NULL) throw ex::invalid_memory_access(nullptr);
	mem.read_raw(reinterpret_cast<void*>(pointer), buffer, offsets::entity::size);
}

vector apex::entity::get_position()
{
	return *reinterpret_cast<vector*>(buffer + offsets::entity::origin);
}

bool apex::entity::is_player() const
{
	// if (*reinterpret_cast<uintptr_t*>(buffer + offsets::player::name) == 125780153691248) return true; // 'player'
	//
	// auto* const str1 = reinterpret_cast<char*>(buffer + offsets::player::team);
	//
	// return strlen(str1) > 0 && (*reinterpret_cast<int*>(str1) == 97);

	return this->cl_class->name(mem) == "CPlayer";
}

bool apex::entity::is_item() const
{
	return this->cl_class->name(mem) == "CPropSurvival";
}

int apex::entity::get_health()
{
	return *reinterpret_cast<int*>(buffer + offsets::player::health);
}

std::unique_ptr<apex::client_class> apex::client_class::get(memory& mem, uintptr_t cl)
{
	const auto net_vtable = mem.read<uint64_t>(cl + 8 * 3);
	const auto get_class = mem.read<uint64_t>(net_vtable + 8 * 3);

	const auto disp = mem.read<uint32_t>(get_class + 3);
	const auto cl_ptr = get_class + disp + 7;

	auto cl_class = std::make_unique<client_class>();

	mem.read_raw(PVOID(cl_ptr), cl_class.get(), sizeof(client_class));

	return std::move(cl_class);
}

std::string apex::client_class::name(memory& mem)
{
	char buf[33] = { 0 };

	mem.read_raw(PVOID(this->p_network_name), buf, 32);

	return std::string(buf);
}
