#include "entity.hpp"

apex::entity::entity(uintptr_t pointer, provider& mem): ptr(pointer), buffer{ 0 }
{
	mem.read_raw(reinterpret_cast<void*>(pointer), buffer, offsets::entity_size);
}

vector apex::entity::get_position()
{
	return *reinterpret_cast<vector*>(buffer + offsets::entity::origin);
}

bool apex::entity::is_player()
{
	if (*reinterpret_cast<uintptr_t*>(buffer + offsets::player::name) == 125780153691248) return true;

	auto* const str1 = reinterpret_cast<char*>(buffer + offsets::player::team);
	
	if (strlen(str1) > 0 && (*reinterpret_cast<int*>(str1) == 97)) return true;

	return false;
}

int apex::entity::get_health()
{
	return *reinterpret_cast<int*>(buffer + offsets::player::health);
}
