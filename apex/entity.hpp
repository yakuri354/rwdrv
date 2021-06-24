#pragma once
#include <memory>
#include <string>

#include "../host/memory.hpp"
#include "offsets.hpp"
#include "math.hpp"

namespace apex
{
	class client_class
	{
	public:
		static std::unique_ptr<client_class> get(memory& mem, uintptr_t cl);
		std::string name(memory& mem);
	private:
		uint64_t p_create_fn = 0;
		uint64_t p_create_event_fn = 0;
		uint64_t p_network_name = 0;
		uint64_t p_recv_table = 0;
		uint64_t p_next = 0;
		uint32_t class_id = 0;
		uint32_t class_size = 0;
	};
	
	struct entity
	{
		entity(uintptr_t pointer, memory& mem);
		
		uintptr_t ptr;
		uint8_t buffer[offsets::entity::size];
		std::unique_ptr<client_class> cl_class;
		memory& mem;

		vector get_position();
		bool is_player() const;
		bool is_item() const;
		int get_health();
	};
}
