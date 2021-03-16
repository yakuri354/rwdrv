#include "cheat.h"

#include "apex.hpp"

void cheat::run(memory& mem)
{
	log("Starting cheat loop");

	while (true)
	{
		try
		{
			const apex::game game{ mem };

			const auto ent_list = game.entity_list();
			auto local_player = std::make_unique<apex::entity>(game.local_player(), mem);

			while (true)
			{
				game.process_entities(ent_list, *local_player);
				Sleep(100);
			}
		}
		catch (std::exception& e)
		{
			if (!strcmp(e.what(), ::jm::xor_string([]() { return "could not find the process"; }, std::integral_constant<std::size_t, sizeof("could not find the process") / sizeof(*"could not find the process")>{}, std::make_index_sequence<::jm::detail::_buffer_size<sizeof("could not find the process")>()>{}).crypt_get()))
			{
				log("Waiting for game to open");
				while (!util::process_id(xs(apex::name)))
					Sleep(1500);
			}
			else
			{
				log("Catched an exception: %s", e.what());
				return;
			}
		}
	}
}
