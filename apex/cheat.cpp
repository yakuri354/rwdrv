#include "cheat.hpp"

#include "apex.hpp"
// TODO redo logging
void cheat::run(provider& mem)
{
	log("Starting cheat loop");

	while (true)
	{
		try
		{
			const apex::game game{ mem };
			
			auto local_player = std::make_unique<apex::entity>(game.local_player(), mem);
			dbgLog("Local player at [0x%llx]", local_player->ptr);
			
			while (true)
			{
				game.process_entities(*local_player);
				Sleep(1000);
			}
		}
		catch (std::exception& e)
		{
			if (!strcmp(e.what(), xs("could not find the process")))
			{
				log("Waiting for game to open");
				while (!util::process_id(apex::name))
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
