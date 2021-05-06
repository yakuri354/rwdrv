#include "cheat.hpp"
#include "apex.hpp"

void cheat(const hoster& host)
{
	host.logH("Starting cheat loop");

	while (true)
	{
		try
		{
			const apex::game game{ host.mem };
			
			auto local_player = std::make_unique<apex::entity>(game.local_player(), host.mem);
			host.logH("Local player at [0x%llx]", local_player->ptr);
			
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
				host.logH("Waiting for game to open");
				while (!util::process_id(apex::name))
					Sleep(1500);
			}
			else
			{
				host.logH("Caught an exception: %s", e.what());
				return;
			}
		}
	}
}
