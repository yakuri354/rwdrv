#include "cheat.hpp"
#include "apex.hpp"

void cheat(const hoster& host)
{
	host.logH("Starting cheat loop");

	while (true)
	{
		try
		{
			const apex::game game{host.mem};

			auto local_player = std::make_unique<apex::entity>(game.local_player(), host.mem);
			host.logH("Local player at [0x%llx]", local_player->ptr);

			while (true)
			{
				game.process_entities(*local_player);
				Sleep(1000);
			}
		}
		catch (ex::process_not_found&)
		{
			host.logH("Waiting for game to open");
			Sleep(500);
		}
		catch (ex::host_exception& e)
		{
			host.logH("Memory exception occurred: %s", e.what());
			Sleep(1000);
		}
	}
}
