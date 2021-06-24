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

			auto lptr = game.local_player();

			while (lptr == NULL)
			{
				host.logH("Local player is null, waiting for lobby");
				Sleep(1000);
				lptr = game.local_player();
			}
			
			auto local_player = std::make_unique<apex::entity>(lptr, host.mem);
			host.logH("Local player at [0x%llx]", local_player->ptr);

			while (true)
			{
				game.process_entities(*local_player);
#ifdef _DEBUG
				Sleep(1000);
#endif
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
