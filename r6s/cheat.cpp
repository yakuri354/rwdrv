#include "cheat.hpp"

void cheat::run(memory& mem)
{
	log("Starting cheat loop");

	while (true)
	{
		try
		{
			const r6s::game game{ mem };

			while (true)
			{
				game.cav_esp(true);
				Sleep(1);
			}
		}
		catch (std::exception& e)
		{
			if (!strcmp(e.what(), xs("could not find r6s")))
			{
				log("Waiting for game to open");
				while (!util::process_id(xs(GAME_NAME)))
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
