#include "cheat.hpp"

void cheat::cheat_loop(memory& mem)
{
	log(xs("[cheat] Starting cheat loop"));

	const r6s::game game{ mem };
	
	while (true)
	{
		game.cav_esp(true);
		Sleep(1);
	}
}
