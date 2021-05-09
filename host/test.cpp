#include "pch.h"
#include "test.h"

void test(hoster host)
{
	host.logger(xs("Starting test\n"));

	uint32_t pid = 0;

	for (auto i = 0; i < 10; i++)
		try
		{
			pid = util::process_id(xs(L"wordpad.exe"));
			break;
		}
		catch (ex::process_not_found&)
		{
			host.logH("Process not found, attempt %d/10", i + 1);
		}
	
	if (pid == 0) return;
	host.mem.attach(pid);
	const auto base = host.mem.base();

	host.logH(xs("Attached; PID %u; Base 0x%p\n"), pid, base);

	const auto bcp = host.mem.read<uint32_t>(base);

	uint64_t time = 0;
	for (uint32_t i = 0; i < 10; i++)
	{
		LARGE_INTEGER then;
		LI_FN(QueryPerformanceCounter)(&then);
		for (uint32_t j = 0; j < 10000; j++)
		{
			uint32_t value = 0xDEADBEEF;
			host.mem.write(base, value);
			if (host.mem.read<uint32_t>(base) != value)
				throw std::exception(xs("stress test failed"));
		}
		LARGE_INTEGER now;
		LI_FN(QueryPerformanceCounter)(&now);
		LARGE_INTEGER tick_rate;
		LI_FN(QueryPerformanceFrequency)(&tick_rate);

		const auto elapsed = (now.QuadPart - then.QuadPart) * tick_rate.QuadPart / 1000000Ui64;
		time += elapsed;

		host.logH(xs("Completed test run #%u in %llu us\n"), i + 1, elapsed);
	}

	host.mem.write(base, bcp);

	host.logH(xs("Test completed successfully, each r/w operation took %llu us in average\n"), time / (10 * 10000));
}
