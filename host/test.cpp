#include "pch.h"
#include "test.h"


void test(hoster host) // TODO Fix VirtQuery, writing, finish test
{
	host.logger(xs("Starting test\n"));

	const auto pid = util::process_id(xs(L"notepad.exe"));
	host.mem.attach(pid);
	const auto base = host.mem.base();

	host.logger(fmt::format(xs("Attached; PID {}, Base {}\n"), pid, reca<void*>(base)).c_str());

	auto mg = host.mem.read<short>(base);

	if (mg != 0x5A4D)
	{
		host.logger(fmt::format(xs("Magic {0:#x}; incorrect"), mg).c_str());
		throw std::exception(xs("magic assertion failed\n"));
	}
	host.logger(fmt::format(xs("Magic {0:#x}; correct"), mg).c_str());

	uint64_t time = 0;
	for (auto i = 0; i < 10; i++)
	{
		LARGE_INTEGER then;
		LI_FN(QueryPerformanceCounter)(&then);
		for (auto i = 0; i < 10000; i++)
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

		auto elapsed = (now.QuadPart - then.QuadPart) * tick_rate.QuadPart / 1000000Ui64;
		time += elapsed;

		host.logger(fmt::format(xs("Completed test run #{} in {} us\n"), i + 1, elapsed).c_str());
	}

	host.logger(
		fmt::format(xs("Test completed successfully, each r/w operation took {} us in average\n"), time / 100000).
		c_str());
}
