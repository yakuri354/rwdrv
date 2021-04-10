#include "pch.h"
#include "test.h"


void test(hoster host)
{
	host.logger(xs("Starting test"));

	const auto pid = util::process_id(xs(L"notepad.exe"));
	host.mem.attach(pid);
	auto base = host.mem.base();

	host.logger(fmt::format("Attached; PID {}, Base {}", pid, base).c_str());

	_ASSERT_EXPR(host.mem.read<short>(base) == 0x5A4D, xs("Magic assertion failed"));

	std::random_device dev{};

	std::default_random_engine engine(dev());
	const std::uniform_int_distribution<uint64_t> dist{};

	for (auto i = 0; i < 10000; i++)
	{
		auto value = dist(engine);
		host.mem.write(base, value);
		if (host.mem.read<uint64_t>(base) != value)
		{
			host.logger("Stress test failed");
			return;
		}
	}

	host.logger("Test completed successfully");
}
