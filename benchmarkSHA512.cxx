#include <benchmark/benchmark.h>
#include <memory>
#include <openssl/sha.h>
#include "sha512.hxx"

using state_t = benchmark::State;

namespace sha512
{
	void hashCXX(state_t &state)
	{
		int64_t bytes = 1 << state.range(0);
		auto data = std::make_unique<char []>(bytes);

		while (state.KeepRunning())
			sha512::sha512(data.get(), bytes);

		state.SetBytesProcessed(int64_t(state.iterations()) * bytes);
		if (bytes < 1024)
			state.SetLabel(std::to_string(bytes) + "B");
		else
			state.SetLabel(std::to_string(bytes / 1024) + "kB");
	}
	BENCHMARK(hashCXX)->DenseRange(0, 24)->ReportAggregatesOnly(true);
}

namespace openSSL
{
	std::array<uint8_t, SHA512_DIGEST_LENGTH> hash;

	void hashOpenSSL(state_t &state)
	{
		int64_t bytes = 1 << state.range(0);
		auto data = std::make_unique<uint8_t []>(bytes);

		while (state.KeepRunning())
			SHA512(data.get(), bytes, hash.data());

		state.SetBytesProcessed(int64_t(state.iterations()) * bytes);
		if (bytes < 1024)
			state.SetLabel(std::to_string(bytes) + "B");
		else
			state.SetLabel(std::to_string(bytes / 1024) + "kB");
	}
	BENCHMARK(hashOpenSSL)->DenseRange(0, 24)->ReportAggregatesOnly(true);
}

BENCHMARK_MAIN()
