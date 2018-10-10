#include "sha512.hxx"
#include "sha512Internals.hxx"

using namespace sha512;
static std::array<uint64_t, 8> sha512Hash;

constexpr static const std::array<const uint64_t, 80> K{
{
	0x428A2F98D728AE22, 0x7137449123EF65CD, 0xB5C0FBCFEC4D3B2F, 0xE9B5DBA58189DBBC,
	0x3956C25BF348B538, 0x59F111F1B605D019, 0x923F82A4AF194F9B, 0xAB1C5ED5DA6D8118,
	0xD807AA98A3030242, 0x12835B0145706FBE, 0x243185BE4EE4B28C, 0x550C7DC3D5FFB4E2,
	0x72BE5D74F27B896F, 0x80DEB1FE3B1696B1, 0x9BDC06A725C71235, 0xC19BF174CF692694,
	0xE49B69C19EF14AD2, 0xEFBE4786384F25E3, 0x0FC19DC68B8CD5B5, 0x240CA1CC77AC9C65,
	0x2DE92C6F592B0275, 0x4A7484AA6EA6E483, 0x5CB0A9DCBD41FBD4, 0x76F988DA831153B5,
	0x983E5152EE66DFAB, 0xA831C66D2DB43210, 0xB00327C898FB213F, 0xBF597FC7BEEF0EE4,
	0xC6E00BF33DA88FC2, 0xD5A79147930AA725, 0x06CA6351E003826F, 0x142929670A0E6E70,
	0x27B70A8546D22FFC, 0x2E1B21385C26C926, 0x4D2C6DFC5AC42AED, 0x53380D139D95B3DF,
	0x650A73548BAF63DE, 0x766A0ABB3C77B2A8, 0x81C2C92E47EDAEE6, 0x92722C851482353B,
	0xA2BFE8A14CF10364, 0xA81A664BBC423001, 0xC24B8B70D0F89791, 0xC76C51A30654BE30,
	0xD192E819D6EF5218, 0xD69906245565A910, 0xF40E35855771202A, 0x106AA07032BBD1B8,
	0x19A4C116B8D2D0C8, 0x1E376C085141AB53, 0x2748774CDF8EEB99, 0x34B0BCB5E19B48A8,
	0x391C0CB3C5C95A63, 0x4ED8AA4AE3418ACB, 0x5B9CCA4F7763E373, 0x682E6FF3D6B2B8A3,
	0x748F82EE5DEFB2FC, 0x78A5636F43172F60, 0x84C87814A1F0AB72, 0x8CC702081A6439EC,
	0x90BEFFFA23631E28, 0xA4506CEBDE82BDE9, 0xBEF9A3F7B2C67915, 0xC67178F2E372532B,
	0xCA273ECEEA26619C, 0xD186B8C721C0C207, 0xEADA7DD6CDE0EB1E, 0xF57D4F7FEE6ED178,
	0x06F067AA72176FBA, 0x0A637DC5A2C898A6, 0x113F9804BEF90DAE, 0x1B710B35131C471B,
	0x28DB77F523047D84, 0x32CAAB7B40C72493, 0x3C9EBE0A15C9BEBC, 0x431D67C49C100D4C,
	0x4CC5D4BECB3E42B6, 0x597F299CFC657E2A, 0x5FCB6FAB3AD6FAEC, 0x6C44198C4A475817
}};

inline uint64_t Ch(const uint64_t E, const uint64_t F, const uint64_t G) noexcept
	{ return (E & F) ^ ((~E) & G); }

inline uint64_t Ma(const uint64_t A, const uint64_t B, const uint64_t C) noexcept
	{ return (A & B) ^ (A & C) ^ (B & C); }

inline uint64_t S0(const uint64_t A) noexcept
	{ return ror(A, 28) ^ rol(A, 30) ^ rol(A, 25); }

inline uint64_t S1(const uint64_t E) noexcept
	{ return ror(E, 14) ^ ror(E, 18) ^ rol(E, 23); }

inline void roundStep(const int8_t roundNum, const uint64_t A, const uint64_t B, const uint64_t C, uint64_t &D, const uint64_t E, const uint64_t F, const uint64_t G, uint64_t &H, const uint64_t W) noexcept
{
	const uint64_t t1 = Ch(E, F, G) + H + W + K[roundNum] + S1(E);
	D += t1;
	H = t1 + Ma(A, B, C) + S0(A);
}

struct extMessage
{
private:
	std::array<uint64_t, 16> blocks;

	inline uint64_t &W(const int8_t i) noexcept { return blocks[i]; }

public:
	extMessage(const uint64_t *const mesg) noexcept
	{
		for (int8_t i = 0; i < 16; ++i)
			blocks[i] = flipBytes64(mesg[i]);
	}

	inline uint64_t operator [](const int8_t i) noexcept
	{
		if (i < 16)
			return blocks[i];
		const uint64_t s0 = ror(W(i - 15), 1) ^ ror(W(i - 15), 8) ^ (W(i - 15) >> 7);
		const uint64_t s1 = ror(W(i - 2), 19) ^ rol(W(i - 2), 3) ^ (W(i - 2) >> 6);
		return W(i) += s0 + W(i) + s1;
	}

	template<const int8_t i, const int8_t a_, const int8_t b_, const int8_t c>
	inline uint64_t next(const int8_t at) noexcept
	{
		if (!at)
			return blocks[i];
		const uint64_t a = blocks[a_], b = blocks[b_];
		const uint64_t s0 = ror(b, 1) ^ ror(b, 8) ^ (b >> 7);
		const uint64_t s1 = ror(a, 19) ^ rol(a, 3) ^ (a >> 6);
		return blocks[i] += s0 + blocks[c] + s1;
	}
};

sha512Hash_t::sha512Hash_t() noexcept : len(0)
{
	state[0] = 0x6A09E667F3BCC908;
	state[1] = 0xBB67AE8584CAA73B;
	state[2] = 0x3C6EF372FE94F82B;
	state[3] = 0xA54FF53A5F1D36F1;
	state[4] = 0x510E527FADE682D1;
	state[5] = 0x9B05688C2B3E6C1F;
	state[6] = 0x1F83D9ABFB41BD6B;
	state[7] = 0x5BE0CD19137E2179;
}

constexpr uint8_t stateIndex(const uint8_t i, const uint8_t offset) noexcept
	{ return 7 - ((i + offset) % 8); }
template<int8_t j> inline void round_(const int8_t i, std::array<uint64_t, 8> &state, const uint64_t W) noexcept
{
	roundStep(i, state[stateIndex(j, 7)], state[stateIndex(j, 6)], state[stateIndex(j, 5)], state[stateIndex(j, 4)],
		state[stateIndex(j, 3)], state[stateIndex(j, 2)], state[stateIndex(j, 1)], state[stateIndex(j, 0)], W);
}

inline void sha512Hash_t::round(std::array<uint64_t, 8> &initState, const uint64_t *const mesg) noexcept
{
	extMessage W(mesg);
	std::array<uint64_t, 8> state = initState;

	for (int8_t i = 0; i < 80; i += 16)
	{
		// The following commented lines show conceptually what this loop does.
		/*roundStep(uint8_t(i), state[7 - ((i + 7) % 8)], state[7 - ((i + 6) % 8)], state[7 - ((i + 5) % 8)], state[7 - ((i + 4) % 8)], state[7 - ((i + 3) % 8)],
			state[7 - ((i + 2) % 8)], state[7 - ((i + 1) % 8)], state[7 - (i % 8)], W[i]);*/
		round_<0>(i, state, W.next<0, 14, 1, 7>(i));
		round_<1>(i, state, W.next<1, 15, 2, 8>(i));
		round_<2>(i, state, W.next<2, 0, 3, 9>(i));
		round_<3>(i, state, W.next<3, 1, 4, 10>(i));
		round_<4>(i, state, W.next<4, 2, 5, 11>(i));
		round_<5>(i, state, W.next<5, 3, 6, 12>(i));
		round_<6>(i, state, W.next<6, 4, 7, 13>(i));
		round_<7>(i, state, W.next<7, 5, 8, 14>(i));
		round_<0>(i, state, W.next<8, 6, 9, 15>(i));
		round_<1>(i, state, W.next<9, 7, 10, 0>(i));
		round_<2>(i, state, W.next<10, 8, 11, 1>(i));
		round_<3>(i, state, W.next<11, 9, 12, 2>(i));
		round_<4>(i, state, W.next<12, 10, 13, 3>(i));
		round_<5>(i, state, W.next<13, 11, 14, 4>(i));
		round_<6>(i, state, W.next<14, 12, 15, 5>(i));
		round_<7>(i, state, W.next<15, 13, 0, 6>(i));
	}
	for (int8_t i = 0; i < int8_t(state.size()); ++i)
		initState[i] += state[i];
}

void sha512Hash_t::round(const void *const mesg) noexcept
{
	len += 128;
	round(state, (const uint64_t *const)mesg);
}

char *sha512Hash_t::hash(const void *const mesg, const uint8_t msgLen) noexcept
{
	std::array<uint64_t, 16> block;

	block.fill(0);
	memcpy(block.data(), mesg, msgLen);
	reinterpret_cast<uint8_t *>(block.data())[msgLen] = 0x80;
	len += msgLen;
	if (msgLen > 111)
	{
		round(state, block.data());
		block.fill(0);
	}
	appendBlockLen(block.data(), len << 3, len >> 61);
	round(state, block.data());

	for (uint8_t i = 0; i < state.size(); ++i)
		sha512Hash[i] = flipBytes64(state[i]);
	return (char *)sha512Hash.data();
}

char *sha512::sha512(const char *const buffer, const uint64_t len) noexcept
{
	sha512Hash_t state;
	uint64_t buffIdx = 0;
	const uint64_t buffBlockMax = len & ~127;
	const uint64_t *mesg = reinterpret_cast<const uint64_t *>(buffer);

	while (buffIdx != buffBlockMax)
	{
		state.round(mesg);
		mesg += 16;
		buffIdx += 128;
	}

	return state.hash(mesg, uint8_t(len - buffIdx));
}
