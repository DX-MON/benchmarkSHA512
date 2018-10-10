#ifndef SHA512_INTERNALS__HXX
#define SHA512_INTERNALS__HXX

#include <stdint.h>
#include <string.h>
#include <array>

inline void clearBlock(uint32_t *block) noexcept
{
	for (int8_t i = 0; i < 16; ++i)
		block[i] = 0;
}

inline uint32_t rol(const uint32_t val, const uint8_t shift) noexcept
	{ return (val << shift) | (val >> (32 - shift)); }

inline uint64_t rol(const uint64_t val, const uint8_t shift) noexcept
	{ return (val << shift) | (val >> (64 - shift)); }

inline uint32_t ror(const uint32_t val, const uint8_t shift) noexcept
	{ return (val >> shift) | (val << (32 - shift)); }

inline uint64_t ror(const uint64_t val, const uint8_t shift) noexcept
	{ return (val >> shift) | (val << (64 - shift)); }

inline uint32_t flipBytes32(const uint32_t uint) noexcept
{
	return ((uint >> 24) & 0xFF) | ((uint >> 8) & 0xFF00) |
		((uint & 0xFF00) << 8) | ((uint & 0xFF) << 24);
}

inline uint64_t flipBytes64(const uint64_t uint) noexcept
{
	return ((uint >> 56) & 0xFF) | ((uint >> 40) & 0xFF00) | ((uint >> 24) & 0xFF0000) | ((uint >> 8) & 0xFF000000) |
		((uint & 0xFF000000) << 8) | ((uint & 0xFF0000) << 24) | ((uint & 0xFF00) << 40) | ((uint & 0xFF) << 56);
}

inline void appendBlockLen(uint32_t *block, const uint64_t len) noexcept
{
	block[14] = uint32_t(len);
	block[15] = uint32_t(len >> 32);
}

inline void appendBlockLen(uint64_t *block, const uint64_t lenLow, const uint64_t lenHigh) noexcept
{
	block[15] = flipBytes64(lenLow);
	block[14] = flipBytes64(lenHigh);
}

#endif /*SHA512_INTERNALS__HXX*/
