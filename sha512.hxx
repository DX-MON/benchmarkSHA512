#ifndef SHA512__HXX
#define SHA512__HXX

#include <stdint.h>
#include <array>

namespace sha512
{
	struct sha512Hash_t final
	{
	private:
		std::array<uint64_t, 8> state;
		uint64_t len;

		void round(std::array<uint64_t, 8> &initState, const uint64_t *const mesg) noexcept;

	public:
		sha512Hash_t() noexcept;
		void round(const void *const mesg) noexcept;
		char *hash(const void *const mesg, const uint8_t msgLen) noexcept;
	};

	extern char *sha512(const char *const buffer, const uint64_t len) noexcept;
}

#endif /*SHA512__HXX*/
