/**
 * Name: SHA-512
 *
 * Description: Computes the 512 bit SHA-512 hash of a byte oriented message.
 *
 * Computation time: O(N)
 *
 * Category: Algorithms > Cryptography
 */

#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct sha512_context
{
	uint64_t size;
	uint64_t h[8];
	uint32_t buffer_fill;
	uint8_t buffer[128];
};

#define ROR(x,n) (((x) >> (n)) | ((x) << (64 - (n))))

void sha512_init(struct sha512_context *state)
{
	state->size = 0;
	state->h[0] = 0x6a09e667f3bcc908;
	state->h[1] = 0xbb67ae8584caa73b;
	state->h[2] = 0x3c6ef372fe94f82b;
	state->h[3] = 0xa54ff53a5f1d36f1;
	state->h[4] = 0x510e527fade682d1;
	state->h[5] = 0x9b05688c2b3e6c1f;
	state->h[6] = 0x1f83d9abfb41bd6b;
	state->h[7] = 0x5be0cd19137e2179;

	state->buffer_fill = 0;
}

static void sha512_consume(struct sha512_context *state)
{
	static const uint64_t k[80] =
	{
		0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
		0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
		0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
		0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
		0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
		0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
		0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
		0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
		0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
		0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
		0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
		0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
		0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
		0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
		0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
		0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
		0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
		0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
		0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
		0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817
	};

	uint64_t w[80];
	uint64_t s0, s1, maj, ch, t1, t2;
	uint64_t a, b, c, d, e, f, g, h;
	unsigned int i;

	for (i = 0; i < 16; ++i)
		w[i] = ((uint64_t) state->buffer[i * 8] << 56)     | ((uint64_t) state->buffer[i * 8 + 1] << 48)
		     | ((uint64_t) state->buffer[i * 8 + 2] << 40) | ((uint64_t) state->buffer[i * 8 + 3] << 32)
		     | ((uint64_t) state->buffer[i * 8 + 4] << 24) | (state->buffer[i * 8 + 5] << 16)
		     | (state->buffer[i * 8 + 6] << 8)             | state->buffer[i * 8 + 7];

	for (i = 16; i < 80; ++i)
	{
		s0 = ROR(w[i - 15], 1) ^ ROR(w[i - 15], 8) ^ (w[i - 15] >> 7);
		s1 = ROR(w[i - 2], 19) ^ ROR(w[i - 2], 61) ^ (w[i - 2] >> 6);
		w[i] = w[i - 16] + s0 + w[i - 7] + s1;
	}

	a = state->h[0];
	b = state->h[1];
	c = state->h[2];
	d = state->h[3];
	e = state->h[4];
	f = state->h[5];
	g = state->h[6];
	h = state->h[7];

	for (i = 0; i < 80; ++i)
	{
		s0 = ROR(a, 28) ^ ROR(a, 34) ^ ROR(a, 39);
		maj = (a & b) ^ (a & c) ^ (b & c);
		t2 = s0 + maj;
		s1 = ROR(e, 14) ^ ROR(e, 18) ^ ROR(e, 41);
		ch = (e & f) ^ (~e & g);
		t1 = h + s1 + ch + k[i] + w[i];

		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;
	state->h[4] += e;
	state->h[5] += f;
	state->h[6] += g;
	state->h[7] += h;

	state->buffer_fill = 0;
}

void sha512_add(struct sha512_context *state, const void *data, size_t size)
{
	size_t amount;

	state->size += size * 8;

	while (state->buffer_fill + size >= sizeof(state->buffer))
	{
		amount = sizeof(state->buffer) - state->buffer_fill;

		memcpy(state->buffer + state->buffer_fill, data, amount);

		state->buffer_fill += amount;

		sha512_consume(state);

		data = (char *) data + amount;
		size -= amount;
	}

	memcpy(state->buffer + state->buffer_fill, data, size);

	state->buffer_fill += size;
}

void sha512_finish(struct sha512_context *state, unsigned char *hash)
{
	unsigned int i;

	state->buffer[state->buffer_fill++] = 0x80;

	while (state->buffer_fill != 112)
	{
		if (state->buffer_fill == sizeof(state->buffer))
			sha512_consume(state);

		state->buffer[state->buffer_fill++] = 0;
	}

	/* Only messages up to 2**64 bits in length are supported.  Fill in
	 * zeros for the top 64 bits of the length value */
	for (i = 0; i < 8; ++i)
		state->buffer[state->buffer_fill++] = 0;

	state->buffer[state->buffer_fill++] = state->size >> 56;
	state->buffer[state->buffer_fill++] = state->size >> 48;
	state->buffer[state->buffer_fill++] = state->size >> 40;
	state->buffer[state->buffer_fill++] = state->size >> 32;
	state->buffer[state->buffer_fill++] = state->size >> 24;
	state->buffer[state->buffer_fill++] = state->size >> 16;
	state->buffer[state->buffer_fill++] = state->size >> 8;
	state->buffer[state->buffer_fill++] = state->size;

	sha512_consume(state);

	for (i = 0; i < 64; i += 8)
	{
		hash[i] =     state->h[i / 8] >> 56;
		hash[i + 1] = state->h[i / 8] >> 48;
		hash[i + 2] = state->h[i / 8] >> 40;
		hash[i + 3] = state->h[i / 8] >> 32;
		hash[i + 4] = state->h[i / 8] >> 24;
		hash[i + 5] = state->h[i / 8] >> 16;
		hash[i + 6] = state->h[i / 8] >> 8;
		hash[i + 7] = state->h[i / 8];
	}
}
