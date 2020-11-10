/**
 * Name: MD5
 *
 * Description: Computes the 128 bit MD5 hash of a byte oriented message.
 *
 * Computation time: O(N)
 *
 * Category: Algorithms > Cryptography
 */

#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

struct md5_context
{
	uint64_t size;
	uint32_t h[4];
	uint32_t buffer_fill;
	uint8_t buffer[64];
};

static uint32_t k[64];

#define ROL(x,n) (((x) << (n)) | ((x) >> (32 - (n))))

void md5_init(struct md5_context *state)
{
	unsigned int i;

	state->size = 0;
	state->h[0] = 0x67452301;
	state->h[1] = 0xefcdab89;
	state->h[2] = 0x98badcfe;
	state->h[3] = 0x10325476;
	state->buffer_fill = 0;

	if (!k[0])
	{
		for (i = 0; i < 64; ++i)
			k[i] = (uint32_t) floor(fabs(sin(i + 1)) * 4294967296.0);
	}
}

static void md5_consume(struct md5_context *state)
{
	static const unsigned int r[64] =
	{
		7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,  7, 12, 17, 22,
		5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,  5,  9, 14, 20,
		4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,  4, 11, 16, 23,
		6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21,  6, 10, 15, 21
	};

	uint32_t w[16];
	uint32_t a, b, c, d, f, g, temp;
	unsigned int i;

	for (i = 0; i < 16; ++i)
	{
		w[i] = (state->buffer[i * 4 + 3] << 24) | (state->buffer[i * 4 + 2] << 16)
		     | (state->buffer[i * 4 + 1] << 8) | state->buffer[i * 4];
	}

	a = state->h[0];
	b = state->h[1];
	c = state->h[2];
	d = state->h[3];

	for (i = 0; i < 64; ++i)
	{
		if (i < 16)
		{
			f = (b & c) | (~b & d);
			g = i;
		}
		else if (i < 32)
		{
			f = (d & b) | (~d & c);
			g = (5 * i + 1) & 15;
		}
		else if (i < 48)
		{
			f = b ^ c ^ d;
			g = (3 * i + 5) & 15;
		}
		else
		{
			f = c ^ (b | ~d);
			g = (7 * i) & 15;
		}

		temp = d;
		d = c;
		c = b;
		b = b + ROL(a + f + k[i] + w[g], r[i]);
		a = temp;
	}

	state->h[0] += a;
	state->h[1] += b;
	state->h[2] += c;
	state->h[3] += d;

	state->buffer_fill = 0;
}

void md5_add(struct md5_context *state, const void *data, size_t size)
{
	size_t amount;

	state->size += size * 8;

	while (state->buffer_fill + size >= sizeof(state->buffer))
	{
		amount = sizeof(state->buffer) - state->buffer_fill;

		memcpy(state->buffer + state->buffer_fill, data, amount);

		state->buffer_fill += amount;

		md5_consume(state);

		data = (char *) data + amount;
		size -= amount;
	}

	memcpy(state->buffer + state->buffer_fill, data, size);

	state->buffer_fill += size;
}

void md5_finish(struct md5_context *state, unsigned char *hash)
{
	unsigned int i;

	state->buffer[state->buffer_fill++] = 0x80;

	while (state->buffer_fill != 56)
	{
		if (state->buffer_fill == sizeof(state->buffer))
			md5_consume(state);

		state->buffer[state->buffer_fill++] = 0;
	}

	for (i = 0; i < 8; ++i)
		state->buffer[state->buffer_fill++] = state->size >> (i * 8);

	md5_consume(state);

	for (i = 0; i < 16; ++i)
		hash[i] = state->h[i / 4] >> ((i & 3) * 8);
}
