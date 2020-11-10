#include "../algorithms/cryptography/sha256.c"
#include "../algorithms/cryptography/hmac.c"

#include <assert.h>
#include <string.h>

static const struct
{
  const unsigned char digest[32];
  const char *key;
  const char *message;
} test_vectors[] =
{
	{ { 0xf7, 0xbc, 0x83, 0xf4, 0x30, 0x53, 0x84, 0x24, 0xb1, 0x32, 0x98,
	    0xe6, 0xaa, 0x6f, 0xb1, 0x43, 0xef, 0x4d, 0x59, 0xa1, 0x49, 0x46,
	    0x17, 0x59, 0x97, 0x47, 0x9d, 0xbc, 0x2d, 0x1a, 0x3c, 0xd8 },
	    "key",
	    "The quick brown fox jumps over the lazy dog"
        },
};

int main(int argc, char **argv)
{
	struct hash_function sha256;
	unsigned char result[32];	
	int ret;

	sha256.state_size = sizeof (struct sha256_context);
	sha256.block_size = 64;
	sha256.output_size = 32;
	sha256.init = (hash_init_t) sha256_init;
	sha256.add = (hash_add_t) sha256_add;
	sha256.finish = (hash_finish_t) sha256_finish;

	ret = hmac (result,
	            test_vectors[0].key, strlen (test_vectors[0].key),
	            test_vectors[0].message, strlen (test_vectors[0].message),
	            &sha256);

	assert (ret == 0);
	assert (!memcmp (result, test_vectors[0].digest, 32));

	return 0;
}
