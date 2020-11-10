#include <stdlib.h>

typedef void (*hash_init_t)(void *state);
typedef void (*hash_add_t)(void *state, const void *data, size_t size);
typedef void (*hash_finish_t)(void *state, unsigned char *hash);

struct hash_function
{
	size_t state_size;
	size_t block_size;
	size_t output_size;

	hash_init_t   init;
	hash_add_t    add;
	hash_finish_t finish;
};

int hmac (unsigned char *result,
          const char *key, size_t key_size,
          const char *message, size_t message_size,
          struct hash_function *hash)
{
	void *hash_state;
	unsigned char *buffer;
	size_t i;

	hash_state = malloc (hash->state_size + hash->block_size);

	if (!hash_state)
		return -1;

	buffer = (unsigned char *) hash_state + hash->state_size;

	for (i = 0; i < key_size && i < hash->block_size; ++i)
		buffer[i] = key[i] ^ 0x36;

	for (; i < hash->block_size; ++i)
		buffer[i] = 0x36;

	hash->init (hash_state);
	hash->add (hash_state, buffer, hash->block_size);
	hash->add (hash_state, message, message_size);	
	hash->finish (hash_state, result);

	for (i = 0; i < key_size && i < hash->block_size; ++i)
		buffer[i] = key[i] ^ 0x5c;

	for (; i < hash->block_size; ++i)
		buffer[i] = 0x5c;

	hash->init (hash_state);
	hash->add (hash_state, buffer, hash->block_size);
	hash->add (hash_state, result, hash->output_size);
	hash->finish (hash_state, result);
	
	free (hash_state);

	return 0;
}
