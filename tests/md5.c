#include "../algorithms/cryptography/md5.c"

#include <assert.h>
#include <ctype.h>
#include <stdio.h>

void run_tests(const char *path)
{
	FILE *input;
	size_t size;
	char *buffer, *line_begin, *line_end;
	char *len = 0, *msg = 0;
	unsigned char *ref_digest = 0;

	const char *hex = "0123456789abcdef";

	struct md5_context md5;

	unsigned char digest[16];

	unsigned int i, length;

	input = fopen(path, "r");

	assert(input);

	fseek(input, 0, SEEK_END);
	size = ftell(input);
	fseek(input, 0, SEEK_SET);

	buffer = malloc(size + 1);

	assert(buffer);

	if (size != fread(buffer, 1, size, input))
		assert(!"fread failed");

	fclose(input);

	buffer[size] = 0;

	line_begin = buffer;

	while (*line_begin)
	{
		if (*line_begin && isspace(*line_begin))
			++line_begin;

		line_end = line_begin;

		while (*line_end && *line_end != '\n' && *line_end != '\r')
			++line_end;

		if (!*line_end)
			break;

		*line_end = 0;

		if (!strncmp(line_begin, "Len = ", 6))
			len = line_begin + 6;
		else if (!strncmp(line_begin, "Msg = ", 6))
			msg = line_begin + 6;
		else if (!strncmp(line_begin, "MD = ", 5))
			ref_digest = (unsigned char *) line_begin + 5;

		if (len && msg && ref_digest)
		{
			length = strtol(len, 0, 0);

			assert(!(length % 8));

			length /= 8;

			assert(strlen(msg) >= length * 2);
			assert(strspn(msg, hex) == strlen(msg));
			assert(strlen((char *) ref_digest) == 32);

			for (i = 0; i < length; ++i)
				msg[i] = ((strchr(hex, (unsigned char) msg[i * 2]) - hex) << 4) | (strchr(hex, (unsigned char) msg[i * 2 + 1]) - hex);

			for (i = 0; i < 16; ++i)
				ref_digest[i] = ((strchr(hex, (unsigned char) ref_digest[i * 2]) - hex) << 4) | (strchr(hex, (unsigned char) ref_digest[i * 2 + 1]) - hex);

			md5_init(&md5);
			md5_add(&md5, msg, length);
			md5_finish(&md5, digest);

			for (i = 0; i < 16; ++i)
				assert(ref_digest[i] == digest[i]);

			len = 0;
			msg = 0;
			ref_digest = 0;
		}

		line_begin = line_end + 1;
	}

	free(buffer);
}

int main(int argc, char **argv)
{
	run_tests("data/MD5.txt");

	return 0;
}
