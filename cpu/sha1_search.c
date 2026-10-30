#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"

#define MAX_MESSAGE_LENGTH 55

static int parse_hex(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

static int parse_unsigned(const char* text, unsigned long long* value)
{
	char* end;
	unsigned long long parsed;

	if (*text == '\0' || *text == '-')
		return 0;
	errno = 0;
	parsed = strtoull(text, &end, 10);
	if (errno == ERANGE || end == text || *end != '\0')
		return 0;
	*value = parsed;
	return 1;
}

static unsigned int append_decimal(unsigned long long value, char* output)
{
	char reversed[20];
	unsigned int count = 0;
	unsigned int i;

	do {
		reversed[count++] = (char)('0' + value % 10);
		value /= 10;
	} while (value != 0);

	for (i = 0; i < count; ++i)
		output[i] = reversed[count - i - 1];
	return count;
}

static int matches_suffix(const BYTE digest[SHA1_BLOCK_SIZE],
                          const char* suffix, size_t suffix_length)
{
	size_t i;
	const size_t first_nibble = 40 - suffix_length;

	for (i = 0; i < suffix_length; ++i) {
		const size_t digest_nibble = first_nibble + i;
		const BYTE byte = digest[digest_nibble / 2];
		const int actual = (digest_nibble & 1) ? (byte & 0x0f) : (byte >> 4);
		if (actual != parse_hex(suffix[i]))
			return 0;
	}
	return 1;
}

int main(int argc, char* argv[])
{
	const char* prefix;
	char suffix[41];
	char candidate[MAX_MESSAGE_LENGTH + 1];
	size_t prefix_length;
	size_t suffix_length;
	unsigned long long attempts;
	unsigned long long start_nonce = 0;
	unsigned long long index;
	unsigned long long found_nonce = 0;
	int found = 0;

	if (argc < 4 || argc > 5) {
		fprintf(stderr, "Usage: %s <prefix> <hex-suffix> <attempts> [start-nonce]\n",
		        argv[0]);
		return EXIT_FAILURE;
	}

	prefix = argv[1];
	prefix_length = strlen(prefix);
	suffix_length = strlen(argv[2]);
	if (prefix_length > MAX_MESSAGE_LENGTH - 20) {
		fprintf(stderr, "Error: prefix must be at most 35 bytes.\n");
		return EXIT_FAILURE;
	}
	if (suffix_length == 0 || suffix_length > 40) {
		fprintf(stderr, "Error: suffix must contain 1 to 40 hex characters.\n");
		return EXIT_FAILURE;
	}
	memcpy(suffix, argv[2], suffix_length + 1);
	for (size_t i = 0; i < suffix_length; ++i) {
		if (parse_hex(suffix[i]) < 0) {
			fprintf(stderr, "Error: suffix must contain only hexadecimal characters.\n");
			return EXIT_FAILURE;
		}
		if (suffix[i] >= 'A' && suffix[i] <= 'F')
			suffix[i] = (char)(suffix[i] - 'A' + 'a');
	}
	if (!parse_unsigned(argv[3], &attempts) || attempts == 0) {
		fprintf(stderr, "Error: attempts must be a positive integer.\n");
		return EXIT_FAILURE;
	}
	if (argc == 5 && !parse_unsigned(argv[4], &start_nonce)) {
		fprintf(stderr, "Error: start-nonce must be an unsigned integer.\n");
		return EXIT_FAILURE;
	}
	if (attempts - 1 > ULLONG_MAX - start_nonce) {
		fprintf(stderr, "Error: nonce range overflows 64-bit unsigned integers.\n");
		return EXIT_FAILURE;
	}

	memcpy(candidate, prefix, prefix_length);
	for (index = 0; index < attempts; ++index) {
		const unsigned long long nonce = start_nonce + index;
		const unsigned int nonce_length =
			append_decimal(nonce, candidate + prefix_length);
		BYTE digest[SHA1_BLOCK_SIZE];
		SHA1_CTX context;

		sha1_init(&context);
		sha1_update(&context, (const BYTE*)candidate, prefix_length + nonce_length);
		sha1_final(&context, digest);
		if (!found && matches_suffix(digest, suffix, suffix_length)) {
			found = 1;
			found_nonce = nonce;
		}
	}

	if (found)
		printf("CPU match: %s%llu\n", prefix, found_nonce);
	else
		printf("CPU: no match in %llu candidates\n", attempts);
	return EXIT_SUCCESS;
}
