#include <errno.h>
#include <limits.h>
#include <omp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "sha1.h"

static int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
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

static int parse_hex_buffer(const char* text, BYTE** buffer, size_t* length)
{
	size_t i;
	const size_t hex_length = strlen(text);

	if (hex_length % 2 != 0)
		return 0;
	*length = hex_length / 2;
	*buffer = (BYTE*)malloc(*length == 0 ? 1 : *length);
	if (*buffer == NULL)
		return 0;

	for (i = 0; i < *length; ++i) {
		const int high = hex_value(text[i * 2]);
		const int low = hex_value(text[i * 2 + 1]);
		if (high < 0 || low < 0) {
			free(*buffer);
			*buffer = NULL;
			return 0;
		}
		(*buffer)[i] = (BYTE)((high << 4) | low);
	}
	return 1;
}

static void encode_nonce(unsigned long long nonce, BYTE bytes[8])
{
	int i;
	for (i = 0; i < 8; ++i)
		bytes[i] = (BYTE)(nonce >> (i * 8));
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
		if (actual != hex_value(suffix[i]))
			return 0;
	}
	return 1;
}

static void print_digest(const BYTE digest[SHA1_BLOCK_SIZE])
{
	int i;
	for (i = 0; i < SHA1_BLOCK_SIZE; ++i)
		printf("%02x", digest[i]);
}

int main(int argc, char* argv[])
{
	BYTE* buffer = NULL;
	size_t buffer_length = 0;
	const char* suffix;
	size_t suffix_length;
	unsigned long long attempts;
	unsigned long long start_nonce = 0;
	unsigned long long best_nonce = ULLONG_MAX;
	int found_match = 0;
	int thread_count = 1;
	SHA1_CTX base_context;
	double search_start;
	double search_seconds;
	int actual_threads = 1;

	if (argc < 4 || argc > 6) {
		fprintf(stderr,
		        "Usage: %s <buffer-hex> <lowercase-hex-suffix> <attempts> "
		        "[start-nonce] [threads]\n",
		        argv[0]);
		return EXIT_FAILURE;
	}
	if (!parse_hex_buffer(argv[1], &buffer, &buffer_length)) {
		fprintf(stderr, "Error: input buffer must be valid even-length lowercase hex.\n");
		return EXIT_FAILURE;
	}

	suffix = argv[2];
	suffix_length = strlen(suffix);
	if (suffix_length == 0 || suffix_length > 40) {
		fprintf(stderr, "Error: suffix must contain 1 to 40 lowercase hex digits.\n");
		free(buffer);
		return EXIT_FAILURE;
	}
	for (size_t i = 0; i < suffix_length; ++i) {
		if (hex_value(suffix[i]) < 0) {
			fprintf(stderr, "Error: suffix must use lowercase hexadecimal characters.\n");
			free(buffer);
			return EXIT_FAILURE;
		}
	}
	if (!parse_unsigned(argv[3], &attempts) || attempts == 0) {
		fprintf(stderr, "Error: attempts must be a positive integer.\n");
		free(buffer);
		return EXIT_FAILURE;
	}
	if (argc >= 5 && !parse_unsigned(argv[4], &start_nonce)) {
		fprintf(stderr, "Error: start nonce must be an unsigned integer.\n");
		free(buffer);
		return EXIT_FAILURE;
	}
	if (argc == 6) {
		unsigned long long parsed_threads;
		if (!parse_unsigned(argv[5], &parsed_threads) || parsed_threads == 0 ||
		    parsed_threads > INT_MAX) {
			fprintf(stderr, "Error: thread count must be between 1 and %d.\n", INT_MAX);
			free(buffer);
			return EXIT_FAILURE;
		}
		thread_count = (int)parsed_threads;
	}
	if (attempts - 1 > ULLONG_MAX - start_nonce) {
		fprintf(stderr, "Error: nonce range overflows 64-bit unsigned integers.\n");
		free(buffer);
		return EXIT_FAILURE;
	}
	if (buffer_length > ULLONG_MAX / 8 - 8) {
		fprintf(stderr, "Error: input buffer is too long for SHA-1 length encoding.\n");
		free(buffer);
		return EXIT_FAILURE;
	}

	sha1_init(&base_context);
	sha1_update(&base_context, buffer, buffer_length);

	omp_set_dynamic(0);
	search_start = omp_get_wtime();
#pragma omp parallel num_threads(thread_count) shared(best_nonce, actual_threads, base_context, buffer, suffix)
	{
		const int thread_id = omp_get_thread_num();
		const int team_size = omp_get_num_threads();
		const unsigned long long base_count = attempts / (unsigned long long)team_size;
		const unsigned long long remainder = attempts % (unsigned long long)team_size;
		const unsigned long long offset =
			(unsigned long long)thread_id * base_count +
			((unsigned long long)thread_id < remainder
			 ? (unsigned long long)thread_id : remainder);
		const unsigned long long count =
			base_count + ((unsigned long long)thread_id < remainder ? 1 : 0);
		unsigned long long local_best = ULLONG_MAX;
		int local_found = 0;
		unsigned long long i;

#pragma omp single
		actual_threads = team_size;

		for (i = 0; i < count; ++i) {
			const unsigned long long nonce = start_nonce + offset + i;
			BYTE nonce_bytes[8];
			BYTE digest[SHA1_BLOCK_SIZE];
			SHA1_CTX context = base_context;

			encode_nonce(nonce, nonce_bytes);
			sha1_update(&context, nonce_bytes, sizeof(nonce_bytes));
			sha1_final(&context, digest);
			if (matches_suffix(digest, suffix, suffix_length) &&
			    (!local_found || nonce < local_best)) {
				local_best = nonce;
				local_found = 1;
			}
		}

#pragma omp critical
		{
			if (local_found && (!found_match || local_best < best_nonce)) {
				best_nonce = local_best;
				found_match = 1;
			}
		}
	}
	search_seconds = omp_get_wtime() - search_start;

	printf("CPU threads: %d\n", actual_threads);
	printf("CPU search: %.6f seconds\n", search_seconds);
	if (!found_match) {
		printf("CPU: no match in %llu candidates\n", attempts);
	}
	else {
		BYTE nonce_bytes[8];
		BYTE digest[SHA1_BLOCK_SIZE];
		SHA1_CTX context = base_context;
		encode_nonce(best_nonce, nonce_bytes);
		sha1_update(&context, nonce_bytes, sizeof(nonce_bytes));
		sha1_final(&context, digest);
		printf("CPU match: nonce=%llu digest=", best_nonce);
		print_digest(digest);
		putchar('\n');
	}

	free(buffer);
	return EXIT_SUCCESS;
}
