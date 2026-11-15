#include <cuda_runtime.h>

#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>
#include <vector>

extern "C" {
#include "sha1.h"
}

namespace {

constexpr unsigned int kThreadsPerBlock = 256;
constexpr unsigned long long kMaxCandidatesPerLaunch = 1ULL << 24;
constexpr int kDigestSize = SHA1_BLOCK_SIZE;

__device__ __forceinline__ WORD rotate_left(WORD value, unsigned int bits)
{
	return (value << bits) | (value >> (32 - bits));
}

// Device adaptation of the SHA-1 compression routine from cpu/sha1.c.
__device__ void sha1_device_transform(SHA1_CTX* ctx, const BYTE data[])
{
	WORD a, b, c, d, e, i, j, t, words[80];

	for (i = 0, j = 0; i < 16; ++i, j += 4) {
		words[i] = ((WORD)data[j] << 24) | ((WORD)data[j + 1] << 16) |
		           ((WORD)data[j + 2] << 8) | (WORD)data[j + 3];
	}
	for (; i < 80; ++i) {
		words[i] = words[i - 3] ^ words[i - 8] ^ words[i - 14] ^ words[i - 16];
		words[i] = rotate_left(words[i], 1);
	}

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];

	for (i = 0; i < 20; ++i) {
		t = rotate_left(a, 5) + ((b & c) | (~b & d)) + e + ctx->k[0] + words[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = t;
	}
	for (; i < 40; ++i) {
		t = rotate_left(a, 5) + (b ^ c ^ d) + e + ctx->k[1] + words[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = t;
	}
	for (; i < 60; ++i) {
		t = rotate_left(a, 5) + ((b & c) | (b & d) | (c & d)) +
		    e + ctx->k[2] + words[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = t;
	}
	for (; i < 80; ++i) {
		t = rotate_left(a, 5) + (b ^ c ^ d) + e + ctx->k[3] + words[i];
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = t;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
}

__device__ void sha1_device_init(SHA1_CTX* ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x67452301u;
	ctx->state[1] = 0xefcdab89u;
	ctx->state[2] = 0x98badcfeu;
	ctx->state[3] = 0x10325476u;
	ctx->state[4] = 0xc3d2e1f0u;
	ctx->k[0] = 0x5a827999u;
	ctx->k[1] = 0x6ed9eba1u;
	ctx->k[2] = 0x8f1bbcdcu;
	ctx->k[3] = 0xca62c1d6u;
}

__device__ void sha1_device_update(SHA1_CTX* ctx, const BYTE data[], size_t length)
{
	for (size_t i = 0; i < length; ++i) {
		ctx->data[ctx->datalen++] = data[i];
		if (ctx->datalen == 64) {
			sha1_device_transform(ctx, ctx->data);
			ctx->bitlen += 512;
			ctx->datalen = 0;
		}
	}
}

__device__ void sha1_device_final(SHA1_CTX* ctx, BYTE digest[])
{
	WORD i = ctx->datalen;
	if (ctx->datalen < 56) {
		ctx->data[i++] = 0x80;
		while (i < 56)
			ctx->data[i++] = 0;
	}
	else {
		ctx->data[i++] = 0x80;
		while (i < 64)
			ctx->data[i++] = 0;
		sha1_device_transform(ctx, ctx->data);
		for (i = 0; i < 56; ++i)
			ctx->data[i] = 0;
	}

	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = (BYTE)ctx->bitlen;
	ctx->data[62] = (BYTE)(ctx->bitlen >> 8);
	ctx->data[61] = (BYTE)(ctx->bitlen >> 16);
	ctx->data[60] = (BYTE)(ctx->bitlen >> 24);
	ctx->data[59] = (BYTE)(ctx->bitlen >> 32);
	ctx->data[58] = (BYTE)(ctx->bitlen >> 40);
	ctx->data[57] = (BYTE)(ctx->bitlen >> 48);
	ctx->data[56] = (BYTE)(ctx->bitlen >> 56);
	sha1_device_transform(ctx, ctx->data);

	for (i = 0; i < 4; ++i) {
		digest[i] = (BYTE)(ctx->state[0] >> (24 - i * 8));
		digest[i + 4] = (BYTE)(ctx->state[1] >> (24 - i * 8));
		digest[i + 8] = (BYTE)(ctx->state[2] >> (24 - i * 8));
		digest[i + 12] = (BYTE)(ctx->state[3] >> (24 - i * 8));
		digest[i + 16] = (BYTE)(ctx->state[4] >> (24 - i * 8));
	}
}

__device__ bool device_matches_suffix(const BYTE digest[kDigestSize],
                                      const char* suffix, int length)
{
	const int first_nibble = 40 - length;
	for (int i = 0; i < length; ++i) {
		const int nibble = first_nibble + i;
		const BYTE byte = digest[nibble / 2];
		const int value = (nibble & 1) ? (byte & 0x0f) : (byte >> 4);
		const int target = suffix[i] <= '9'
			? suffix[i] - '0'
			: suffix[i] - 'a' + 10;
		if (value != target)
			return false;
	}
	return true;
}

__global__ void known_answer_kernel(BYTE* output)
{
	if (blockIdx.x != 0 || threadIdx.x != 0)
		return;

	const BYTE abc[] = {'a', 'b', 'c'};
	const BYTE binary[] = {0x80, 0xff, 0x00};
	const BYTE long_message[] =
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq";
	const BYTE* inputs[] = {abc, binary, long_message};
	const size_t lengths[] = {sizeof(abc), sizeof(binary), sizeof(long_message) - 1};
	for (int test = 0; test < 3; ++test) {
		SHA1_CTX context;
		sha1_device_init(&context);
		sha1_device_update(&context, inputs[test], lengths[test]);
		sha1_device_final(&context, output + test * kDigestSize);
	}
}

__global__ void search_kernel(const SHA1_CTX* base_context, const char* suffix,
                              int suffix_length, unsigned long long start_nonce,
                              unsigned long long attempts,
                              unsigned long long* found_nonce, int* found_flag)
{
	const unsigned long long index =
		static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x;
	if (index >= attempts)
		return;

	const unsigned long long nonce = start_nonce + index;
	BYTE nonce_bytes[8];
	for (int i = 0; i < 8; ++i)
		nonce_bytes[i] = (BYTE)(nonce >> (i * 8));

	SHA1_CTX context = *base_context;
	BYTE digest[kDigestSize];
	sha1_device_update(&context, nonce_bytes, sizeof(nonce_bytes));
	sha1_device_final(&context, digest);
	if (device_matches_suffix(digest, suffix, suffix_length)) {
		atomicMin(found_nonce, nonce);
		atomicExch(found_flag, 1);
	}
}

void check_cuda(cudaError_t result, const char* operation)
{
	if (result != cudaSuccess) {
		std::fprintf(stderr, "CUDA error during %s: %s\n", operation,
		             cudaGetErrorString(result));
		std::exit(EXIT_FAILURE);
	}
}

int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	return -1;
}

bool parse_hex_buffer(const char* text, std::vector<BYTE>* buffer)
{
	const size_t length = std::strlen(text);
	if (length % 2 != 0)
		return false;
	buffer->resize(length / 2);
	for (size_t i = 0; i < buffer->size(); ++i) {
		const int high = hex_value(text[i * 2]);
		const int low = hex_value(text[i * 2 + 1]);
		if (high < 0 || low < 0)
			return false;
		(*buffer)[i] = static_cast<BYTE>((high << 4) | low);
	}
	return true;
}

bool parse_unsigned(const char* text, unsigned long long* value)
{
	if (text[0] == '\0' || text[0] == '-')
		return false;
	errno = 0;
	char* end = nullptr;
	const unsigned long long parsed = std::strtoull(text, &end, 10);
	if (errno == ERANGE || end == text || *end != '\0')
		return false;
	*value = parsed;
	return true;
}

bool host_matches_suffix(const BYTE digest[kDigestSize], const std::string& suffix)
{
	const int first_nibble = 40 - static_cast<int>(suffix.size());
	for (int i = 0; i < static_cast<int>(suffix.size()); ++i) {
		const int nibble = first_nibble + i;
		const BYTE byte = digest[nibble / 2];
		const int value = (nibble & 1) ? (byte & 0x0f) : (byte >> 4);
		const int target = hex_value(suffix[static_cast<size_t>(i)]);
		if (value != target)
			return false;
	}
	return true;
}

void encode_nonce(unsigned long long nonce, BYTE bytes[8])
{
	for (int i = 0; i < 8; ++i)
		bytes[i] = static_cast<BYTE>(nonce >> (i * 8));
}

void print_digest(const BYTE digest[kDigestSize])
{
	for (int i = 0; i < kDigestSize; ++i)
		std::printf("%02x", digest[i]);
}

int validate_gpu_vectors()
{
	const BYTE expected[kDigestSize * 3] = {
		0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
		0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d,
		0x51,0x92,0x47,0x6d,0xfc,0x3e,0xe7,0x79,0x03,0x07,
		0x31,0x88,0x23,0xe5,0x48,0x0b,0xcf,0x9b,0x40,0xcd,
		0x84,0x98,0x3e,0x44,0x1c,0x3b,0xd2,0x6e,0xba,0xae,
		0x4a,0xa1,0xf9,0x51,0x29,0xe5,0xe5,0x46,0x70,0xf1
	};
	BYTE* device_output = nullptr;
	BYTE actual[kDigestSize * 3];
	check_cuda(cudaMalloc(&device_output, sizeof(actual)), "allocating test digests");
	known_answer_kernel<<<1, 1>>>(device_output);
	check_cuda(cudaGetLastError(), "launching SHA-1 known-answer tests");
	check_cuda(cudaMemcpy(actual, device_output, sizeof(actual),
	                      cudaMemcpyDeviceToHost), "copying test digests");
	check_cuda(cudaFree(device_output), "freeing test digests");
	if (std::memcmp(actual, expected, sizeof(expected)) != 0) {
		std::fprintf(stderr, "CUDA SHA-1 known-answer tests failed.\n");
		return 1;
	}
	std::puts("CUDA SHA-1 known-answer tests: SUCCEEDED");
	return 0;
}

} // namespace

int main(int argc, char** argv)
{
	if (argc < 4 || argc > 5) {
		std::fprintf(stderr,
		             "Usage: %s <buffer-hex> <lowercase-hex-suffix> <attempts> "
		             "[start-nonce]\n",
		             argv[0]);
		return EXIT_FAILURE;
	}

	std::vector<BYTE> buffer;
	if (!parse_hex_buffer(argv[1], &buffer)) {
		std::fprintf(stderr, "Error: input buffer must be valid even-length lowercase hex.\n");
		return EXIT_FAILURE;
	}
	const std::string suffix(argv[2]);
	if (suffix.empty() || suffix.size() > 40) {
		std::fprintf(stderr, "Error: suffix must contain 1 to 40 lowercase hex digits.\n");
		return EXIT_FAILURE;
	}
	for (char value : suffix) {
		if (hex_value(value) < 0) {
			std::fprintf(stderr, "Error: suffix must use lowercase hexadecimal characters.\n");
			return EXIT_FAILURE;
		}
	}

	unsigned long long attempts = 0;
	unsigned long long start_nonce = 0;
	if (!parse_unsigned(argv[3], &attempts) || attempts == 0) {
		std::fprintf(stderr, "Error: attempts must be a positive integer.\n");
		return EXIT_FAILURE;
	}
	if (argc == 5 && !parse_unsigned(argv[4], &start_nonce)) {
		std::fprintf(stderr, "Error: start nonce must be an unsigned integer.\n");
		return EXIT_FAILURE;
	}
	if (attempts - 1 > std::numeric_limits<unsigned long long>::max() - start_nonce) {
		std::fprintf(stderr, "Error: nonce range overflows 64-bit unsigned integers.\n");
		return EXIT_FAILURE;
	}
	if (buffer.size() > std::numeric_limits<unsigned long long>::max() / 8 - 8) {
		std::fprintf(stderr, "Error: input buffer is too long for SHA-1 length encoding.\n");
		return EXIT_FAILURE;
	}

	int device_count = 0;
	check_cuda(cudaGetDeviceCount(&device_count), "querying CUDA devices");
	if (device_count == 0) {
		std::fprintf(stderr, "Error: no CUDA-capable GPU was found.\n");
		return EXIT_FAILURE;
	}
	cudaDeviceProp device_properties;
	check_cuda(cudaGetDeviceProperties(&device_properties, 0),
	           "querying GPU properties");
	if (validate_gpu_vectors() != 0)
		return EXIT_FAILURE;

	// Pre-hash the common input once, then clone its SHA-1 state per nonce.
	SHA1_CTX base_context;
	sha1_init(&base_context);
	sha1_update(&base_context, buffer.empty() ? nullptr : buffer.data(), buffer.size());

	SHA1_CTX* device_base_context = nullptr;
	char* device_suffix = nullptr;
	unsigned long long* device_found_nonce = nullptr;
	int* device_found_flag = nullptr;
	check_cuda(cudaMalloc(&device_base_context, sizeof(base_context)),
	           "allocating base SHA-1 state");
	check_cuda(cudaMalloc(&device_suffix, suffix.size()), "allocating suffix");
	check_cuda(cudaMalloc(&device_found_nonce, sizeof(*device_found_nonce)),
	           "allocating result nonce");
	check_cuda(cudaMalloc(&device_found_flag, sizeof(*device_found_flag)),
	           "allocating result flag");
	check_cuda(cudaMemcpy(device_base_context, &base_context, sizeof(base_context),
	                      cudaMemcpyHostToDevice), "copying base SHA-1 state");
	check_cuda(cudaMemcpy(device_suffix, suffix.data(), suffix.size(),
	                      cudaMemcpyHostToDevice), "copying suffix");
	const unsigned long long no_result =
		std::numeric_limits<unsigned long long>::max();
	const int no_match = 0;
	check_cuda(cudaMemcpy(device_found_nonce, &no_result, sizeof(no_result),
	                      cudaMemcpyHostToDevice), "initializing result nonce");
	check_cuda(cudaMemcpy(device_found_flag, &no_match, sizeof(no_match),
	                      cudaMemcpyHostToDevice), "initializing result flag");

	cudaEvent_t start_event;
	cudaEvent_t stop_event;
	check_cuda(cudaEventCreate(&start_event), "creating kernel start event");
	check_cuda(cudaEventCreate(&stop_event), "creating kernel stop event");
	check_cuda(cudaEventRecord(start_event), "starting kernel timer");
	unsigned long long processed = 0;
	while (processed < attempts) {
		const unsigned long long chunk_count =
			(attempts - processed < kMaxCandidatesPerLaunch)
				? attempts - processed
				: kMaxCandidatesPerLaunch;
		const unsigned int blocks = static_cast<unsigned int>(
			(chunk_count - 1) / kThreadsPerBlock + 1);
		search_kernel<<<blocks, kThreadsPerBlock>>>(
			device_base_context, device_suffix, static_cast<int>(suffix.size()),
			start_nonce + processed, chunk_count, device_found_nonce,
			device_found_flag);
		check_cuda(cudaGetLastError(), "launching search kernel chunk");
		processed += chunk_count;
	}
	check_cuda(cudaEventRecord(stop_event), "stopping kernel timer");
	check_cuda(cudaEventSynchronize(stop_event), "waiting for search kernel");
	float kernel_milliseconds = 0.0f;
	check_cuda(cudaEventElapsedTime(&kernel_milliseconds, start_event, stop_event),
	           "measuring search kernel");

	unsigned long long found_nonce = no_result;
	int found = 0;
	check_cuda(cudaMemcpy(&found_nonce, device_found_nonce, sizeof(found_nonce),
	                      cudaMemcpyDeviceToHost), "copying result nonce");
	check_cuda(cudaMemcpy(&found, device_found_flag, sizeof(found),
	                      cudaMemcpyDeviceToHost), "copying result flag");
	check_cuda(cudaEventDestroy(start_event), "destroying kernel start event");
	check_cuda(cudaEventDestroy(stop_event), "destroying kernel stop event");
	check_cuda(cudaFree(device_base_context), "freeing base SHA-1 state");
	check_cuda(cudaFree(device_suffix), "freeing suffix");
	check_cuda(cudaFree(device_found_nonce), "freeing result nonce");
	check_cuda(cudaFree(device_found_flag), "freeing result flag");

	std::printf("GPU: %s\n", device_properties.name);
	std::printf("Candidates: %llu\n", attempts);
	if (found) {
		BYTE nonce_bytes[8];
		BYTE digest[kDigestSize];
		SHA1_CTX verify_context = base_context;
		encode_nonce(found_nonce, nonce_bytes);
		sha1_update(&verify_context, nonce_bytes, sizeof(nonce_bytes));
		sha1_final(&verify_context, digest);
		if (!host_matches_suffix(digest, suffix)) {
			std::fprintf(stderr, "Error: CPU verification of the GPU result failed.\n");
			return EXIT_FAILURE;
		}
		std::printf("GPU match: nonce=%llu digest=", found_nonce);
		print_digest(digest);
		std::putchar('\n');
	}
	else {
		std::printf("GPU: no match in %llu candidates\n", attempts);
	}
	std::printf("GPU kernel: %.3f ms\n", kernel_milliseconds);
	return EXIT_SUCCESS;
}
