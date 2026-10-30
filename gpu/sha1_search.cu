#include <cuda_runtime.h>

#include <chrono>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <limits>
#include <string>

namespace {

// Search launch configuration and the SHA-1 single-block input limits.
constexpr int kThreadsPerBlock = 256;
constexpr int kMaxMessageLength = 55;
constexpr int kDigestSize = 20;

// Rotate a 32-bit word left; SHA-1 uses this operation throughout its rounds.
__device__ __forceinline__ uint32_t rotate_left(uint32_t value, unsigned int bits)
{
	return (value << bits) | (value >> (32 - bits));
}

// Hash one message of at most 55 bytes, including SHA-1 padding, in one block.
__device__ void sha1_one_block(const unsigned char* message, unsigned int length,
                               unsigned char digest[kDigestSize])
{
	uint32_t words[16];
	// Convert the 64-byte padded message block into SHA-1's big-endian words.
	for (int i = 0; i < 16; ++i) {
		const int offset = i * 4;
		words[i] = (static_cast<uint32_t>(message[offset]) << 24) |
		           (static_cast<uint32_t>(message[offset + 1]) << 16) |
		           (static_cast<uint32_t>(message[offset + 2]) << 8) |
		           static_cast<uint32_t>(message[offset + 3]);
	}

	// Add the mandatory padding bit and encode the message length in bits.
	const unsigned int padding_word = length / 4;
	const unsigned int padding_shift = 24 - (length % 4) * 8;
	words[padding_word] |= 0x80u << padding_shift;
	words[14] = 0;
	words[15] = length * 8;

	// Initialize SHA-1's five working words to the standard initial state.
	uint32_t a = 0x67452301u;
	uint32_t b = 0xefcdab89u;
	uint32_t c = 0x98badcfeu;
	uint32_t d = 0x10325476u;
	uint32_t e = 0xc3d2e1f0u;

	// Expand the message schedule as needed and perform all 80 SHA-1 rounds.
	for (unsigned int round = 0; round < 80; ++round) {
		uint32_t word;
		if (round < 16) {
			word = words[round];
		}
		else {
			const unsigned int slot = round & 15;
			words[slot] = rotate_left(
				words[(round - 3) & 15] ^ words[(round - 8) & 15] ^
				words[(round - 14) & 15] ^ words[slot], 1);
			word = words[slot];
		}

		uint32_t function;
		uint32_t constant;
		if (round < 20) {
			function = (b & c) | (~b & d);
			constant = 0x5a827999u;
		}
		else if (round < 40) {
			function = b ^ c ^ d;
			constant = 0x6ed9eba1u;
		}
		else if (round < 60) {
			function = (b & c) | (b & d) | (c & d);
			constant = 0x8f1bbcdcu;
		}
		else {
			function = b ^ c ^ d;
			constant = 0xca62c1d6u;
		}

		const uint32_t next = rotate_left(a, 5) + function + e + constant + word;
		e = d;
		d = c;
		c = rotate_left(b, 30);
		b = a;
		a = next;
	}

	// Add the working values back to the initial state and serialize the digest.
	const uint32_t state[5] = {
		0x67452301u + a,
		0xefcdab89u + b,
		0x98badcfeu + c,
		0x10325476u + d,
		0xc3d2e1f0u + e
	};
	for (int i = 0; i < 5; ++i) {
		digest[i * 4] = static_cast<unsigned char>(state[i] >> 24);
		digest[i * 4 + 1] = static_cast<unsigned char>(state[i] >> 16);
		digest[i * 4 + 2] = static_cast<unsigned char>(state[i] >> 8);
		digest[i * 4 + 3] = static_cast<unsigned char>(state[i]);
	}
}

// Convert a normalized lowercase hexadecimal digit to its numeric value.
__device__ __forceinline__ int hex_value(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	return value - 'a' + 10;
}

// Compare the requested hexadecimal suffix against the digest's final nibbles.
__device__ bool matches_suffix(const unsigned char digest[kDigestSize],
                               const char* suffix, int suffix_length)
{
	const int first_nibble = 40 - suffix_length;
	for (int i = 0; i < suffix_length; ++i) {
		const int digest_nibble = first_nibble + i;
		const unsigned char byte = digest[digest_nibble / 2];
		const int actual = (digest_nibble & 1) ? (byte & 0x0f) : (byte >> 4);
		if (actual != hex_value(suffix[i]))
			return false;
	}
	return true;
}

// Write an unsigned nonce as decimal digits and return the digit count.
__device__ unsigned int append_decimal(unsigned long long value,
                                       unsigned char* output)
{
	unsigned char reversed[20];
	unsigned int count = 0;
	do {
		reversed[count++] = static_cast<unsigned char>('0' + value % 10);
		value /= 10;
	} while (value != 0);

	for (unsigned int i = 0; i < count; ++i)
		output[i] = reversed[count - i - 1];
	return count;
}

// Run a couple of fixed SHA-1 vectors on the GPU for startup correctness checks.
__global__ void hash_vectors_kernel(unsigned char* output)
{
	unsigned char message[64] = {};
	unsigned char digest[kDigestSize];
	message[0] = 'a';
	message[1] = 'b';
	message[2] = 'c';
	sha1_one_block(message, 3, digest);
	for (int i = 0; i < kDigestSize; ++i)
		output[i] = digest[i];

	message[0] = 0x80;
	message[1] = 0xff;
	message[2] = 0x00;
	sha1_one_block(message, 3, digest);
	for (int i = 0; i < kDigestSize; ++i)
		output[kDigestSize + i] = digest[i];
}

// Hash one distinct prefix-plus-nonce candidate per CUDA thread.
__global__ void search_kernel(const unsigned char* prefix, int prefix_length,
                              const char* suffix, int suffix_length,
                              unsigned long long start_nonce,
                              unsigned long long attempts,
                              unsigned long long* found_nonce,
                              int* found_flag)
{
	// Map this thread to its candidate index in the requested nonce range.
	const unsigned long long index =
		static_cast<unsigned long long>(blockIdx.x) * blockDim.x + threadIdx.x;
	if (index >= attempts)
		return;

	unsigned char message[64] = {};
	for (int i = 0; i < prefix_length; ++i)
		message[i] = prefix[i];
	// Append this thread's decimal nonce and hash the resulting candidate.
	const unsigned int nonce_length =
		append_decimal(start_nonce + index, message + prefix_length);
	const unsigned int message_length =
		static_cast<unsigned int>(prefix_length) + nonce_length;

	unsigned char digest[kDigestSize];
	sha1_one_block(message, message_length, digest);
	if (matches_suffix(digest, suffix, suffix_length)) {
		// If several candidates match, preserve the lowest nonce found.
		atomicMin(found_nonce, start_nonce + index);
		atomicExch(found_flag, 1);
	}
}

// Stop on CUDA API failures and print the operation that failed.
void check_cuda(cudaError_t result, const char* operation)
{
	if (result != cudaSuccess) {
		std::fprintf(stderr, "CUDA error during %s: %s\n", operation,
		             cudaGetErrorString(result));
		std::exit(EXIT_FAILURE);
	}
}

// Parse one hexadecimal character; return -1 for invalid characters.
int parse_hex(char value)
{
	if (value >= '0' && value <= '9')
		return value - '0';
	if (value >= 'a' && value <= 'f')
		return value - 'a' + 10;
	if (value >= 'A' && value <= 'F')
		return value - 'A' + 10;
	return -1;
}

// Parse a non-negative decimal integer and reject malformed or overflowing input.
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

// Print the command-line syntax and the candidate-length constraint.
void print_usage(const char* program)
{
	std::fprintf(stderr,
	             "Usage: %s <prefix> <hex-suffix> <attempts> [start-nonce]\n"
	             "Searches SHA-1(prefix + decimal nonce) for the suffix.\n"
	             "The complete candidate must be at most 55 bytes.\n"
	             "Example: %s demo- a 1000000\n",
	             program, program);
}

// Launch GPU known-answer tests and compare their output with trusted digests.
int validate_gpu_vectors()
{
	const unsigned char expected[kDigestSize * 2] = {
		0xa9,0x99,0x3e,0x36,0x47,0x06,0x81,0x6a,0xba,0x3e,
		0x25,0x71,0x78,0x50,0xc2,0x6c,0x9c,0xd0,0xd8,0x9d,
		0x51,0x92,0x47,0x6d,0xfc,0x3e,0xe7,0x79,0x03,0x07,
		0x31,0x88,0x23,0xe5,0x48,0x0b,0xcf,0x9b,0x40,0xcd
	};
	unsigned char* device_output = nullptr;
	unsigned char actual[kDigestSize * 2];
	check_cuda(cudaMalloc(&device_output, sizeof(actual)), "allocating test vectors");
	hash_vectors_kernel<<<1, 1>>>(device_output);
	check_cuda(cudaGetLastError(), "launching SHA-1 self-test");
	check_cuda(cudaMemcpy(actual, device_output, sizeof(actual),
	                      cudaMemcpyDeviceToHost), "copying test vectors");
	check_cuda(cudaFree(device_output), "freeing test-vector memory");
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
	// Read and validate the prefix, hexadecimal suffix, attempt count, and nonce range.
	if (argc < 4 || argc > 5) {
		print_usage(argv[0]);
		return EXIT_FAILURE;
	}

	const std::string prefix(argv[1]);
	std::string suffix(argv[2]);
	unsigned long long attempts = 0;
	unsigned long long start_nonce = 0;
	if (prefix.size() > kMaxMessageLength - 20) {
		std::fprintf(stderr, "Error: prefix must be at most 35 bytes.\n");
		return EXIT_FAILURE;
	}
	if (suffix.empty() || suffix.size() > 40) {
		std::fprintf(stderr, "Error: suffix must contain 1 to 40 hex characters.\n");
		return EXIT_FAILURE;
	}
	for (char& value : suffix) {
		if (parse_hex(value) < 0) {
			std::fprintf(stderr, "Error: suffix must contain only hexadecimal characters.\n");
			return EXIT_FAILURE;
		}
		if (value >= 'A' && value <= 'F')
			value = static_cast<char>(value - 'A' + 'a');
	}
	if (!parse_unsigned(argv[3], &attempts) || attempts == 0) {
		std::fprintf(stderr, "Error: attempts must be a positive integer.\n");
		return EXIT_FAILURE;
	}
	if (argc == 5 && !parse_unsigned(argv[4], &start_nonce)) {
		std::fprintf(stderr, "Error: start-nonce must be an unsigned integer.\n");
		return EXIT_FAILURE;
	}
	if (attempts - 1 > std::numeric_limits<unsigned long long>::max() - start_nonce) {
		std::fprintf(stderr, "Error: nonce range overflows 64-bit unsigned integers.\n");
		return EXIT_FAILURE;
	}

	// Confirm that a CUDA device is available and the requested launch fits its grid.
	int device_count = 0;
	check_cuda(cudaGetDeviceCount(&device_count), "querying CUDA devices");
	if (device_count == 0) {
		std::fprintf(stderr, "Error: no CUDA-capable GPU was found.\n");
		return EXIT_FAILURE;
	}
	cudaDeviceProp device_properties;
	check_cuda(cudaGetDeviceProperties(&device_properties, 0),
	           "querying GPU properties");
	const unsigned long long max_grid_attempts =
		static_cast<unsigned long long>(device_properties.maxGridSize[0]) *
		kThreadsPerBlock;
	if (attempts > max_grid_attempts) {
		std::fprintf(stderr, "Error: attempts exceed the single-launch GPU limit (%llu).\n",
		             max_grid_attempts);
		return EXIT_FAILURE;
	}

	if (validate_gpu_vectors() != 0)
		return EXIT_FAILURE;

	// Allocate GPU buffers and copy the shared prefix and suffix to device memory.
	unsigned char* device_prefix = nullptr;
	char* device_suffix = nullptr;
	unsigned long long* device_found = nullptr;
	int* device_found_flag = nullptr;
	check_cuda(cudaMalloc(&device_prefix, prefix.empty() ? 1 : prefix.size()),
	           "allocating prefix");
	check_cuda(cudaMalloc(&device_suffix, suffix.size()), "allocating suffix");
	check_cuda(cudaMalloc(&device_found, sizeof(*device_found)),
	           "allocating result");
	check_cuda(cudaMalloc(&device_found_flag, sizeof(*device_found_flag)),
	           "allocating result flag");
	if (!prefix.empty()) {
		check_cuda(cudaMemcpy(device_prefix, prefix.data(), prefix.size(),
		                      cudaMemcpyHostToDevice), "copying prefix");
	}
	check_cuda(cudaMemcpy(device_suffix, suffix.data(), suffix.size(),
	                      cudaMemcpyHostToDevice), "copying suffix");
	const unsigned long long no_result = std::numeric_limits<unsigned long long>::max();
	const int no_match = 0;
	check_cuda(cudaMemcpy(device_found, &no_result, sizeof(no_result),
	                      cudaMemcpyHostToDevice), "initializing result");
	check_cuda(cudaMemcpy(device_found_flag, &no_match, sizeof(no_match),
	                      cudaMemcpyHostToDevice), "initializing result flag");

	// Launch enough threads to cover the candidate range and time only the kernel.
	const unsigned int blocks = static_cast<unsigned int>(
		(attempts - 1) / kThreadsPerBlock + 1);
	cudaEvent_t kernel_start;
	cudaEvent_t kernel_stop;
	check_cuda(cudaEventCreate(&kernel_start), "creating kernel start event");
	check_cuda(cudaEventCreate(&kernel_stop), "creating kernel stop event");
	check_cuda(cudaEventRecord(kernel_start), "starting kernel timer");
	search_kernel<<<blocks, kThreadsPerBlock>>>(
		device_prefix, static_cast<int>(prefix.size()), device_suffix,
		static_cast<int>(suffix.size()), start_nonce, attempts, device_found,
		device_found_flag);
	check_cuda(cudaGetLastError(), "launching search kernel");
	check_cuda(cudaEventRecord(kernel_stop), "stopping kernel timer");
	check_cuda(cudaEventSynchronize(kernel_stop), "waiting for search kernel");
	float kernel_milliseconds = 0.0f;
	check_cuda(cudaEventElapsedTime(&kernel_milliseconds, kernel_start, kernel_stop),
	           "measuring search kernel");

	// Copy the match status back, then release the GPU buffers and timing events.
	unsigned long long gpu_found = no_result;
	int gpu_has_match = 0;
	check_cuda(cudaMemcpy(&gpu_found, device_found, sizeof(gpu_found),
	                      cudaMemcpyDeviceToHost), "copying search result");
	check_cuda(cudaMemcpy(&gpu_has_match, device_found_flag, sizeof(gpu_has_match),
	                      cudaMemcpyDeviceToHost), "copying result flag");
	check_cuda(cudaEventDestroy(kernel_start), "destroying kernel start event");
	check_cuda(cudaEventDestroy(kernel_stop), "destroying kernel stop event");
	check_cuda(cudaFree(device_prefix), "freeing prefix");
	check_cuda(cudaFree(device_suffix), "freeing suffix");
	check_cuda(cudaFree(device_found), "freeing result");
	check_cuda(cudaFree(device_found_flag), "freeing result flag");

	// Print the first matching nonce (if any) and the measured kernel duration.
	std::printf("GPU: %s\n", device_properties.name);
	if (!gpu_has_match) {
		std::printf("GPU: no match in %llu candidates\n", attempts);
	}
	else {
		std::printf("GPU match: %s%llu\n", prefix.c_str(), gpu_found);
	}
	std::printf("GPU kernel: %.3f ms\n", kernel_milliseconds);

	return EXIT_SUCCESS;
}
