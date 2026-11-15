# SHA-1 proof-of-work search: sequential C, threaded C, and CUDA

This project searches for a 64-bit nonce `n` such that:

```text
SHA1(B || LE64(n))
```

ends in a chosen lowercase hexadecimal suffix. `B` is an arbitrary byte
sequence, `||` means concatenation, and `LE64(n)` is the nonce encoded as
exactly 8 little-endian bytes. The nonce range and input are identical for the
sequential C, OpenMP C, and CUDA implementations. Each version examines the
entire requested range and reports the lowest matching nonce; none stops early
when a match is found.

The CPU uses Brad Conte's C SHA-1 implementation. The CUDA program adapts its
SHA-1 operations for device execution; each GPU thread hashes one nonce. The
common input is hashed once on the host and the resulting SHA-1 state is
continued independently for each nonce. SHA-1 is used here for an educational
benchmark only, not for security-sensitive applications.

## Project layout

- `cpu\`: shared SHA-1 C implementation, CPU search, and CPU test sources
- `gpu\`: CUDA search source
- `cpu\build\` and `gpu\build\`: generated executables and compiler outputs
- `benchmark.ps1`: builds and benchmarks all three search modes

Build output folders are ignored by Git and are created automatically by the
benchmark script or the build commands below.

## Requirements

- Windows, Visual Studio 2022 C/C++ tools, and the NVIDIA CUDA Toolkit
- A CUDA-capable NVIDIA GPU
- Run build and benchmark commands from a Visual Studio Developer PowerShell
  terminal so the MSVC compiler environment is configured.

The CUDA build below targets `sm_86` (compute capability 8.6), used by the
GeForce RTX 3050 Ti Laptop GPU in the recorded hardware configuration. Change
the `-arch` value if building for a different GPU.

## CPU SHA-1 known-answer tests

Build and run the original CPU tests:

```powershell
New-Item -ItemType Directory -Force cpu\build | Out-Null
cl /nologo /W4 /TC /Focpu\build\ cpu\sha1.c cpu\sha1_test.c /Fecpu\build\sha1_test.exe
if ($LASTEXITCODE -eq 0) { .\cpu\build\sha1_test.exe }
```

## Build and run the searches

Build the CPU executable with OpenMP enabled:

```powershell
New-Item -ItemType Directory -Force cpu\build | Out-Null
cl /nologo /W4 /O2 /openmp /TC /Focpu\build\ /Fecpu\build\sha1_search.exe cpu\sha1_search.c cpu\sha1.c
```

CPU usage:

```text
cpu\build\sha1_search.exe <buffer-hex> <lowercase-hex-suffix> <attempts> [start-nonce] [threads]
```

For example, find a digest ending in `a` in a search starting at nonce zero:

```powershell
.\cpu\build\sha1_search.exe 64656d6f a 1000000 0 1
.\cpu\build\sha1_search.exe 64656d6f a 1000000 0 20
```

The first command runs the sequential case (one thread); the second requests
20 OpenMP threads. The input `64656d6f` is the bytes for `demo`. An empty input
buffer can be passed as `""`. The suffix must contain 1–40 lowercase hex
digits; the buffer must be encoded as even-length lowercase hex.

Build and run the CUDA executable:

```powershell
New-Item -ItemType Directory -Force gpu\build | Out-Null
nvcc -arch=sm_86 -O2 -std=c++17 -Icpu gpu\sha1_search.cu cpu\sha1.c -o gpu\build\sha1_search.exe
.\gpu\build\sha1_search.exe 64656d6f a 1000000 0
```

Before searching, the CUDA program runs three known-answer tests on the GPU
(including binary and multi-block test data). It also verifies any reported
GPU match with the host C SHA-1 implementation.

## Three-way benchmark

The benchmark builds all implementations, warms them up, runs the same
candidate range, and checks that all three return the same lowest match. It
reports medians and ranges for sequential CPU search time, threaded CPU search
time, and aggregate CUDA kernel time, plus CUDA process time and speedups.

```powershell
.\benchmark.ps1 -Attempts 1500000000 -Runs 3 -CpuThreads 20
```

The script defaults to those values. Increase `-Attempts` if the median CUDA
kernel time does not exceed the assignment's 2-second minimum; the script
warns when it does not. CUDA work is split into bounded kernel launches so a
long search does not require one multi-second kernel on Windows. The reported
CUDA kernel time is the aggregate event time around all chunks.

Timing interpretation:

- CPU search times are measured inside each CPU process and exclude process
  startup.
- CUDA kernel time excludes host-side input setup, CUDA initialization, memory
  allocation/transfers, and result verification.
- CUDA process time is measured by the benchmark around the whole executable;
  its difference from kernel time illustrates non-kernel overhead.
- Speedups compare CPU search medians to the aggregate CUDA kernel median.
  Process time is reported separately because it includes setup overhead.

The benchmark uses a 128-byte input containing byte values `00` through `7f`,
suffix `80bfe6c`, and start nonce zero. The suffix is known to match within the
default range.

### Recorded results

RTX 3050 Ti, 1.5 billion candidates, three runs, plugged in.

| Metric | Median | Range |
|---|---:|---:|
| Serial C search | 208.671 s | 208.468–217.760 s |
| Threaded C search (20 threads) | 23.466 s | 23.314–23.566 s |
| CUDA kernel | 2.415 s | 2.413–2.415 s |
| CUDA process | 2.525 s | — |
| CUDA non-kernel overhead | 0.110 s | — |

| Speedup comparison | Speedup |
|---|---:|
| Serial C vs. threaded C | 8.89x |
| Serial C vs. CUDA kernel | 86.42x |
| Threaded C vs. CUDA kernel | 9.72x |

The CUDA kernel median exceeds the assignment's 2-second minimum. An earlier
CUDA-only check of this workload measured 2.616 s; it is not part of the
three-way comparison above.

## Hardware used for previous measurements

- CPU: 12th Gen Intel Core i7-12700H, 2.30 GHz base speed, 1 socket,
  14 cores / 20 logical processors
- GPU: NVIDIA GeForce RTX 3050 Ti Laptop GPU, 2,560 CUDA cores,
  4.0 GB dedicated and 7.8 GB shared GPU memory

Older benchmark numbers in this repository were produced by a different
candidate format and workload, so they are not directly comparable to this
`B || LE64(n)` three-way benchmark.

## Source

- Brad Conte, [crypto-algorithms](https://github.com/B-Con/crypto-algorithms)
- Original [SHA-1 test source](https://github.com/B-Con/crypto-algorithms/blob/master/sha1_test.c)
