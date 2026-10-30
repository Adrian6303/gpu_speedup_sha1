# SHA-1 CPU and CUDA

Educational project that searches candidate strings for a SHA-1 digest ending
in a chosen hexadecimal suffix, and compares CPU and CUDA performance. Do not
use SHA-1 for security-sensitive applications.

## Run CPU tests

Use the VS 2022 Developer PowerShell terminal:

```powershell
cl /nologo /W4 /TC /Focpu\ /Fecpu\sha1_test.exe cpu\sha1.c cpu\sha1_test.c
if ($LASTEXITCODE -eq 0) { .\cpu\sha1_test.exe }
```

## Search with CUDA

From the project root in VS 2022 Developer PowerShell:

```powershell
nvcc -arch=sm_86 -O2 -std=c++17 gpu\sha1_search.cu -o gpu\sha1_search.exe
if ($LASTEXITCODE -eq 0) { .\gpu\sha1_search.exe demo- a 1000000 }
```

Arguments: `<prefix> <hex-suffix> <attempts> [start-nonce]`. Each candidate is
the prefix followed by a decimal nonce. This executable searches on the GPU
only; use the benchmark script for CPU/GPU timing comparisons.

## Benchmark

Builds the CPU and CUDA programs, warms up, then reports median CPU and GPU
process times plus the GPU kernel time:

```powershell
.\benchmark.ps1 -Attempts 5000000 -Runs 5
```

RTX 3050 Ti results, five runs; CPU is single-threaded. Process timings include
startup and CUDA initialization; kernel time excludes startup:

| Candidates | Power condition | CPU process | GPU process | GPU kernel | Kernel speedup | Process speedup |
|---:|---|---:|---:|---:|---:|---:|
| 5,000,000 | Plugged in, power mode | 0.762 s | 0.113 s | 8.852 ms | 86.09x | 6.72x |
| 10,000,000 | Plugged in, power mode | 1.508 s | 0.123 s | 17.687 ms | 85.28x | 12.23x |
| 100,000,000 | Plugged in, power mode | 15.247 s | 0.299 s | 177.665 ms | 85.82x | 50.96x |
| 500,000,000 | Plugged in, power mode | 76.152 s | 1.049 s | 900.690 ms | 84.55x | 72.56x |
| 5,000,000 | Battery, power saving | 1.342 s | 0.995 s | 10.020 ms | 133.89x | 1.35x |
| 10,000,000 | Battery, power saving | 2.686 s | 1.008 s | 19.740 ms | 136.07x | 2.66x |
| 100,000,000 | Battery, power saving | 26.925 s | 1.784 s | 210.889 ms | 127.67x | 15.10x |
| 500,000,000 | Battery, power saving | 135.684 s | 2.653 s | 1,063.628 ms | 127.57x | 51.15x |

Candidates are limited to 55 bytes; suffixes must be 1–40 hexadecimal
characters.

## Source

CPU implementation and test: [Brad Conte's crypto-algorithms repository](https://github.com/B-Con/crypto-algorithms), [SHA-1 test source](https://github.com/B-Con/crypto-algorithms/blob/master/sha1_test.c).