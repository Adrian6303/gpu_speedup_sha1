param(
	[UInt64]$Attempts = 1500000000,
	[ValidateRange(1, 25)]
	[int]$Runs = 3,
	[int]$CpuThreads = 20
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$cpuExecutable = Join-Path $root "cpu\sha1_search.exe"
$gpuExecutable = Join-Path $root "gpu\sha1_search.exe"
$bufferHex = -join (0..127 | ForEach-Object { $_.ToString("x2") })
$suffix = "80bfe6c"
$startNonce = [UInt64]0

if ($Attempts -lt 1 -or $CpuThreads -lt 1) {
	throw "Attempts and CpuThreads must be positive integers."
}
if ($Attempts -gt ([UInt64]::MaxValue - $startNonce)) {
	throw "Attempt range overflows the unsigned 64-bit nonce range."
}
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
	throw "cl was not found. Open a VS 2022 Developer PowerShell terminal."
}
if (-not (Get-Command nvcc -ErrorAction SilentlyContinue)) {
	throw "nvcc was not found. Install the NVIDIA CUDA Toolkit."
}

Push-Location $root
try {
	& cl /nologo /O2 /openmp /TC /Focpu\ /Fecpu\sha1_search.exe cpu\sha1_search.c cpu\sha1.c
	if ($LASTEXITCODE -ne 0) {
		throw "CPU search build failed."
	}
	& nvcc -arch=sm_86 -O2 -std=c++17 -Icpu gpu\sha1_search.cu cpu\sha1.c -o gpu\sha1_search.exe
	if ($LASTEXITCODE -ne 0) {
		throw "CUDA search build failed."
	}

	$attemptText = $Attempts.ToString([Globalization.CultureInfo]::InvariantCulture)
	$startText = $startNonce.ToString([Globalization.CultureInfo]::InvariantCulture)
	$warmupArguments = @($bufferHex, $suffix, "10000", $startText)
	$arguments = @($bufferHex, $suffix, $attemptText, $startText)

	function Invoke-Search {
		param(
			[string]$Executable,
			[string[]]$Arguments,
			[string]$Kind,
			[int]$Threads = 1
		)

		if ($Kind -eq "CPU") {
			$Arguments += "$Threads"
		}
		$timer = [Diagnostics.Stopwatch]::StartNew()
		$output = @(& $Executable @Arguments 2>&1)
		$exitCode = $LASTEXITCODE
		$timer.Stop()
		if ($exitCode -ne 0) {
			$output | ForEach-Object { Write-Host $_ }
			throw "$Kind search failed."
		}

		$text = $output -join "`n"
		$match = [regex]::Match($text, '(?:CPU|GPU) match: (.+)')
		if ($match.Success) {
			$result = $match.Groups[1].Value
		}
		elseif ($text -match '(?:CPU|GPU): no match') {
			$result = "<no match>"
		}
		else {
			throw "$Kind search did not report a match result."
		}

		$searchSeconds = $null
		$kernelMilliseconds = $null
		$actualThreads = $null
		if ($Kind -eq "CPU") {
			$threadMatch = [regex]::Match($text, 'CPU threads: ([0-9]+)')
			if (-not $threadMatch.Success) {
				throw "CPU search did not report its actual thread count."
			}
			$actualThreads = [int]::Parse($threadMatch.Groups[1].Value)
			$search = [regex]::Match($text, 'CPU search: ([0-9.]+) seconds')
			if (-not $search.Success) {
				throw "CPU search did not report elapsed search time."
			}
			$searchSeconds = [double]::Parse(
				$search.Groups[1].Value,
				[Globalization.CultureInfo]::InvariantCulture)
		}
		else {
			$kernel = [regex]::Match($text, 'GPU kernel: ([0-9.]+) ms')
			if (-not $kernel.Success) {
				throw "GPU search did not report kernel time."
			}
			$kernelMilliseconds = [double]::Parse(
				$kernel.Groups[1].Value,
				[Globalization.CultureInfo]::InvariantCulture)
		}

		return [pscustomobject]@{
			ProcessSeconds = $timer.Elapsed.TotalSeconds
			SearchSeconds = $searchSeconds
			KernelMilliseconds = $kernelMilliseconds
			ActualThreads = $actualThreads
			Result = $result
		}
	}

	Write-Host "Warming up serial C, threaded C, and CUDA..."
	$serialWarmup = Invoke-Search $cpuExecutable $warmupArguments "CPU" 1
	$threadedWarmup = Invoke-Search $cpuExecutable $warmupArguments "CPU" $CpuThreads
	if ($serialWarmup.ActualThreads -ne 1 -or $threadedWarmup.ActualThreads -ne $CpuThreads) {
		throw "OpenMP started $($threadedWarmup.ActualThreads) threads instead of the requested $CpuThreads."
	}
	$null = Invoke-Search $gpuExecutable $warmupArguments "GPU"

	$serialRuns = @()
	$threadedRuns = @()
	$gpuRuns = @()
	for ($run = 1; $run -le $Runs; $run++) {
		$serial = Invoke-Search $cpuExecutable $arguments "CPU" 1
		$threaded = Invoke-Search $cpuExecutable $arguments "CPU" $CpuThreads
		$gpu = Invoke-Search $gpuExecutable $arguments "GPU"
		if ($serial.ActualThreads -ne 1 -or $threaded.ActualThreads -ne $CpuThreads) {
			throw "CPU thread count changed during benchmark run $run."
		}
		if ($serial.Result -ne $threaded.Result -or $serial.Result -ne $gpu.Result) {
			throw "Search variants found different results: serial '$($serial.Result)', threaded '$($threaded.Result)', GPU '$($gpu.Result)'."
		}
		$serialRuns += $serial
		$threadedRuns += $threaded
		$gpuRuns += $gpu
		Write-Host "Completed run $run of $Runs."
	}

	function Get-Stats {
		param([double[]]$Values)

		$sorted = @($Values | Sort-Object)
		$middle = [int][Math]::Floor($sorted.Count / 2.0)
		if (($sorted.Count % 2) -eq 1) {
			$median = [double]$sorted[$middle]
		}
		else {
			$median = ([double]$sorted[$middle - 1] + [double]$sorted[$middle]) / 2
		}
		return [pscustomobject]@{
			Median = $median
			Min = [double]$sorted[0]
			Max = [double]$sorted[$sorted.Count - 1]
		}
	}

	$serialStats = Get-Stats @($serialRuns | ForEach-Object { $_.SearchSeconds })
	$threadedStats = Get-Stats @($threadedRuns | ForEach-Object { $_.SearchSeconds })
	$gpuKernelStats = Get-Stats @($gpuRuns | ForEach-Object { $_.KernelMilliseconds / 1000.0 })
	$gpuProcessStats = Get-Stats @($gpuRuns | ForEach-Object { $_.ProcessSeconds })
	$gpuOverhead = [Math]::Max(0.0, $gpuProcessStats.Median - $gpuKernelStats.Median)

	Write-Host ""
	Write-Host "Median search time (range across runs in parentheses), $attemptText candidates:"
	Write-Host ("Serial C: {0:N3} s ({1:N3}-{2:N3} s)" -f $serialStats.Median, $serialStats.Min, $serialStats.Max)
	Write-Host ("Threaded C ({0} threads): {1:N3} s ({2:N3}-{3:N3} s)" -f $CpuThreads, $threadedStats.Median, $threadedStats.Min, $threadedStats.Max)
	Write-Host ("CUDA kernel: {0:N3} s ({1:N3}-{2:N3} s)" -f $gpuKernelStats.Median, $gpuKernelStats.Min, $gpuKernelStats.Max)
	Write-Host ("CUDA process: {0:N3} s; non-kernel overhead: {1:N3} s" -f $gpuProcessStats.Median, $gpuOverhead)
	Write-Host ("Threaded CPU speedup over serial: {0:N2}x" -f ($serialStats.Median / $threadedStats.Median))
	Write-Host ("CUDA kernel speedup over serial: {0:N2}x" -f ($serialStats.Median / $gpuKernelStats.Median))
	Write-Host ("CUDA kernel speedup over threaded CPU: {0:N2}x" -f ($threadedStats.Median / $gpuKernelStats.Median))

	if ($gpuKernelStats.Median -le 2.0) {
		Write-Warning "CUDA kernel median is not over 2 seconds; increase -Attempts to meet the assignment's timing requirement."
	}
}
finally {
	Pop-Location
}
