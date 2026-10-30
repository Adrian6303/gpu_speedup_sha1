param(
	[int]$Attempts = 10000000,
	[int]$Runs = 5
)

$ErrorActionPreference = "Stop"
$root = $PSScriptRoot
$cpuExecutable = Join-Path $root "cpu\sha1_search.exe"
$gpuExecutable = Join-Path $root "gpu\sha1_search.exe"

if ($Attempts -lt 1 -or $Runs -lt 1) {
	throw "Attempts and Runs must be positive integers."
}
if (-not (Get-Command cl -ErrorAction SilentlyContinue)) {
	throw "cl was not found. Open a VS 2022 Developer PowerShell terminal."
}
if (-not (Get-Command nvcc -ErrorAction SilentlyContinue)) {
	throw "nvcc was not found. Install the NVIDIA CUDA Toolkit."
}

Push-Location $root
try {
	& cl /nologo /O2 /TC /Focpu\ /Fecpu\sha1_search.exe cpu\sha1_search.c cpu\sha1.c
	if ($LASTEXITCODE -ne 0) {
		throw "CPU build failed; benchmark stopped."
	}
	& nvcc -arch=sm_86 -O2 -std=c++17 gpu\sha1_search.cu -o gpu\sha1_search.exe
	if ($LASTEXITCODE -ne 0) {
		throw "CUDA build failed; benchmark stopped."
	}

	$arguments = @("demo-", "a", "$Attempts")
	function Invoke-Search {
		param(
			[string]$Executable,
			[string[]]$Arguments,
			[string]$Kind
		)

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

		$kernelMilliseconds = $null
		if ($Kind -eq "GPU") {
			$kernel = [regex]::Match($text, 'GPU kernel: ([0-9.]+) ms')
			if (-not $kernel.Success) {
				throw "GPU search did not report its kernel time."
			}
			$kernelMilliseconds = [double]$kernel.Groups[1].Value
		}

		return [pscustomobject]@{
			Seconds = $timer.Elapsed.TotalSeconds
			KernelMilliseconds = $kernelMilliseconds
			Result = $result
		}
	}

	Write-Host "Warming up CPU and GPU..."
	$null = Invoke-Search $cpuExecutable $arguments "CPU"
	$null = Invoke-Search $gpuExecutable $arguments "GPU"
	$cpuTimes = @()
	$gpuTimes = @()
	$gpuKernelTimes = @()

	for ($run = 1; $run -le $Runs; $run++) {
		$cpu = Invoke-Search $cpuExecutable $arguments "CPU"
		$gpu = Invoke-Search $gpuExecutable $arguments "GPU"
		if ($cpu.Result -ne $gpu.Result) {
			throw "CPU and GPU found different results: '$($cpu.Result)' vs '$($gpu.Result)'."
		}
		$cpuTimes += $cpu.Seconds
		$gpuTimes += $gpu.Seconds
		$gpuKernelTimes += $gpu.KernelMilliseconds
		Write-Host "Completed run $run of $Runs."
	}

	$cpuSorted = @($cpuTimes | Sort-Object)
	$gpuSorted = @($gpuTimes | Sort-Object)
	$gpuKernelSorted = @($gpuKernelTimes | Sort-Object)
	$middle = [int][Math]::Floor($Runs / 2.0)
	$cpuMedian = [double]$cpuSorted[$middle]
	$gpuMedian = [double]$gpuSorted[$middle]
	$gpuKernelMedian = [double]$gpuKernelSorted[$middle]
	if (($Runs % 2) -eq 0) {
		$cpuMedian = ($cpuSorted[$middle - 1] + $cpuSorted[$middle]) / 2
		$gpuMedian = ($gpuSorted[$middle - 1] + $gpuSorted[$middle]) / 2
		$gpuKernelMedian = ($gpuKernelSorted[$middle - 1] + $gpuKernelSorted[$middle]) / 2
	}

	Write-Host ""
	Write-Host "Median end-to-end time for $Runs runs ($('{0:N0}' -f $Attempts) candidates each):"
	Write-Host ("CPU: {0:N3} s" -f $cpuMedian)
	Write-Host ("GPU process: {0:N3} s" -f $gpuMedian)
	Write-Host ("GPU kernel: {0:N3} ms" -f $gpuKernelMedian)
	Write-Host ("GPU kernel speedup: {0:N2}x" -f ($cpuMedian / ($gpuKernelMedian / 1000)))
	Write-Host ("GPU process speedup: {0:N2}x" -f ($cpuMedian / $gpuMedian))
}
finally {
	Pop-Location
}
