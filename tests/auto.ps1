#-----------------------------------------------------------------------------;
# Author: Helvio Junior (helvio_junior[at]hotmail[dot]com)
# Update: 2024-10-13
#-----------------------------------------------------------------------------;
#
#
#-----------------------------------------------------------------------------;
# Parameters
#-----------------------------------------------------------------------------;

# Path to save the current project
$outPath="E:\Results\sample_eset"

# Full path of the EXE file to test
$file="E:\Shared\sample.exe"

# Remote server
$server="http://xxx.xxx.xxx.xxx:8080"

# Command to execute at remote server
#$cmd="powershell -ep bypass -file E:\T3scan\scan.ps1 -Filename {exe}"
$cmd=""

# Uncomment the command bellow to remove all folder
#Remove-Item $outPath -Recurse -Force -ErrorAction ignore

#-----------------------------------------------------------------------------;
# Code
#-----------------------------------------------------------------------------;

class CustomStopException : Exception {}

Function Kill-All {
	Get-Process | Select-Object Id,Path | Where-Object { $_.Path -like "$outPath\bin\*" }  | Stop-Process
}

# This step is responsible to reduce the number of strings to be analysed by step 2
# The goal is reduce up to 80% of strings to be analysed one-by-one at step 2
# Note: If we reduce a lot of we can face issue at Step 2
Function Invoke-Step1 {

	$lastCount=-1
	if ($null -eq $threshold -Or $threshold -ge 200){
		$threshold=200
	}
	try {
		1..10 | % {
			if (Test-Path "$outPath\sniper.db" -PathType Leaf){
				Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_bkp_tmp.db" -Force
			}
			Kill-All
			avsniper $outPath --strip -vv --disable-unique --disable-sliced --linear --strategy rev
			avsniper $outPath --check-remote --api $server --execute -T 20 -sleep 1 -vv --command "$cmd " --continue
			$code=$LastExitCode
			if (99999 -eq $code){
				Write-Host -ForegroundColor DarkRed "###########"
				Write-Host -ForegroundColor DarkRed "Error found at round $_, rollbacking database file..."
				Copy-Item -Path "$outPath\sniper_bkp.db" -Destination "$outPath\sniper.db" -Force
				throw [CustomStopException]::new()
			}
			Write-Host -ForegroundColor DarkYellow "###########"
			Write-Host -ForegroundColor DarkYellow "Round $_, $code string(s) flagged"
			Write-Host -ForegroundColor DarkYellow "   "
			if ($code -le $threshold -And $_ -gt 1){
				Write-Host -ForegroundColor DarkBlue "Threshold reached at round $_, rollbacking database file..."
				Copy-Item -Path "$outPath\sniper_bkp_tmp.db" -Destination "$outPath\sniper.db" -Force
				throw [CustomStopException]::new()
			}
			if ($lastCount -eq $code){
				avsniper $outPath --bl-to-str
				throw [CustomStopException]::new()
			}
			$lastCount=$code
			Copy-Item -Path "$outPath\sniper_bkp_tmp.db" -Destination "$outPath\sniper_bkp.db" -Force
			avsniper $outPath --bl-to-str
		}
	} catch [CustomStopException] {
		Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_step1.db" -Force
	}
}

Function Invoke-Step2 {
	try {
		while($true){
			Kill-All
			avsniper $outPath --strip -vv --disable-incremental --disable-sliced --linear --strategy rev
			avsniper $outPath --check-remote --api $server --execute -T 20 -sleep 1 -vv --command "$cmd "
			Write-Host -ForegroundColor DarkYellow "$LastExitCode string(s) flagged"
			if (0 -eq $LastExitCode -or 99999 -eq $LastExitCode){
				throw [CustomStopException]::new()
			}
		}
	} catch [CustomStopException] {
		Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_step2.db" -Force
	}

	# Check result
	avsniper $outPath --show-blacklist
	if (0 -eq $LastExitCode){
		try {
			while($true){
				Kill-All
				avsniper $outPath --strip -vv --disable-unique --disable-sliced --linear
				avsniper $outPath --check-remote --api $server --execute -T 20 -sleep 1 -vv --command "$cmd "
				Write-Host -ForegroundColor DarkYellow "$LastExitCode string(s) flagged"
				if (0 -eq $LastExitCode -or 99999 -eq $LastExitCode){
					throw [CustomStopException]::new()
				}
			}
		} catch [CustomStopException] {
			Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_step2.db" -Force
		}
	}
}

Function Invoke-Step3 {

	try {

		if (-not (Test-Path "$outPath\sniper.db" -PathType Leaf)){
			throw [CustomStopException]::new()
		}

        Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_bkp.db" -Force
		Kill-All
		avsniper $outPath --show-blacklist
		if ($LastExitCode -le 50){
			throw [CustomStopException]::new()
		}

		# Try to convert black list as strings
		# Check if we is usable of not
		avsniper $outPath --bl-to-str
		avsniper $outPath --check-remote --api $server --execute -T 20 -sleep 1 -vv --command "$cmd " --initial-check
		if (99999 -eq $LastExitCode){
			Write-Host -ForegroundColor DarkRed "###########"
			Write-Host -ForegroundColor DarkRed "Ops!, rollbacking database file..."
			Copy-Item -Path "$outPath\sniper_bkp.db" -Destination "$outPath\sniper.db" -Force
			throw [CustomStopException]::new()
		}

		Invoke-Step2

	} catch [CustomStopException] {
		Copy-Item -Path "$outPath\sniper.db" -Destination "$outPath\sniper_step3.db" -Force
	}
}

if ($null -eq $cmd){
	$cmd=""
}

avsniper $outPath --enumerate --create-path  --file $file --info -vv
$threshold=($LastExitCode * 0.2)

# Do initial Check
Kill-All
avsniper $outPath --strip -vv --disable-unique --disable-sliced --linear
avsniper $outPath --check-remote --api $server --execute -T 20 -sleep 1 -vv --command "$cmd " --initial-check
if (99999 -eq $LastExitCode){
	exit 1
}

Invoke-Step1
Invoke-Step2
Invoke-Step3

Remove-Item "$outPath\bin\" -Recurse -Force
#avsniper $outPath --show-blacklist -vv
avsniper $outPath --list --black-list