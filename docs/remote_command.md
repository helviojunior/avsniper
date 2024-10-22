
## Remote Commands

Sometimes the AV to be tested cannot check at runtime, or it is just a command, in that cases the avsniper permit us to execute a remote command  

Example: 
```bash
avsniper E:\Results\sample_dev\ --check-remote --api http://xxx.xxx.xxx.xxx:8080 --command "powershell -ep bypass -file E:\T3scan\scan.ps1 -Filename {exe}" --execute -T 20 -sleep 1 -vv
```

The goal here is the following command that will be executed at remote host throughout the web server.
```bash
powershell -ep bypass -file E:\T3scan\scan.ps1 -Filename {exe}
```

Note: The string `{exe}` at command will be replaced by real path of tem EXE file generated and saved by web server.

## Remote AV - Command line

At the following sample we will use an Antivirus that jus return a text with status as follows

```bash
PS E:\> cd .\T3scan\
PS E:\T3scan> .\t3scan_w64.exe 'V:\Sample.exe'
IKARUS - T3SCAN V6.00.06 (WIN64)
         Engine version: 6.02.07
         VDB: 09.11.2023 13:23:13 (Build: 106495)
         Copyright - IKARUS Security Software GmbH 2021.
         All rights reserved.

V:\Sample.exe - Adware Signature 5152918 'PUA.MediaArena' found

  Summary:
  ==========================================================
    1 file scanned
    1 file infected
      (1 file contained 16 items, 0 infected)

    Used time: 0:00.266
  ==========================================================
```

Or

```bash
IKARUS - T3SCAN V6.00.06 (WIN64)
         Engine version: 6.02.07
         VDB: 09.11.2023 13:23:13 (Build: 106495)
         Copyright - IKARUS Security Software GmbH 2021.
         All rights reserved.


  Summary:
  ==========================================================
    0 files scanned
    0 files infected
      (0 files contained 0 items, 0 infected)

    Used time: 0:00.016
  ==========================================================
```

Note the following pattern `1 file infected` or `0 files infected`

So we created the following RegEx `([0-9]{1,3}) file[s]{0,1} infected` to extract the result text.

## Remote Script sample

As demonstrated above, we use the AV command output to identify if our EXE was flagged as malicious or not. So we created the following powershell script to execute the AV command line, check the response. If AV flagged our EXE file, the powershell script will remove the EXE file in order to the web server identify that the AV removed the file.

File: `scan.ps1`
```
param(
     [Parameter()]
     [string]$filename
 )


if (-not (Test-Path $filename -PathType Leaf))
{
    Write-Host "File not found: $filename"
    exit 1
}

Write-Host $filename
$txt=$(E:\T3scan\t3scan_w64.exe $filename) 
$m=[regex]::Match($txt, '([0-9]{1,3}) file[s]{0,1} infected')
if ($m.Success) 
{
    Write-Host $m
    if ($m.Groups[1].Value -gt 0) 
    { 
        Write-Host "Removing $filename "
        Remove-Item -Path $filename
        exit 0
    }else{
        exit 0
    }
}else{
    Write-Host $txt
    exit 1
}
```

### iKARUS download
```bash
#Bash
curl -H "Host: updates.ikarus.at" -LO "http://91.212.136.10/cgi-bin/t3download.pl/t3sigs.vdb"


#Powershell
Invoke-WebRequest -SkipCertificateCheck -Headers @{"Host"="updates.ikarus.at"} -URI "http://91.212.136.10/cgi-bin/t3download.pl/t3sigs.vdb" -OutFile "t3sigs.vdb"
```