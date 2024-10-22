
## Help

```bash
avsniper -h
```

```bash
AV Sniper v0.1.14 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip and test binary string.

usage:
    avsniper projet_path module [flags]

positional arguments:
  [project path]    Project path

Available Modules:
  --check-remote    Check detected files using a remote server
  --clean           Clean already processed strings
  --enumerate       Enumerate EXE file
  --show-blacklist  Show black listed strings
  --strip           Strip EXE file
  --bl-to-str       Transform all blacklisted strings as file strings

Global Flags:
  -h, --help        Show help message and exit
  -v                Specify verbosity level (default: 0). Example: -v, -vv, -vvv
  --version         Show current version

Use "avsniper projet_path [module] --help" for more information about a command.

```

## Utilization

### Step 1 – Enumerate strings at EXE file
This step will parse the EXE file, create the database (SQLite3) and extract the strings.

```bash
avsniper E:\Results\ --create-path --enumerate --file E:\Shared\Sample.exe -m 10 -vv
```

Where:

* The first parameter is the output directory where the SQLite database and all PE files will be stored
* `--create-path` indicate to create output directory if it does not exist
* `--enumerate` indicate the module (of application to be used)
* `--file` indicate the file to be analysed
* `-m 10` indicate the minimum size of string
* `-vv` verbose level 2

Sample output
```bash
 [+] Startup parameters
     command line: avsniper E:\Results\ --enumerate --file E:\Shared\Sample.exe --force -m 10 -vv
     verbosity level: 2
     module: enumerate
     minimum string length: 5
     minimum percent of printable ASCII string: 0%
     check .NET: Enabled
 [+] Start time 2024-10-09 07:58:45
 [+] SHA 256 Hash: 4ba60166e7e9c01ef6fb67cfcc22bb4ca4ba60166e7e9c01ef6fb67cfcc22bb4
 [+] Tags: PE, AMD64, Win 64, Windows GUI, .Net v4.0.30319
 [*] Parsing .NET PE file using ASCII encoding
 [*] Parsing .NET PE file using UTF-8 encoding
 [*] Parsing .NET PE file using UTF-16 BE encoding
 [*] Parsing .NET PE file using UTF-16 LE encoding
 [*] Parsing .NET PE file using UTF-32 BE encoding
 [*] Parsing .NET PE file using UTF-32 LE encoding
 [+] Checking strings that crashe EXE files
 [+] strings list finished, waiting processors...
 [+] Calculating binary tree
 [+] Strings found:
     ────────────┬───────────┬────────────────┬────────────
        Quantity │ Section   │ .net section   │ Encoding
     ────────────┼───────────┼────────────────┼────────────
             794 │ #strings  │ T              │ UTF-8
             672 │ .rsrc     │ F              │ UTF-8
              94 │ #us       │ T              │ UTF-16 BE
              28 │ .rsrc     │ F              │ UTF-16 LE
              20 │ #us       │ T              │ UTF-16 LE
              16 │ #blob     │ T              │ UTF-8
               8 │ .rsrc     │ F              │ ASCII
               2 │ .rsrc     │ F              │ UTF-32 LE
               1 │ #blob     │ T              │ UTF-16 BE
               1 │ #blob     │ T              │ UTF-16 LE
               1 │ #~        │ T              │ UTF-16 LE
     ────────────┴───────────┴────────────────┴────────────

 [+] End time 2024-10-09 07:59:08
```

### Step 2 – Creating sample files
This step will generates all sample EXE files to be tested by AV.

```bash
avsniper E:\Results\ --strip -vv
```

Where:

* The first parameter is the output directory where the SQLite database and all PE files will be stored
* `--strip` indicate the module (of application to be used)
* `-vv` verbose level 2

Sample output
```bash

AV Sniper v0.1.3 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip binary string.

 [+] Startup parameters
     command line: avsniper E:\Results\ --strip --file E:\Shared\Sample.exe --force -m 10 -vv
     verbosity level: 2
     module: strip
 [!] Database exists (you have 10 seconds to abort...) to prevent overwriting.
 [+] Start time 2024-10-08 14:33:05
 [+] SHA 256 Hash: 4ba60166e7e9c01ef6fb67cfcc22bb4ca4ba60166e7e9c01ef6fb67cfcc22bb4
 [*] Parsing .NET PE file using ASCII encoding
 [*] Parsing .NET PE file using UTF-8 encoding
 [*] Parsing .NET PE file using UTF-16 BE encoding
 [*] Parsing .NET PE file using UTF-16 LE encoding
 [*] Parsing .NET PE file using UTF-32 BE encoding
 [*] Parsing .NET PE file using UTF-32 LE encoding
 [+] Strings found:
     ────────────┬───────────┬────────────
        Quantity │ Section   │ Encoding
     ────────────┼───────────┼────────────
             655 │ #strings  │ UTF-8
             305 │ #us       │ UTF-16 LE
              40 │ #us       │ UTF-16 BE
              16 │ #blob     │ UTF-8
               1 │ #blob     │ UTF-16 LE
               1 │ #~        │ UTF-16 LE
     ────────────┴───────────┴────────────

 [+] Generating stripped files
 [+] Generating PE files
 [+] Fully stripped file saved as 0000000_stripped.exe
 [+] Generated files:
     ────────────┬──────────────
        Quantity │ Type
     ────────────┼──────────────
            1018 │ Unique
            1018 │ Sliced
            1018 │ Incremental
               1 │ All stripped
     ────────────┴──────────────

 [+] End time 2024-10-08 14:33:14
```

### Step 2 – Checking at the test host
At the test host (machine where the AV is installed) we can verify the generated EXE files

**Note:** At the test machine we do not need to install this tool, because at this machine we will run just a powershell script

1.  Download these 2 files at the target machine: [web-server.ps1](web-server.ps1) and [start_server.cmd](start_server.cmd)
2.  Save these 2 files at the same folder
3.  Open a powershell bash as administrator and run the commands bellow to permit the web server to bind at TCP port 8080
    *  `netsh http add urlacl url=http://+:8080/ user=([System.Security.Principal.WindowsIdentity]::GetCurrent().Name)`
    *  `New-NetFirewallRule -DisplayName "AllowTestWebServer" -Direction Inbound -Protocol TCP -LocalPort 8080 -Action Allow`
4.  Run the script `web-server.ps1` (in a non administrator cmd) to start the server

After this you must see the following screen

![Web server running](https://github.com/helviojunior/avsniper/blob/main/docs/images/web_server.jpg)

#### Check EXE files

At your current machine `machine where the AV Sniper is installed and have no EDR/AV`, execute the command bellow

```bash
avsniper E:\Results\ --check-remote --api http://xxx.xxx.xxx.xxx:8080 --strict -T 10
```

This command fill does the following action:
1.	Upload (encrypted and obfuscated) EXE file to remote web server
2.	Decrypt and deobfuscate the file and save at the disk
2.	Open file and read this content
3.	Generate the file hash and compare with the database hash
4.  Execute the EXE file as SUSPENDED mode
5.  Open file and read this content
6.	Generate the file hash and compare with the database hash

If any of this steps above fail, the file (and his respective string) is marked as identified by AV

Where:
* The first parameter is the directory path where the SQLite database and all PE files are stored
* `--check-remote` indicate the module (of application to be used)
* `--api` indicate the URL of our Powershell Web Server
* `--strict` indicate that only non-broken EXE files must be tested
* `-T 10` indicate the number of worker process
* `-vv` verbose level 2

Sample output
```bash
AV Sniper v0.1.3 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip binary string.

 [+] Startup parameters
     command line: avsniper E:\Results\ --check-remote --api http://xxx.xxx.xxx.xxx:8080 --strict -T 10
     verbosity level: 2
     module: check-remote
     temp path: E:\IZLRcLHrrZJaOluUsIFD
 [+] Start time 2024-10-08 14:18:45
 [+] Checking files
 [*] could not open file "0000472_incremental.exe"

 [!] interrupted, shutting down...
```

The application will show us the content of this string at the next steps, but for informational purpose to read this encoded strings we need to do this steps:
1.	Decode from base64 string
2.	Do XOR operation with 0x4d
3.	Decode the byte to String using the UTF-16 BE encoding
4.	Decode from base64 string

Using the [CyberChef](https://gchq.github.io/CyberChef/#recipe=From_Base64('A-Za-z0-9%2B/%3D',true,false)XOR(%7B'option':'Hex','string':'4d'%7D,'Standard',false)Decode_text('UTF-16BE%20(1201)')From_Base64('A-Za-z0-9%2B/%3D',true,false)&input=VFJsTkNrMTBUU1ZORjAwSVRUMU5OMDBZVFg5TkcwMTlUU2xORlUwTVRYQT0) we can see this result

* **Input:** `TRlNCk10TSVNF00ITT1NN00YTX9NG019TSlNFU0MTXA=`
* **Output:** `LoadJsSetup`

### Step 3 – Recreating sample files
Now we will repeat the same command at the step 1, will parse the EXE file, update the database (SQLite3), extract the strings and generates all sample EXE files to be tested by AV.
Note: As we already have a database, and one or more blacklisted (identified) string, the tool will not put this string at the generated EXE files. 
At the image bellow we can see this behavior. 

Sample output
```bash

AV Sniper v0.1.3 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip binary string.

 [+] Startup parameters
     command line: avsniper E:\Results\ --strip --file E:\Shared\Sample.exe --force -m 10 -vv
     verbosity level: 2
     module: strip
 [!] Database exists (you have 10 seconds to abort...) to prevent overwriting.
 [+] Start time 2024-10-08 14:33:05
 [+] SHA 256 Hash: 4ba60166e7e9c01ef6fb67cfcc22bb4ca4ba60166e7e9c01ef6fb67cfcc22bb4
 [*] Parsing .NET PE file using ASCII encoding
 [*] Parsing .NET PE file using UTF-8 encoding
 [*] Parsing .NET PE file using UTF-16 BE encoding
 [*] Parsing .NET PE file using UTF-16 LE encoding
 [*] Parsing .NET PE file using UTF-32 BE encoding
 [*] Parsing .NET PE file using UTF-32 LE encoding
 [+] Strings found:
     ────────────┬───────────┬────────────
        Quantity │ Section   │ Encoding
     ────────────┼───────────┼────────────
             655 │ #strings  │ UTF-8
             305 │ #us       │ UTF-16 LE
              40 │ #us       │ UTF-16 BE
              16 │ #blob     │ UTF-8
               1 │ #blob     │ UTF-16 LE
               1 │ #~        │ UTF-16 LE
     ────────────┴───────────┴────────────

 [+] Generating stripped files
 [+] Generating PE files
 [+] Fully stripped file saved as 0000000_stripped.exe
 [*] Ignoring black listed string id 2161
     00000000: 4C 6F 61 64 4A 73 53 65  74 75 70                 LoadJsSetup

 [+] Generated files:
     ────────────┬──────────────
        Quantity │ Type
     ────────────┼──────────────
            1018 │ Unique
            1018 │ Sliced
            1018 │ Incremental
               1 │ All stripped
     ────────────┴──────────────

 [+] End time 2024-10-08 14:33:14
```

Also the application show us what was the flagged string. 

```bash
...
 [*] Ignoring black listed string id 2161
     00000000: 4C 6F 61 64 4A 73 53 65  74 75 70                 LoadJsSetup
...
```

### Step 4 – Testing again
Now we will repeat the same command at the step 2.

### Step 5 – Checking flagged strings

In order to understand better where is the flagged string, we can check it using the command bellow

```bash
avsniper E:\Results\sample_ikarus --list --black-list

AV Sniper v0.1.17 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip and test binary string.

 [+] Startup parameters
     command line: avsniper E:\Results\sample_ikarus --list --black-list
     module: list
 [+] Start time 2024-10-14 19:37:56
 [+] Strings list
 ────────────────────────────────────────────────
  File: sample.exe
  SHA 256 Hash: 4ba60166e7e9c01ef6fb67cfcc22bb4ca4ba60166e7e9c01ef6fb67cfcc22bb4
  Tags: PE, AMD64, Win 64, Windows GUI, .Net v4.0.30319

 ────────────┬─────────────┬───────────┬──────────┬────────────┬────────────────────────────────────
  Address    │   String id │ Section   │ Dotnet   │ Encoding   │ Encoded_string
 ────────────┼─────────────┼───────────┼──────────┼────────────┼────────────────────────────────────
  0x0001588a │        1760 │ #us       │ True     │ UTF-16 BE  │ Sample;component/offerscreen.xaml
 ────────────┴─────────────┴───────────┴──────────┴────────────┴────────────────────────────────────


 [+] End time 2024-10-14 19:37:56
```

Another option is see detailed black listed strings

```bash
avsniper E:\Results\sample_defender\ --show-blacklist -vv

AV Sniper v0.1.10 by Helvio Junior (M4v3r1ck)
AV Sniper is a tool to strip binary string.

 [+] Startup parameters
     command line: avsniper E:\Results\sample_defender\ --show-blacklist -vv
     verbosity level: 2
     module: show-blacklist
     strategy: Direct
 [+] Start time 2024-10-16 18:28:42
 [+] Getting black listed strings
 [+] File: sample.exe
 ────────────────────────────────────────────────
  File: sample.exe
  SHA 256 Hash: 4ba60166e7e9c01ef6fb67cfcc22bb4ca4ba60166e7e9c01ef6fb67cfcc22bb4
  Tags: PE, AMD64, Win 64, Windows GUI, .Net v4.0.30319
 ────────────────────────────────────────────────
  Raw Address: 0x0016b702
  Section: Native .rsrc
  Size: 12
  Encoding: UTF-8
  Black list id: 1
  String id: 3487
 ────────────────────────────────────────────────
  Digital Signature
   └── Certificate Entry, Type: Pkcs_signed_data, Raw. Address: 0x00168c08, Size: 0x00002bc0  ←
       ├── SHA-256..: 2ef59d35885240f725762ab35f8eecca8aca06f1977df35dd620cb377e1377d6
       ├── MIME.....: application/octet-stream
       ├── Sign Info, entries: 5
       │   ├── Hash algorithm: sha256
       │   ├── Hash: b67fc90bf7e81fd5a6c4a7430396ff98deaea89b609144c25437e2cd9f9974d8
       │   └── Attributes (microsoft_time_stamp_token)
       │       ├── Type: signed_data
       │       ├── Signer info (Hash): 94258e0f06b1e7bf621a9de8bc2de7422e7bc981b40825f90ed667afe574fb69
       │       ├── Signer info (Signature):
       │       │     0016b642: 0F 7B CE C0 1B C0 24 7D  61 FA 3D F8 83 9B F0 A5  .{....$}a.=.....
       │       │     0016b652: 5F 84 3D BE 24 DE 69 38  4F 68 29 63 6F 98 C5 EB  _.=.$.i8Oh)co...
       │       │     0016b662: A6 AB 4E 2C C9 77 BB E2  C4 7B 77 1C 84 D0 E6 C4  ..N,.w...{w.....
       │       │     0016b672: 99 5C 9C 9A 20 47 2C D4  BB 9E 46 28 E9 39 A4 D2  .\.. G,...F(.9..
       │       │     0016b682: A1 1C 11 27 5E BE 7D 1E  FC 89 EC E7 3B 6B 40 41  ...'^.}.....;k@A
       │       │     0016b692: 85 21 C9 3A 51 C7 14 A8  73 9B 21 50 9C F9 E1 23  .!.:Q...s.!P...#
       │       │     0016b6a2: 2F 1C F1 83 16 FB 6A B2  B7 B2 B6 67 64 47 9D AF  /.....j....gdG..
       │       │     0016b6b2: 67 7D E1 5A 41 E1 F1 2F  38 34 2D E9 F9 3E BE CC  g}.ZA../84-..>..
       │       │     0016b6c2: F9 85 A9 31 22 D4 31 C1  98 D4 79 D2 24 03 E1 F8  ...1".1...y.$...
       │       │     0016b6d2: 3D 89 BD EE C2 7B 05 D0  D9 41 6E 9C 8C 1D 65 FC  =....{...An...e.
       │       │     0016b6e2: B1 02 9B E1 09 F0 69 D1  8B D9 66 43 30 4C B9 8A  ......i...fC0L..
       │       │     0016b6f2: 92 95 B1 CA 60 8F 5C C8  9D 1F D4 B8 3B 7D 36 20  ....`.\.....;}6
       │       │   → 0016b702: 7D 45 C1 50 E9 E2 2F FD  B2 D2 25 AA 0B B0 09 0E  }E.P../...%.....
       │       │     0016b712: 17 13 84 8A 92 5C B4 4F  27 C1 D4 E7 E9 DE 99 FC  .....\.O'.......
       │       │     0016b722: E0 87 1C 4B B7 AD BE AB  8B CE F6 69 23 7F D4 40  ...K.......i#..@
       │       │     0016b732: 97 7B B9 F3 6E 1F 91 CC  D8 49 47 B5 C0 54 EE 82  .{..n....IG..T..
       │       │     0016b742: 13 21 BE 19 1C C0 64 50  93 8E 9C 9B 27 90 E9 08  .!....dP....'...
       │       │     0016b752: 45 D8 91 9E 30 DD 4F 20  7E 4B 61 34 92 B2 5D 0D  E...0.O ~Ka4..].
       │       │     0016b762: 69 E4 D7 1F 94 6E 42 7C  20 BE 71 C0 DA 45 E6 D6  i....nB| .q..E..
       │       │     0016b772: FA 7F 04 97 6E E9 5C E9  F6 B1 02 5A 8C 18 08 2E  ....n.\....Z....
       │       │     0016b782: 62 44 72 68 35 D5 F8 59  92 F7 7D 52 58 37 AE 99  bDrh5..Y..}RX7..
       │       │     0016b792: FA C4 59 D1 A3 47 EC E4  34 CF 1C DC E9 94 80 75  ..Y..G..4......u
       │       │     0016b7a2: A7 DF A3 C5 AB 88 BC 37  BE 05 F8 BE 54 DD 2D D2  .......7....T.-.
       │       │     0016b7b2: 29 A9 3B 24 02 BC 47 B9  58 9C 7F 9F      ).;$..G.X...  ←
       │       ├── Certificate 0 (Serial): 2339707383737284136150073125663650077
       │       ├── Certificate 0 (Subject): Globalsign TSA for Advanced - G4
       │       ├── Certificate 0 (Issuer): GlobalSign Timestamping CA - SHA384 - G4
       │       ├── Certificate 0 (Fingerprint): 9f20deab9e36d5020a8ccc0530387c687f2ad1c7
       │       ├── Certificate 1 (Serial): 152301165417217153014605563764
       │       ├── Certificate 1 (Subject): GlobalSign Timestamping CA - SHA384 - G4
       │       ├── Certificate 1 (Issuer): GlobalSign
       │       ├── Certificate 1 (Fingerprint): f585500925786f88e721d235240a2452ae3d23f9
       │       ├── Certificate 2 (Serial): 154201219015179786474947899900
       │       ├── Certificate 2 (Subject): GlobalSign
       │       ├── Certificate 2 (Issuer): GlobalSign
       │       ├── Certificate 2 (Fingerprint): 618a4f66f2ab56af464b0c3697f6f1c91f88f8b4
       │       ├── Certificate 3 (Serial): 4835703278459759426209954
       │       ├── Certificate 3 (Subject): GlobalSign
       │       ├── Certificate 3 (Issuer): GlobalSign
       │       └── Certificate 3 (Fingerprint): d69b561148f01c77c54578c10926df5b856976ad
       └── X509 Certificates, entries: 2
           ├── X509 Entry 0, Address: 0x00168c95 Size: 0x000006ec
           │   ├── Serial......: 159159760011286741492753271723304908269
           │   ├── Subject.....: GlobalSign GCC R45 EV CodeSigning CA 2020
           │   ├── Issuer......: GlobalSign Code Signing Root R45
           │   ├── Fingerprint.: c10bb76ad4ee815242406a1e3e1117ffec743d4f
           │   └── Alternate names, entries 0
           └── X509 Entry 1, Address: 0x00169381 Size: 0x0000074c
               ├── Serial......: 22839527670408942845317757697
               ├── Subject.....: SAMPLE COMPANY
               ├── Issuer......: GlobalSign GCC R45 EV CodeSigning CA 2020
               ├── Fingerprint.: 0af62114955f389a50f7fc8d7e90ff7c747b573e
               └── Alternate names, entries 0
 ────────────────────────────────────────────────
     0016b6d2: 3D 89 BD EE C2 7B 05 D0  D9 41 6E 9C 8C 1D 65 FC  =....{...An...e.
     0016b6e2: B1 02 9B E1 09 F0 69 D1  8B D9 66 43 30 4C B9 8A  ......i...fC0L..
     0016b6f2: 92 95 B1 CA 60 8F 5C C8  9D 1F D4 B8 3B 7D 36 20  ....`.\.....;}6
   → 0016b702: 7D 45 C1 50 E9 E2 2F FD  B2 D2 25 AA 0B B0 09 0E  }E.P../...%.....
     0016b712: 17 13 84 8A 92 5C B4 4F  27 C1 D4 E7 E9 DE 99 FC  .....\.O'.......
     0016b722: E0 87 1C 4B B7 AD BE AB  8B CE F6 69 23 7F D4 40  ...K.......i#..@
     0016b732: 97 7B B9 F3 6E 1F 91 CC  D8 49 47 B5 C0 54 EE 82  .{..n....IG..T..
 ────────────────────────────────────────────────


 [+] End time 2024-10-16 18:28:43
```

## Sample of automation

Save the file [auto.ps1](../tests/auto.ps1) and run as follows

```
powershell -ep bypass -File .\auto.ps1
```

## Replace strings at the project

You can replace all black listed strings with the command bellow

```bash
avsniper E:\Results\sample_eset\ --auto-adjust --vs-project-path E:\path\to\visual_studio_project
```

Or all enumerated strings

```bash
avsniper E:\Results\sample_eset\ --auto-adjust --vs-project-path E:\path\to\visual_studio_project --all
```