# AV Sniper

## Motivation
In terms of end point protection generally we have 2 big categories:

1.  Static Analysis: The AV products has hashes and patterns rules to identify a threat.
2.  Dynamic Analysis: The AV products try to understand the application behavior to identify a threat.

The focus of this study and tool is the first approach, where the AV flag the application as malicious without needs to run, in other words, just in fact to save the EXE at the disk, the AV catch them.
So, the motivation to create this tool is have an instrumentation to identify in a quick way what is the string (or set of strings) that is making the application flagged to the AV.

## General functions
The tool was designed to follow these actions:

1.  Parse Windows Portable Executable (aka PE) generally an EXE file.
2.  Identify if the PE is a native application developed in C, C++ and so on, or if is a .NET application.
3.  List all existing string in the file.
4.  Create several PE files to be checked by AV.
5.  Verify which PE file was flagged as malicious by AV.

## General flow
The general functions are executed according to the flow bellow:

1.  Parse Windows Portable Executable (aka `PE`) 
2.  Identify if the PE is a `native application` developed in C, C++ and so on, or if is a `.NET application`.
3.  List and store at the Database file all identified strings using the following encodings (`ASCII`, `UTF-8`, `UTF-16 BE`, `UTF-16 LE`, `UTF-32 BE`, `UTF-32 LE`)
4.  Save several PE (exe) files using 3 different strategies (according to the list below). Each file is related to one String at the database (identified at the step above)
    1.  Unique: Just one original string is kept at the file, all other strings are replaced by random strings
    2.  Incremental: The strings are being put at the file one-by-one 
    3.  Sliced: Just a range of 30 strings is kept at the file, all other strings are replaced by random strings. 
5.  At the protected machine (test machine with AV), check each generated file (by the step above) if it has flagged as malicious. As each file is related to a string, flag this string as blacklisted.
6.  At this point we return to step 4, but if has a blacklisted string at the database, the step for will not put back this string at the PE file, instead that, a random string will be put.


## Installation

```bash
pip3 install --upgrade avsniper
```

## Documentation

Follow the detailed documentation

1.  [How does it works](docs/howworks.md)
2.  [Understanding strip strategies](docs/strip_strategies.md)
3.  [How to use](docs/howto.md)
4.  [How to use - Remote commands](docs/remote_command.md)
5.  [Building](docs/build.md)
6.  Windows Http Server Module
    *  [web-server.ps1](docs/web-server.ps1)
    *  [start_server.cmd](docs/start_server.cmd)
