# How does it works?

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

## Understanding strip strategies

In order to understand steps 1 to 4, please see the document [Understanding strip strategies](strip_strategies.md)

## Understanding test environment

The main focus of this document is explain how to the tool test each EXE in order to check if it is flagged as malicious or not.

![Teste Environment](https://github.com/helviojunior/avsniper/blob/main/docs/images/test_environment.png)

As we can see at the image above the test environment has at least 2 machines:

1.  `Target machine`: Machine where the EDR/AV is installed
2.  `Test machine`: Machine where has no AV/EDR

### Target machine

At the target machine we do not need to install this tool, because at this machine we will run just a powershell script as detailed at [How to use](howto.md).

### Test machine

The test machine is the machine where this tool needs to be installed.

**Note:** This document does not explain each command parameter, this document purpose is to explain the technique and methodology, so to see detailed command, please see [How to use](howto.md). 

As we can see at the document [How to use](howto.md), these steps are proceeded:

**Note:** The number bellow is related to the image above with the test environment flow.

1.  The first step is generation of stripped files running `avsniper` with module `--strip`
2.  After generate all striped EXE files we need to run the `avsniper` with module `--check-remote` in order to check one by one EXE file using the web server. In other words when we run this command these following steps have been executed:
    2.  Send EXE file to the `target machine` using our powershell web server
    3.  At the `target machine` these steps is executed:
        *  Decode and decrypt received file and save file at the disk
        *  Read file from the disk and check his MD5 hash
        *  Try to execute the EXE file in suspended mode
        *  Onde again, read file from the disk and check his MD5 hash
    4.  The web server answer with the test result
    5.  `avsniper` receive the answer and check if this file is flagged or not by AV/EDR

## Strategy and results

Each strategy (`direct` and `reversed`), detailed at [Understanding strip strategies](strip_strategies.md), impact how the `avsniper` will interpret the result of the web server.

**Note:** We consider `bad string` as the array of bytes (pattern) that makes the AV/EDR trigger the EXE as malicious

### Direct

If the EXE files was generated using `direct` strategy, the tool will identify the `bad string` when the first EXE file is flagged by AV/EDR as malicious.

This behaviour is in fact to this strategy first remove all enumerated strings and will putting back one by one, so the first flag is the pattern looked up by the AV/EDR.

### Reversed

In other hand of the `direct` strategy, the `reversed` strategy will identify the `bad string` when the first EXE **NOT being** flagged by AV/EDR as malicious. 

In other words, as the name suggests, the `reverse` strategy keep all the original EXE file and will removing one by one previous enumerated strings, so the first EXE NOT flagged is the replaced pattern that bypass the AV/EDR