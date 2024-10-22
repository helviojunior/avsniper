#reference: https://medium.com/assertqualityassurance/tutorial-de-pytest-para-iniciantes-cbdd81c6d761
import codecs
import os
import shutil
import struct
from pprint import pprint
import pytest, sys

from avsniper.util.disassembler import Disassembler
from avsniper.util.tools import Tools

from avsniper.avsniper import AVSniper
from avsniper.config import Configuration
from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.color import Color


def test_01_parse_dotnet():
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    try:
        with open('./tests/test_dotnet.exe', 'rb') as pe:
            data = bytearray(pe.read())

        Color.pl('\n{+} {O}Data size : {O}%s{W}' % len(data))

        mz = b"MZ"
        if data[0x0:0x2] != mz:
            raise Exception('File is not a PE file')

        pe_file = MicrosoftPe.from_bytes(data)

        Color.pl('\n{+} {O}PE Tags:{W}')
        Color.pl('  - ' + '\n  - '.join([t.strip() for t in Tools.pe_file_tags(pe_file).split(',')]))

        if not (pe_file.pe.optional_hdr.data_dirs.clr_runtime_header is not None
                and pe_file.pe.optional_hdr.data_dirs.clr_runtime_header.size >= 0x48
                and pe_file.pe.dotnet_header is not None
                and pe_file.pe.dotnet_metadata_header is not None
                and pe_file.pe.dotnet_metadata_header.streams is not None
                and len(pe_file.pe.dotnet_metadata_header.streams) > 0):
            raise Exception('PE file is not .NET')

        Color.pl('\n{+} {O}Native PE Sections:{W}')
        for s in pe_file.pe.sections:
            print(f"     {s}")

        #Color.pl('\n{+} {O}PE Resources:{W}')
        #Color.pl(Tools.pe_resource_table(pe_file))

        if pe_file.pe.certificate_table is not None:
            Color.pl('\n{+} {O}PE Certificates:{W}')
            Color.pl(Tools.pe_certificate(data=pe_file))

        Color.pl('\n{+} {O}.NET MetaData Header: {W}\n     %s' % pe_file.pe.dotnet_metadata_header)

        Color.pl('\n{+} {O}.NET Streams:{W}')
        for s in pe_file.pe.dotnet_metadata_header.streams:
            print(f"     {s}")

        assert True
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False


def test_02_parse_native():
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    try:
        with open('./tests/test_native.exe', 'rb') as pe:
            data = bytearray(pe.read())

        Color.pl('\n{+} {O}Data size : {O}%s{W}' % len(data))

        mz = b"MZ"
        if data[0x0:0x2] != mz:
            raise Exception('File is not a PE file')

        pe_file = MicrosoftPe.from_bytes(data)

        Color.pl('\n{+} {O}PE Tags:{W}')
        Color.pl('  - ' + '\n  - '.join([t.strip() for t in Tools.pe_file_tags(pe_file).split(',')]))

        Color.pl('\n{+} {O}Native PE Sections:{W}')
        Color.pl('\n'.join([
            ', '.join([
                Color.s("{O}%s: {G}%s{W}" % (k, v)) for k, v in ({
                    '     Section': s.name,
                    'Virtual Size': '0x' + (
                        ''.join([f'{x:02x}' for x in struct.pack('>I', s.virtual_size)])).zfill(8),
                    'Virtual Address': '0x' + (
                        ''.join(
                            [f'{x:02x}' for x in struct.pack('>I', s.virtual_address)])).zfill(8),
                    'Raw Size': '0x' + (
                        ''.join([f'{x:02x}' for x in struct.pack('>I', s.size_of_raw_data)])).zfill(8),
                    'Raw Address': '0x' + (
                        ''.join(
                            [f'{x:02x}' for x in struct.pack('>I', s.pointer_to_raw_data)])).zfill(8)
                }).items()
            ])

            for s in pe_file.pe.sections
        ]))

        Color.pl('\n{+} {O}PE Resources:{W}')
        Color.pl(Tools.pe_resource_table(pe_file))

        if pe_file.pe.certificate_table is not None:
            Color.pl('\n{+} {O}PE Certificates:{W}')
            Color.pl(Tools.pe_certificate(data=pe_file))

        Color.pl('\n{+} {O}Disassembly:{W}')
        dis = Disassembler(pe_file)
        Color.pl(dis.dump())

        assert True
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False


def tesnonot_03_dotnet():
    sys.argv = ['avsniper', './build/dotnet_test', '-vvv', '--enumerate', '--file', './tests/test_dotnet.exe', '-m', '15']
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    Configuration.initialized = False

    if os.path.exists(sys.argv[1]):
        shutil.rmtree(sys.argv[1])

    if not os.path.exists(sys.argv[1]):
        os.mkdir(sys.argv[1])

    o = AVSniper()
    o.print_banner()

    try:
        o.main()

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False


def tesnonot_04_dotnet():
    sys.argv = ['avsniper', './build/dotnet_test', '-vvv', '--strip']
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    Configuration.initialized = False

    if os.path.exists(sys.argv[1]):
        shutil.rmtree(sys.argv[1])

    if not os.path.exists(sys.argv[1]):
        os.mkdir(sys.argv[1])

    o = AVSniper()
    o.print_banner()

    try:
        o.main()

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False


def tesnonot_05_native():
    sys.argv = ['avsniper', './build/native_test', '-vvv', '--enumerate', '--file', './tests/test_native.exe', '-m', '15']
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    Configuration.initialized = False

    if os.path.exists(sys.argv[1]):
        shutil.rmtree(sys.argv[1])

    if not os.path.exists(sys.argv[1]):
        os.mkdir(sys.argv[1])

    o = AVSniper()
    o.print_banner()

    try:
        o.main()

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False


def tesnonot_06_native():
    sys.argv = ['avsniper', './build/native_test', '-vvv', '--strip']
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    Configuration.initialized = False

    if os.path.exists(sys.argv[1]):
        shutil.rmtree(sys.argv[1])

    if not os.path.exists(sys.argv[1]):
        os.mkdir(sys.argv[1])

    o = AVSniper()
    o.print_banner()

    try:
        o.main()

        assert True
        #sys.exit(0)
    except Exception as e:
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        Color.pl('\n{!} {O}Full stack trace below')
        from traceback import format_exc
        Color.p('\n{!}    ')
        err = format_exc().strip()
        err = err.replace('\n', '\n{W}{!} {W}   ')
        err = err.replace('  File', '{W}{D}File')
        err = err.replace('  Exception: ', '{R}Exception: {O}')
        Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

        assert False

