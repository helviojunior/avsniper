import errno
import hashlib
import os
import shutil
import sqlite3
import struct
import threading
import time
from argparse import _ArgumentGroup, Namespace
from pathlib import Path
from typing import Optional
import string as pystr

import hexdump

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.disassembler import Disassembler
from clint.textui import progress

from avsniper.util.cursor import Cursor
from avsniper.util.exerunner import ExeRunner
from avsniper.util.microsoft_pe_holder import MicrosoftPeHolder
from avsniper.util.worker import Worker

from avsniper.cmdbase import CmdBase
from avsniper.config import Configuration
from avsniper.util.color import Color
from avsniper.util.logger import Logger
from avsniper.util.sniperdb import SniperDB
from avsniper.util.strings import Strings, StringsEncoding, StringPart
from avsniper.util.tools import Tools


class CloneInfo(CmdBase):
    db = None
    file_name = None
    source_file = None
    check_database = False
    temp_folder = None
    f_data = None

    clone_info = True
    cert_chain = True

    t_line = ""
    t_header_prefix = ""

    def __init__(self):
        super().__init__('clone-info', 'Clone information')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--file',
                           action='store',
                           metavar='[PE file path]',
                           type=str,
                           dest=f'pe_file',
                           help=Color.s('Full path of the PE file'))

        flags.add_argument('--source',
                           action='store',
                           metavar='[PE file path]',
                           type=str,
                           dest=f'source_file',
                           help=Color.s('Full path of the PE file that info need to be cloned'))

        flags.add_argument('--no-info',
                           action='store_true',
                           default=False,
                           dest=f'no_clone_info',
                           help=Color.s('Disable clone File Info (default: {G}False{W})'))

        flags.add_argument('--no-cert-chain',
                           action='store_true',
                           default=False,
                           dest=f'no_cert_chain',
                           help=Color.s('Disable create fake certificate chain (default: {G}False{W})'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        if not os.path.exists(args.pe_file):
            Logger.pl(
                '{!} {R}error: PE file "{O}%s{R}" does not exists{W}\r\n' % args.pe_file)
            exit(1)

        try:
            with open(args.pe_file, 'r') as f:
                self.file_name = args.pe_file
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {O}permission denied{R}{W}\r\n' %
                    args.pe_file)
                exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {O}it is an directory{R}{W}\r\n' %
                    args.pe_file)
                exit(1)
            else:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {W}\r\n' %
                    args.pe_file)
                exit(1)

        if not os.path.exists(args.pe_file):
            Logger.pl(
                '{!} {R}error: PE file "{O}%s{R}" does not exists{W}\r\n' % args.pe_file)
            exit(1)

        try:
            with open(args.source_file, 'r') as f:
                self.source_file = args.source_file
                pass
        except IOError as x:
            if x.errno == errno.EACCES:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {O}permission denied{R}{W}\r\n' %
                    args.source_file)
                exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {O}it is an directory{R}{W}\r\n' %
                    args.source_file)
                exit(1)
            else:
                Logger.pl(
                    '{!} {R}error loading {O}%s{R}: could not open PE file {W}\r\n' %
                    args.source_file)
                exit(1)

        self.clone_info = not args.no_clone_info
        self.cert_chain = not args.no_cert_chain

        self.t_line = ' ' + ''.join([
            '%s──' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
        ]) + Color.s('{W}\n')

        self.t_header_prefix = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> '

        return True

    def run(self):
        try:

            import avsniper.libs.versioninfo.parser as vi

            res_path = str(Path(os.path.join(Configuration.path, '../clone')).resolve())
            shutil.rmtree(res_path, ignore_errors=True)
            if not os.path.isdir(res_path):
                os.mkdir(res_path)

            if Configuration.verbose >= 2:
                Logger.pl('{*} {GR}Loading files...{W}')
            with open(self.file_name, 'rb') as pe:
                self.f_data = bytearray(pe.read())

            with open(self.source_file, 'rb') as pe:
                source_data = MicrosoftPeHolder.from_bytes(pe.read())

            if Configuration.verbose >= 2:
                Logger.pl('{*} {GR}Loading original file information...{W}')
            tags = Tools.pe_file_tags(self.f_data)
            sha256_hash = hashlib.sha256(self.f_data).hexdigest().lower()

            Logger.pl('{+} {C}SHA 256 Hash: {O}%s{W}' % sha256_hash)
            Logger.pl('{+} {C}Tags: {O}%s{W}' % tags)

            table = '\n{+} Original data{W}'
            table += self.t_line
            table += '{+} {C}SHA 256 Hash: {O}%s{W}\n' % sha256_hash
            table += '{+} {C}Tags: {O}%s{W}\n\n' % tags

            # Replace FileInfo
            if self.clone_info:
                Logger.pl('{+} {W}Cloning file information{W}')

                new_fi = Tools.pe_version_raw(source_data)

                if Configuration.verbose >= 2:
                    Logger.pl('{*} {GR}Source/reference file information data len: {O}%s{W}' % len(new_fi))

                if len(new_fi) > 0:

                    old_len = len(new_fi)

                    filename = next(iter([
                        Path(v).stem + ".exe"
                        for k, v in Tools.pe_version(self.f_data).items()
                        if k in ['InternalName', 'OriginalFilename']
                        and v is not None
                        and str(v).strip() != ''
                    ]), str(Path(self.file_name).name))

                    new_data = {
                        'InternalName': Path(filename).stem,
                        'OriginalFilename': Path(filename).name,
                    }

                    # Replace Original Filename
                    ver = vi.get_detailed_version_info(new_fi)
                    if ver is not None:
                        for k, v in ({
                            k1: dict(
                                old=bytearray(
                                    int(len(kb) + len(od) + len(opad) + 6).to_bytes(length=2, byteorder='little') +  # wLength
                                    int(len(od) / 2).to_bytes(length=2, byteorder='little') +  # wValueLength
                                    int(1).to_bytes(length=2, byteorder='little') +  # wType
                                    kb +  # key bytes
                                    od +  # value bytes
                                    opad  # padding
                                ),
                                new=bytearray(
                                    int(len(kb) + len(dt) + len(pad) + 6).to_bytes(length=2, byteorder='little') +  # wLength
                                    int(len(dt) / 2).to_bytes(length=2, byteorder='little') +  # wValueLength
                                    int(1).to_bytes(length=2, byteorder='little') +  # wType
                                    kb +  # key bytes
                                    dt +  # value bytes
                                    pad  # padding
                                ),
                            )
                            for k1, v1 in ver.items()
                            if len(v1.get('Bytes', bytearray())) >= 0
                            and (dt := next(iter([
                                    bytearray(str(v2).encode("utf-16-le")) + bytearray([0x00, 0x00])
                                    for k2, v2 in new_data.items()
                                    if k2.lower() == k1.lower()
                                ]), None)) is not None
                            and (kb := bytearray(str(k1).encode("utf-16-le")) + bytearray([0x00, 0x00])) is not None
                            and (od := bytearray(v1['Bytes']) + bytearray([0x00, 0x00])) is not None
                            and (opad := (bytearray([0x00, 0x00]) * v1['Padding'])) is not None
                            and (pad := (bytearray([0x00]) * (4 - ((len(kb) + len(dt) + 6) % 4)))) is not None
                        }).items():
                            while new_fi.find(v['old']) != -1:
                                new_fi = bytearray(new_fi.replace(v['old'], v['new']).copy())

                        # Adjust header
                        diff = len(new_fi) - old_len
                        if diff != 0:

                            cursor = 0
                            try:
                                vs_versioninfo, cursor = vi.get_header(new_fi, cursor, expected='VS_VERSION_INFO')
                            except UnicodeDecodeError:
                                raise Exception('Header is not parsable and may be corrupted.')

                            # total size
                            wLength = int(
                                vs_versioninfo['wLength'] + diff
                            ).to_bytes(length=2, byteorder='little')
                            for i, b in enumerate(wLength):
                                new_fi[i] = b

                            # If the wValueLength is zero, the VS_FIXEDFILEINFO does not exist.
                            if vs_versioninfo['wValueLength'] == 52:
                                _, cursor = vi.get_ffi(new_fi, cursor)
                                _, cursor = vi.get_padding(new_fi, cursor)

                            fileinfo_type = vi.get_fileinfo_type(new_fi, cursor)
                            if fileinfo_type == 'StringFileInfo':
                                c1 = cursor
                                stringfileinfo, cursor = vi.get_header(new_fi, cursor, expected='StringFileInfo')

                                # StringFileInfo size
                                wLength = int(
                                    stringfileinfo['wLength'] + diff
                                ).to_bytes(length=2, byteorder='little')
                                for i, b in enumerate(wLength):
                                    new_fi[c1 + i] = b

                                if cursor < c1 + stringfileinfo['wLength']:
                                    c2 = cursor
                                    stringtable, cursor = vi.get_header(new_fi, cursor)

                                    wLength = int(
                                        stringtable['wLength'] + diff
                                    ).to_bytes(length=2, byteorder='little')
                                    for i, b in enumerate(wLength):
                                        new_fi[c2 + i] = b

                        #sanity check
                        try:
                            ver = vi.get_detailed_version_info(new_fi)
                        except Exception as e:
                            Tools.print_error(e)
                            raise Exception('Version data is not parsable and may be corrupted.')

                        self.f_data = Tools.pe_replace_version(self.f_data, new_fi)

            if self.cert_chain:
                Logger.pl('{+} {W}Generating fake digital certificate chain{W}')
                certs = [cert for cert in Tools.pe_certificate_list(source_data)]

                if len(certs) == 0:
                    Logger.pl('{!} {O}Warning: file {G}%s{O} has no digital signature {W}\r\n' % self.source_file)
                    source_data = self.f_data

                certs = [cert for cert in Tools.pe_certificate_list(source_data)]
                if len(certs) >= 0:

                    # Strip digital certificates
                    self.f_data = Tools.pe_strip_certificate(self.f_data, error_on_equal=False)

                    p12_name = os.path.join(res_path, f'cloned_cert.pfx')

                    # Create fake certificate chain
                    Tools.pe_create_fake_cert_pkcs12(source_data, p12_name)

                    self.f_data = Tools.sign_pe(self.f_data, p12_name)

            exe_name = os.path.join(res_path, f'cloned.exe')
            with open(exe_name, 'wb') as pe:
                pe.write(self.f_data)

            sha256_hash2 = hashlib.sha256(self.f_data).hexdigest().lower()
            if sha256_hash == sha256_hash2:
                raise Exception('Final file is the same of Original file')

            tags = Tools.pe_file_tags(self.f_data)
            table += '\n{+} Changed data{W}'
            table += self.t_line
            table += '{+} {C}SHA 256 Hash: {O}%s{W}\n' % sha256_hash2
            table += '{+} {C}Tags: {O}%s{W}\n' % tags

            ver_data = Tools.pe_version_raw(self.f_data)
            table += '{+} {C}Version info data len: {O}%s{W}\n' % len(ver_data) if ver_data is not None else "Empty"

            color1 = "{O}"
            color2 = "\033[92m"
            color3 = "{C}"
            color4 = "\033[35m"
            color5 = "{GR}"

            if ver_data is not None:
                try:
                    ver = vi.get_version_info(ver_data)
                    ms = max([
                        len(name) + 2
                        for name, _ in ver.items()
                    ] + [18])

                    table += '{+} {C}Version Info '
                    table += f'{color2}->{color1} StringFileInfo{color5}, entries: {len(ver)}\n'
                    table += f'{color5}\n'.join([
                           f"      {m1} {name}{dt}: {color1}{value}"
                           for idx, (name, value) in enumerate(
                            sorted(ver.items(), key=lambda x: x[0], reverse=False))
                           if (m1 := '└──' if (idx == len(ver) - 1) else '├──') is not None
                              and (dt := '.' * (ms - len(name)))
                    ])
                    table += "{W}\n"

                except Exception as e:
                    table += '   {GR}   └── {R}Invalid data: {GR}%s{W}' % str(e)

            certs = [cert for cert in Tools.pe_certificate_list(self.f_data)]
            if len(certs) > 0:

                table += '{+} {C}Certificates: '
                table += f'{color1}X509 Certificates{color5}, entries: {len(certs)}\n'
                table += f'{color5}\n'.join([
                    f'{color5}\n'.join([
                                           f"      {m} {color2}X509 Entry {idx}",
                                           f"      {m2}   ├── Subject.....: {color3}{cert['subject']}",
                                           f"      {m2}   ├── Serial......: {color1}{cert['serial_number']}",
                                           f"      {m2}   ├── Issuer......: {color1}{cert['issuer']}",
                                           f"      {m2}   ├── Fingerprint.: {color1}{cert['fingerprint']}",
                                           f"      {m2}   └── {color4}Alternate names{color5}, entries {sc}"
                                       ] + [
                                           f"      {m2}        {m3} {color4}Alternate name {idx2}{color5}: {an}"
                                           for idx2, an in enumerate(cert['san'])
                                           if (m3 := '├──' if idx == sc - 1 else '└──') is not None
                                       ])
                    for idx, cert in enumerate(Tools.pe_certificate_list(self.f_data))
                    if (f1 := (idx == len(certs) - 1)) is not None and
                       (m := '└──' if f1 else '├──') is not None and
                       (m2 := '   ' if f1 else '│  ') is not None and
                       (sc := len(cert['san'])) is not None
                ])
                table += "\n\n"

            Logger.pl(table)

            Logger.pl('{+} {W}File saved at: {O}%s{W}' % exe_name)

        except KeyboardInterrupt as e:
            raise e
