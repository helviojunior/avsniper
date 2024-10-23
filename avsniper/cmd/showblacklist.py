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
from avsniper.util.disassembler import Disassembler
from avsniper.util import progress

from avsniper.util.cursor import Cursor
from avsniper.util.exerunner import ExeRunner
from avsniper.util.worker import Worker

from avsniper.cmdbase import CmdBase
from avsniper.config import Configuration
from avsniper.util.color import Color
from avsniper.util.logger import Logger
from avsniper.util.sniperdb import SniperDB
from avsniper.util.strings import Strings, StringsEncoding, StringPart
from avsniper.util.tools import Tools


class ShowBlackList(CmdBase):
    db = None
    order = 40
    force = False
    file_name = None
    check_database = True
    temp_folder = None
    execute_exe = False
    continue_on_flag = False
    count = 0
    tasks = 1

    bytes_before = 48
    bytes_after = 48
    t_line = ""
    t_header_prefix = ""

    def __init__(self):
        super().__init__('show-blacklist', 'Show black listed strings')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('-b',
                           action='store',
                           type=int,
                           default=48,
                           dest=f'bytes_before',
                           help=Color.s('Print num bytes of leading context before each match. (default: {G}48{W}).'))

        flags.add_argument('-a',
                           action='store',
                           type=int,
                           default=48,
                           dest=f'bytes_after',
                           help=Color.s('Print num bytes of leading context after each match. (default: {G}48{W}).'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.db = self.open_db(args)

        self.bytes_before = args.bytes_before
        self.bytes_after = args.bytes_after

        if self.bytes_before < 16:
            self.bytes_before = 16

        if self.bytes_after < 16:
            self.bytes_after = 16

        if self.bytes_before % 16 > 0:
            self.bytes_before += 16 - (self.bytes_before % 16)

        self.t_line = ' ' + ''.join([
            '%s──' % c for k, c in sorted(Color.gray_scale.items(), key=lambda x: x[0], reverse=True)
        ]) + Color.s('{W}\n')

        self.t_header_prefix = ' \033[38;5;52m=\033[38;5;88m=\033[38;5;124m=\033[38;5;160m=\033[38;5;196m> '

        return True

    def run(self):

        bl_count = 0
        try:
            Logger.pl('{+} {C}Getting black listed strings{W}')

            sql = ("select * from [src_file] "
                   "where src_file_id in ("
                   "    select src_file_id from [black_list]"
                   ")")
            db_files = self.db.select_raw(sql=sql, args=[])
            for f_row in db_files:
                Logger.pl('{+} {C}File: {O}%s{W}' % f_row['name'])
                f_data = StringPart.b64decode(f_row['original_data'])

                sql = ("select bl.*, "
                       "s.src_file_id, s.string_id, s.section, s.dotnet, s.address, s.bytes_size, s.virtual_address "
                       "from [black_list] as bl "
                       "inner join [string] as s "
                       "    on s.src_file_id = bl.src_file_id "
                       "    and s.sha256_hash = bl.sha256_hash "
                       "    and s.encoding = bl.encoding "
                       "where bl.src_file_id = ? "
                       "order by bl.created, s.address asc")
                db_data = self.db.select_raw(sql=sql, args=[f_row['src_file_id']])

                for r_idx, row in enumerate(db_data):
                    bl_count += 1
                    yara = {
                        'name': f'r_{f_row["sha256_hash"]}_{(r_idx + 1)}',
                        'strings': [],
                        'conditions': [
                            '// MZ signature at offset 0 and ...\nuint16(0) == 0x5A4D and',
                            ('// ... PE signature at offset stored in MZ header at 0x3C\n'
                             'uint32(uint32(0x3C)) == 0x00004550 and '),
                        ],
                        'comment': 'Details:'
                    }

                    addr = row['address']
                    size = row['bytes_size']
                    dump_size = size + self.bytes_after

                    # Check symmetry to 16 bytes
                    dump_size += (16 - (dump_size % 16)) if dump_size % 16 > 0 else 0

                    bl_data = f_data[addr - self.bytes_before: addr + dump_size]

                    dump = Tools.hexdump(
                        data=bl_data,
                        start_address=addr - self.bytes_before,
                        highlight_address=addr,
                        highlight_size=size,
                        prefix=' '
                    )

                    if StringsEncoding.parse(row["encoding"]) in [StringsEncoding.single_7_bit_byte,
                                                                  StringsEncoding.single_7_bit_byte]:
                        yara['strings'].append(
                            '// Address %s\n$r%s = "%s" wide ascii nocase' %
                            ('0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', addr)])).zfill(8),
                             r_idx,
                             ''.join([
                                chr(x)
                                if chr(x) in (pystr.ascii_uppercase +
                                              pystr.ascii_lowercase +
                                              pystr.ascii_letters) else f'\\x{x:02x}'
                                for x in StringPart.b64decode(row['encoded_string'])
                                ]))
                        )
                    else:
                        yara['strings'].append(
                            '// Address %s\n$r%s = { %s }' %
                            ('0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', addr)])).zfill(8),
                             r_idx,
                             ' '.join([
                                 f'{x:02x}'
                                 for x in StringPart.b64decode(row['encoded_string'])
                             ]))
                        )

                    tmp = '\n'.join([
                        Color.s("  {O}%s: {G}%s{W}" % (k, v)) for k, v in ({
                            'File': f_row['name'],
                            'SHA 256 Hash': f_row['sha256_hash'],
                            'Tags': f_row['tags'],
                        }).items()
                    ]) + '\n'
                    yara['comment'] += Tools.escape_ansi(tmp)

                    table = self.t_line
                    table += tmp
                    table += self.t_line

                    tmp = '\n'.join([
                        Color.s("  {O}%s: {G}%s{W}" % (k, v)) for k, v in ({
                            'Raw Address': '0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', addr)])).zfill(8),
                            'Virtual Address': '0x' + (
                                ''.join([f'{x:02x}' for x in struct.pack('>Q', row['virtual_address'])])).zfill(16),
                            'Section': ('.Net ' if row['dotnet'] == 'T' else 'Native ') + row['section'],
                            'Size': row['bytes_size'],
                            'Encoding': StringsEncoding.get_human_text(row['encoding']),
                            'Black list id': row["bl_id"],
                            'String id': row["string_id"]
                        }).items()
                    ]) + '\n'
                    yara['comment'] += '\nIdentification:\n' + Tools.escape_ansi(tmp)

                    table += tmp
                    table += self.t_line

                    file_row = self.db.select_first('src_file', src_file_id=row['src_file_id'])
                    if file_row is not None and len(file_row) > 0:
                        from avsniper.formats.microsoft_pe import MicrosoftPe
                        pe_file = MicrosoftPe.from_bytes(StringPart.b64decode(file_row['data']))

                        cert_tree = Tools.pe_certificate(
                            data=pe_file,
                            highlight_address=addr,
                            highlight_data=f_data[addr: addr + size],
                            show_only_highlighted=Configuration.verbose <= 3
                        )
                        if cert_tree is not None and cert_tree != "":
                            table += '  ' + '\n   '.join(cert_tree.strip('\n').split('\n')) + '\n'
                            table += self.t_line

                            if '←' in cert_tree:
                                yara['comment'] += '\n' + Tools.escape_ansi(cert_tree)

                        if row['section'] == '.rsrc':

                            yara['conditions'].append(('//Find at .rsrc\n(for any of ($r*) : ($ in ( '
                                                       '(pe.sections[pe.section_index(".rsrc")].raw_data_offset+'
                                                       'pe.sections[pe.section_index(".rsrc")].raw_data_size)..filesize)) '
                                                       ')  '))

                            # Save Resource file
                            Tools.pe_resource_table_extract(
                                file_id=f_row['src_file_id'],
                                data=pe_file,
                                save_address=addr)

                            res_tree = Tools.pe_resource_table(
                                data=pe_file,
                                highlight_address=addr,
                                show_only_highlighted=Configuration.verbose <= 3
                            )
                            if res_tree is not None and res_tree != "":
                                table += '  ' + '\n   '.join(res_tree.strip('\n').split('\n')) + '\n'
                                table += self.t_line

                                yara['comment'] += 'Resource table:\n' + Tools.escape_ansi(res_tree)

                        elif row['section'] == '.text' and row['dotnet'] == 'F':
                            yara['conditions'].append(('//Find at .text\n(for any of ($r*) : ($ in ( '
                                                       '(pe.sections[pe.section_index(".text")].raw_data_offset+'
                                                       'pe.sections[pe.section_index(".text")].raw_data_size)..filesize)) '
                                                       ')  '))

                            dis = Disassembler(pe_file)
                            code = dis.dump(
                                highlight_address=addr,
                                highlight_size=size,
                                show_only_highlighted=Configuration.verbose <= 3,
                                prefix=' '
                            )
                            if code != '':
                                table += code
                                table += self.t_line

                        else:
                            yara['conditions'].append('//Find at .rsrc\nany of them')

                    table += Color.s('{GR}%s{W}\n' % dump)
                    table += self.t_line

                    yara['comment'] += 'Hexdump:\n' + Tools.escape_ansi(Color.s(dump))

                    y_txt = ""
                    y_txt += '//Yara Rule\n'
                    y_txt += 'import "pe"\n'
                    y_txt += '/*\n'
                    y_txt += yara['comment']
                    y_txt += '*/\n\n'
                    y_txt += 'rule %s : PECheck {\n' % yara['name']
                    y_txt += '    meta:\n'
                    y_txt += '      author = "Helvio Junior (M4v3r1ck)"\n'
                    y_txt += '      description = "Raw Address: %s, Size %s"\n' % (
                             '0x' + (''.join([f'{x:02x}' for x in struct.pack('>I', addr)])).zfill(8),
                             row['bytes_size']
                    )
                    y_txt += '    strings:\n'
                    y_txt += '      ' + '\n      '.join([
                        s for s1 in yara['strings'] for s in s1.split('\n')
                    ])
                    y_txt += '\n    condition:\n'
                    y_txt += '      ' + '\n      '.join([
                        s for s1 in yara['conditions'] for s in s1.split('\n')
                    ])
                    y_txt += '\n}\n\n'

                    res_path = str(Path(os.path.join(Configuration.path, '../yara')).resolve())
                    shutil.rmtree(res_path, ignore_errors=True)
                    if not os.path.isdir(res_path):
                        os.mkdir(res_path)
                    f_name = os.path.join(res_path, f'{yara["name"]}_yara.txt')
                    with open(f_name, 'wb') as f_res:
                        f_res.write(y_txt.encode("UTF-8"))

                    if Configuration.verbose >= 2:
                        table += y_txt
                        table += self.t_line

                    Logger.pl(table)

                Logger.pl(' ')

            Configuration.exit_code = bl_count

        except KeyboardInterrupt as e:
            raise e
