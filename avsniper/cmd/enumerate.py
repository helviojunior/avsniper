import errno
import hashlib
import os
import shutil
import sqlite3
import threading
import time
from argparse import _ArgumentGroup, Namespace
from typing import List

import hexdump
from pathlib import Path

from avsniper.util.worker import Worker
from avsniper.util import progress
from functools import reduce

from avsniper.cmdbase import CmdBase
from avsniper.config import Configuration
from avsniper.util.color import Color
from avsniper.util.cursor import Cursor
from avsniper.util.exerunner import ExeRunner
from avsniper.util.logger import Logger
from avsniper.util.sniperdb import SniperDB
from avsniper.util.strings import Strings, StringsEncoding, StringPart
from avsniper.util.tools import Tools


class EnumerateFile(CmdBase):
    db = None
    order = 10
    file_name = None
    check_database = True
    min_size = 5
    threshold = 30
    min_entropy = 2.5
    no_dotnet = True
    count = 0
    f_data = None
    use_raw = False
    cert_only = False
    disable_crashable_string_check = False
    info = False

    def __init__(self):
        super().__init__('enumerate', 'Enumerate EXE file')

    def add_flags(self, flags: _ArgumentGroup):
        flags.add_argument('--create-path',
                           action='store_true',
                           default=False,
                           dest=f'path_create',
                           help=Color.s('Create path if not exists (default: {G}False{W}).'))

        flags.add_argument('--min-entropy',
                           action='store',
                           type=float,
                           default=2.5,
                           dest=f'min_entropy',
                           help=Color.s('Minimum entropy of the string (default: {G}2.5{W}).'))

        flags.add_argument('-m', '--min-size',
                           action='store',
                           type=int,
                           default=5,
                           dest=f'min_size',
                           help=Color.s('Minimum size of the string (default: {G}5{W}).'))

        flags.add_argument('--threshold',
                           action='store',
                           type=int,
                           default=30,
                           dest=f'threshold',
                           help=Color.s('Minimum percent of printable ASCII string (default: {G}30{W}).'))

        flags.add_argument('--no-dotnet',
                           action='store_true',
                           default=False,
                           dest=f'no_dotnet',
                           help=Color.s('If the file is a .NET, ignore it and strip all file data'))

        flags.add_argument('--raw',
                           action='store_true',
                           default=False,
                           dest=f'use_raw',
                           help=Color.s('Use as raw binary (default: {G}false{W}).'))

        flags.add_argument('--disable-crashable-string-check',
                           action='store_true',
                           default=False,
                           dest=f'disable_crashable_string_check',
                           help=Color.s('Ignore strings that crash the EXE file (default: {G}false{W}).'))

        flags.add_argument('--cert-only',
                           action='store_true',
                           default=False,
                           dest=f'cert_only',
                           help=Color.s('Enumerate only in Digital Certificate data (default: {G}False{W})'))

        flags.add_argument('--info',
                           action='store_true',
                           default=False,
                           dest=f'info',
                           help=Color.s('Show all PE information at the end (default: {G}False{W})'))

    def add_commands(self, cmds: _ArgumentGroup):
        cmds.add_argument('--file',
                          action='store',
                          metavar='[PE file path]',
                          type=str,
                          dest=f'pe_file',
                          help=Color.s('Full path of the PE file'))

    def load_from_arguments(self, args: Namespace) -> bool:

        if args.path_create and not os.path.isdir(Configuration.path):
            Path(Configuration.path).mkdir(parents=True)

        if not os.path.isdir(Configuration.path):
            Logger.pl('{!} {R}error: path does not exists {O}%s{R} {W}\r\n' % (
                Configuration.path))
            exit(1)

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
                Logger.pl('{!} {R}error: could not open PE file {O}permission denied{R}{W}\r\n')
                exit(1)
            elif x.errno == errno.EISDIR:
                Logger.pl('{!} {R}error: could not open PE file {O}it is an directory{R}{W}\r\n')
                exit(1)
            else:
                Logger.pl('{!} {R}error: could not open PE file {W}\r\n')
                exit(1)

        self.min_size = args.min_size
        self.min_entropy = round(args.min_entropy, 2)
        self.threshold = args.threshold
        self.use_raw = args.use_raw
        self.cert_only = args.cert_only
        self.disable_crashable_string_check = args.disable_crashable_string_check
        self.info = args.info

        if self.min_size < 3:
            self.min_size = 3

        if self.min_entropy < 0:
            self.min_entropy = 0
        elif self.min_entropy >= 10:
            self.min_entropy = 10

        if self.threshold < 0:
            self.threshold = 0
        elif self.threshold >= 100:
            self.threshold = 100

        Logger.pl('     {C}minimum string length:{O} %s{W}' % self.min_size)
        Logger.pl('     {C}minimum entropy:{O} %s{W}' % self.min_entropy)
        Logger.pl('     {C}minimum percent of printable ASCII string:{O} %s{W}' % f'{self.threshold}%')

        self.no_dotnet = args.no_dotnet

        Logger.pl('     {C}check .NET:{O} %s{W}' % ('Enabled' if not self.no_dotnet else 'Disabled'))

        if not os.path.isfile(Configuration.db_name):
            SniperDB(auto_create=True, db_name=Configuration.db_name)
            Logger.pl('{+} {C}Database created {O}%s{W}' % Configuration.db_name)

        self.db = self.open_db(args)

        return True

    def run(self):

        # Put on blacklist non finished checking
        self.db.execute(sql=(
            "INSERT or IGNORE into black_list (src_file_id, sha256_hash, encoded_string, encoding) "
            "select s.src_file_id, s.sha256_hash, s.encoded_string, s.encoding  from test_file tf "
            "inner join string s on s.string_id = tf.string_id "
            "where flagged = 'C'"), args=[])

        with open(self.file_name, 'rb') as pe:
            self.f_data = bytearray(pe.read())

        tags = Tools.pe_file_tags(self.f_data)
        sha256_hash = hashlib.sha256(self.f_data).hexdigest().lower()
        Logger.pl('{+} {C}SHA 256 Hash: {O}%s{W}' % sha256_hash)
        Logger.pl('{+} {C}Tags: {O}%s{W}' % tags)
        file_id = 0

        db_file = self.db.select_first('src_file', sha256_hash=sha256_hash)
        if db_file is not None and len(db_file) > 0 and db_file['finished'] == "T":
            file_id = db_file['src_file_id']
            if Configuration.verbose >= 1:
                Logger.pl('{+} {C}File is already scanned, skipping string search{W}')
        else:
            if db_file is None or len(db_file) == 0:
                md5_hash = hashlib.md5(self.f_data).hexdigest().lower()
                file_id = self.db.insert_file(name=self.file_name, sha256_hash=sha256_hash, md5_hash=md5_hash,
                                              data=self.f_data, tags=tags)
            else:
                # get data from DB
                # Because in sometimes the data can be different (in case of previous strip)
                self.f_data = StringPart.b64decode(db_file['data'])
                file_id = db_file['src_file_id']

            # clear old strings
            self.db.execute(sql="delete from [string] where src_file_id = ?", args=[file_id])

            # Filter by certificate only
            filter_addr = []
            if self.cert_only:
                filter_addr = [cd for cd in Tools.pe_certificate_positions(self.f_data)]

            sts = Strings(data=self.f_data, include_all_whitespace=True)
            try:
                Cursor.hide()
                # for data in StringsEncoding:
                for data in [
                    StringsEncoding.single_7_bit_byte,
                    StringsEncoding.single_8_bit_byte,
                    StringsEncoding.littleendian_16_bit,
                    StringsEncoding.bigendian_16_bit,
                    StringsEncoding.littleendian_32_bit,
                    StringsEncoding.bigendian_32_bit
                ]:
                    sts.reset()
                    count = 0
                    with progress.Bar(label=f" ",
                                      expected_size=len(self.f_data),
                                      unit='b',
                                      unit_label='Size',
                                      show_percent=True,
                                      no_tty_every_percent=10,
                                      auto_hide_cursor=True
                                      ) as bar:
                        try:
                            section = ""
                            Tools.clear_line(bar.line_size)
                            for s in sts.get_strings(encoding=data,
                                                     string_min=self.min_size,
                                                     threshold=self.threshold,
                                                     min_entropy=self.min_entropy,
                                                     parse_dotnet=not self.no_dotnet,
                                                     raw_binary=self.use_raw
                                                     ):
                                s.strip()

                                if s.section != section:
                                    bar.label = Color.s(" {W}{GR}Section: {W}{G}%s{W}{GR}, Encoding: {W}{G}%s{W} " % (
                                    s.section, StringsEncoding.get_human_text(data)))
                                    section = s.section

                                if Configuration.verbose < 5:
                                    bar.show(s.address)

                                if s.size >= self.min_size:
                                    if Configuration.verbose >= 4:
                                        bar.clear_line()
                                        Logger.pl("\n\n {*} {GR}%sString %s\n%s\n{W}" % (
                                            ".NET " if s.is_dotnet_section else "", count, s.hexdump()
                                        ))

                                    if len(filter_addr) == 0 or next(iter([
                                        True
                                        for f in filter_addr
                                        if f['start_addr'] <= s.address <= f['end_addr']
                                    ]), False):
                                        st = self.db.insert_string(file_id=file_id, string_part=s)
                                        count += int(st.get('inserted', 0))

                        except KeyboardInterrupt as e:
                            raise e
                        finally:
                            bar.hide = True
                            bar.no_tty_every_percent = None

            except KeyboardInterrupt as e:
                raise e
            finally:
                Cursor.show()

            Tools.kill_all_running()

            # Checking simular strings
            # error caused by endianess
            Logger.pl('{+} {C}Checking duplicated strings{W}')
            sql = ("select s.string_id, s.address, s.bytes_size, s.encoding, s.encoded_string "
                   "from [string] as s "
                   "where s.src_file_id == ? "
                   "and s.encoding in (?, ?, ?, ?) "
                   "order by s.address asc")
            args = [file_id,
                    str(StringsEncoding.littleendian_16_bit), str(StringsEncoding.bigendian_16_bit),
                    str(StringsEncoding.littleendian_32_bit), str(StringsEncoding.bigendian_32_bit)]
            db_data = self.db.select_raw(sql=sql, args=args)
            with progress.Bar(label=" Checking endianess strings ",
                              expected_size=len(db_data),
                              show_percent=True,
                              no_tty_every_percent=10,
                              auto_hide_cursor=True) as bar:
                try:
                    for idx, row in enumerate(db_data):
                        bar.show(idx)
                        enc = StringsEncoding.parse(row['encoding'])
                        l_enc = None
                        if enc == StringsEncoding.littleendian_16_bit:
                            l_enc = StringsEncoding.bigendian_16_bit
                        elif enc == StringsEncoding.bigendian_16_bit:
                            l_enc = StringsEncoding.littleendian_16_bit
                        elif enc == StringsEncoding.littleendian_32_bit:
                            l_enc = StringsEncoding.bigendian_32_bit
                        elif enc == StringsEncoding.bigendian_32_bit:
                            l_enc = StringsEncoding.littleendian_32_bit

                        if l_enc is None:
                            continue

                        addr = row['address']
                        decoded1 = StringPart.b64decode_as_str(row['encoded_string'], enc)

                        sql = ("select s.string_id, s.address, s.bytes_size, s.encoding, s.encoded_string "
                               "from [string] as s "
                               "where s.src_file_id = ? "
                               "and s.string_id != ? "
                               "and s.encoding = ? "
                               "and s.address between ? and ? "
                               "and bytes_size = ? "
                               "order by s.address asc")
                        args = [file_id, row['string_id'], str(l_enc), addr - 1, addr + 1,
                                row['bytes_size'] - (4 if l_enc in [StringsEncoding.littleendian_32_bit,
                                                                    StringsEncoding.bigendian_32_bit] else 2)
                                ]
                        sim_db_data = self.db.select_raw(sql=sql, args=args)
                        if sim_db_data is None or len(sim_db_data) == 0:
                            continue

                        decoded2 = StringPart.b64decode_as_str(sim_db_data[0]['encoded_string'], l_enc)
                        if len(decoded2) == len(decoded1) - 1 and decoded1.find(decoded2) == 1:
                            if Configuration.verbose >= 3:
                                bar.clear_line()
                                Logger.pl("{*} {GR}Removing duplicated string {O}%s{W}" % Tools.int_to_hex(addr))
                            self.db.delete('string', string_id=sim_db_data[0]['string_id'])

                except KeyboardInterrupt as e:
                    bar.hide = True
                    bar.clear_line()
                    raise e
                except Exception as ex:
                    Tools.print_error(ex)
                finally:
                    bar.hide = True
                    bar.no_tty_every_percent = None
                    Tools.clear_line()

            if not self.disable_crashable_string_check:
                Logger.pl('{+} {C}Checking strings that crashe EXE files{W}')
                sql = ("select s.string_id, s.address, s.bytes_size, s.encoding "
                       "from [string] as s "
                       "where s.src_file_id = ? "
                       "order by s.address asc")
                args = [file_id]
                db_data = self.db.select_raw(sql=sql, args=args)

                self.count = 0
                with Worker(callback=self.file_callback_crash, per_thread_callback=self.thread_start_callback,
                            threads=10) as t:
                    t.start()

                    with progress.Bar(label=" Checking strings ",
                                      expected_size=len(db_data),
                                      show_percent=True,
                                      no_tty_every_percent=10,
                                      auto_hide_cursor=True) as bar:

                        t1 = threading.Thread(target=self.status,
                                              kwargs=dict(sync=t, bar=bar))
                        t1.daemon = True
                        t1.start()

                        try:
                            Cursor.hide()
                            for row in db_data:
                                if not t.running:
                                    break

                                t.add_item(row)

                                while t.count > 100 and t.running:
                                    time.sleep(0.3)

                            time.sleep(0.5)
                            bar.clear_line()
                            Logger.pl('{+} {C}strings list finished, waiting processors...{W}')

                            t.wait_finish()

                        except KeyboardInterrupt as e:
                            bar.hide = True
                            time.sleep(0.4)
                            bar.clear_line()
                            raise e
                        finally:
                            t.close()
                            bar.hide = True
                            bar.no_tty_every_percent = None
                            Tools.clear_line()
                            Cursor.show()

            # Update file scan as finished
            self.db.update('src_file', filter_data=dict(src_file_id=file_id), finished='T')

        EnumerateFile.calculate_binary_tree(self.db, False)

        sql = ("select count(s.string_id) as qty, s.section, s.dotnet as '.NET section', s.encoding from string s "
               "group by s.section, s.dotnet, s.encoding order by qty desc")
        db_data = [
            {k: v if k != 'encoding' else StringsEncoding.get_human_text(v)
             for k, v in r.items()}
            for r in self.db.select_raw(sql=sql, args=[])
        ]

        if len(db_data) > 0:
            Logger.pl('{+} {C}Strings found:\n{GR}%s{W}\n' % Tools.get_ansi_tabulated(db_data, "     "))
        else:
            Logger.pl('{!} {R}Zero strings found{W}')

        strings_count = sum([
            int(r['qty'])
            for r in db_data
        ])

        Configuration.exit_code = strings_count

        if self.info:
            try:
                from avsniper.formats.microsoft_pe import MicrosoftPe
                pe_file = MicrosoftPe.from_bytes(self.f_data)

                res_tree = Tools.pe_resource_table(
                    data=pe_file,
                    highlight_address=0,
                    show_only_highlighted=False
                )
                if res_tree is not None and res_tree != "":
                    res_tree = '  ' + '\n   '.join(res_tree.strip('\n').split('\n')) + '\n'
                    Logger.pl('{+} {C}Resources:\n{GR}%s{W}\n' % res_tree)

                cert_tree = Tools.pe_certificate(
                    data=pe_file,
                    highlight_address=0,
                    highlight_data=None,
                    show_only_highlighted=False
                )
                if cert_tree is not None and cert_tree != "":
                    cert_tree = '  ' + '\n   '.join(cert_tree.strip('\n').split('\n')) + '\n'
                    Logger.pl('{+} {C}Certificates:\n{GR}%s{W}\n' % cert_tree)

            except Exception as e:
                Tools.print_error(e)

    def thread_start_callback(self, index, **kwargs):
        return self.db.clone()

    def file_callback_crash(self, worker, entry, thread_callback_data, thread_count, **kwargs):

        t_db = thread_callback_data

        try:

            if not self.disable_crashable_string_check:

                # Check if this specific string crashes the executable
                addr = entry["address"]
                size = entry["bytes_size"]
                rnd = StringPart.random_string(4, 'S').decode("UTF-8")
                filename = os.path.join(Configuration.path, f'tst_{addr}_{rnd}.exe')
                try:
                    tmp_data = self.f_data.copy()
                    r_data = StringPart.random_string(raw_size=size, encoding=entry["encoding"])
                    for i in range(0, size):
                        tmp_data[addr + i] = r_data[i]

                    with(open(filename, 'wb')) as f:
                        f.write(tmp_data)

                    if not ExeRunner.execute(filename):  # is crashed
                        for idx in range(5):
                            try:
                                os.unlink(filename)
                            except:
                                pass
                            try:
                                t_db.delete(
                                    table_name='string',
                                    string_id=entry['string_id']
                                )
                                break

                            except sqlite3.OperationalError as e1:
                                if idx < 4:
                                    time.sleep(idx * 0.5)
                                else:
                                    raise e1
                            except Exception as e2:
                                raise e2

                except Exception as e:
                    raise e
                finally:
                    try:
                        os.unlink(filename)
                    except:
                        pass

            self.count += 1

        except KeyboardInterrupt as e:
            worker.close()
        except Exception as e:
            Tools.print_error(e)

    def status(self, sync, bar):
        try:
            last_data = 0
            while sync.running:
                if self.count != last_data:
                    bar.show(self.count)
                    last_data = self.count
                time.sleep(0.3)
        except KeyboardInterrupt as e:
            raise e
        except:
            pass
        finally:
            Tools.clear_line()

    @staticmethod
    def calculate_binary_tree(database: SniperDB, linear: bool = False):

        Logger.pl('{+} {C}Calculating binary tree{W}')
        try:

            # Check if we need to recalculate
            sql = "select count(distinct s.parent_id) as tree, count(distinct s.string_id) as rows from [string] as s"
            row = database.select_raw(sql=sql, args=[])
            if (row[0]['tree'] <= 1 and linear) or (row[0]['tree'] > 1 and not linear):
                return

            database.execute(
                sql="UPDATE [string] set tree_idx = address, parent_id = ?",
                args=[-1 if not linear else 0])

            if not linear:
                sql = "select s.string_id, s.address from [string] as s order by s.address asc"
                db_data = database.select_raw(sql=sql, args=[])

                if len(db_data) > 0:
                    Cursor.hide()
                    with progress.Bar(label=f" Binary tree",
                                      expected_size=len(db_data) * 2,
                                      show_percent=True,
                                      auto_hide_cursor=True,
                                      no_tty_every_percent=10
                                      ) as bar:
                        try:
                            nodes = {}
                            indexes = {'inserted': 0}

                            def calc_tree(node: dict):
                                ac_left = [
                                    r for r in db_data
                                    if node['address'] > r['address'] >= node['min']
                                ]
                                ac_right = [
                                    r for r in db_data
                                    if node['address'] <= r['address'] <= node['max']
                                       and r['string_id'] != node['string_id']
                                ]

                                il = int(len(ac_left) / 2) - 1
                                if len(ac_left) > 2 and il > 0:
                                    key = str(ac_left[il]['string_id'])
                                    # ccalc += 1
                                    indexes['inserted'] += 1
                                    database.update('string',
                                                    filter_data=dict(string_id=key, parent_id=-1),
                                                    parent_id=node['string_id'], tree_idx=indexes['inserted'])
                                    if key not in nodes:
                                        nodes[key] = ac_left[il]
                                        nodes[key]['executed'] = False
                                        nodes[key]['min'] = node['min']
                                        nodes[key]['max'] = node['address']
                                else:
                                    for r in ac_left:
                                        indexes['inserted'] += 1
                                        database.update('string',
                                                        filter_data=dict(string_id=r['string_id'], parent_id=-1),
                                                        parent_id=node['string_id'], tree_idx=indexes['inserted'])

                                ir = int(len(ac_right) / 2) - 1
                                if len(ac_right) > 2 and ir < len(ac_right):
                                    key = str(ac_right[ir]['string_id'])
                                    # ccalc += 1
                                    indexes['inserted'] += 1
                                    database.update('string',
                                                    filter_data=dict(string_id=key, parent_id=-1),
                                                    parent_id=node['string_id'], tree_idx=indexes['inserted'])

                                    if key not in nodes:
                                        nodes[key] = ac_right[ir]
                                        nodes[key]['executed'] = False
                                        nodes[key]['min'] = node['address']
                                        nodes[key]['max'] = node['max']
                                else:
                                    for r in ac_right:
                                        indexes['inserted'] += 1
                                        database.update('string',
                                                        filter_data=dict(string_id=r['string_id'], parent_id=-1),
                                                        parent_id=node['string_id'], tree_idx=indexes['inserted'])

                                nodes[str(node['string_id'])]['executed'] = True

                            i1 = int(len(db_data) / 2) - 1
                            indexes['inserted'] += 1
                            database.update('string',
                                            filter_data=dict(string_id=db_data[i1]['string_id']),
                                            parent_id=0, tree_idx=0)

                            nodes[str(db_data[i1]['string_id'])] = db_data[i1]
                            nodes[str(db_data[i1]['string_id'])]['executed'] = False
                            nodes[str(db_data[i1]['string_id'])]['min'] = min(r['address'] for r in db_data)
                            nodes[str(db_data[i1]['string_id'])]['max'] = max(r['address'] for r in db_data)

                            while reduce(lambda a, i: a + 1 if (not nodes[i]['executed']) else a, nodes, 0) > 0:
                                for k in [
                                    k for k in nodes.keys()
                                    if not nodes[k]['executed']
                                ]:
                                    calc_tree(nodes[k])
                                    bar.show(indexes['inserted'])

                        except KeyboardInterrupt as e:
                            raise e
                        finally:
                            bar.hide = True

        except KeyboardInterrupt as e:
            raise e
        finally:
            Cursor.show()
