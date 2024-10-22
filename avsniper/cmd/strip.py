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

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.worker import Worker
from clint.textui import progress
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


class StripFile(CmdBase):
    db = None
    order = 20
    file_name = None
    check_database = True
    incremental = True
    unique = True
    sliced = True
    test_crashed = True
    count = 0
    linear = False
    strategy = Configuration.StrategyEnum.Unknown

    def __init__(self):
        super().__init__('strip', 'Strip EXE file')

    def add_flags(self, flags: _ArgumentGroup):

        flags.add_argument('--strategy',
                           action='store',
                           metavar='[strategy]',
                           type=str,
                           default='direct',
                           dest=f'strategy',
                           help=Color.s('Strip and check strategy (default: {G}Direct{W}).'))

        flags.add_argument('--linear',
                           action='store_true',
                           default=False,
                           dest=f'linear',
                           help=Color.s('Use linear address order, disabling {G}binary tree{W} (default: {G}False{W})'))

        flags.add_argument('--disable-crashed-test',
                           action='store_true',
                           default=False,
                           dest=f'disable_crash_test',
                           help=Color.s('Disable test if EXE is crashed'))

        flags.add_argument('--disable-incremental',
                           action='store_true',
                           default=False,
                           dest=f'disable_incremental',
                           help=Color.s('Disable generation of incremental EXE files'))

        flags.add_argument('--disable-unique',
                           action='store_true',
                           default=False,
                           dest=f'disable_unique',
                           help=Color.s('Disable generation of unique EXE files'))

        flags.add_argument('--disable-sliced',
                           action='store_true',
                           default=False,
                           dest=f'disable_sliced',
                           help=Color.s('Disable generation of sliced EXE files'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        sf = [
            s for s in Configuration.StrategyEnum
            if s.name.lower().find(args.strategy.lower().strip()) == 0
        ]

        if len(sf) > 1:
            Logger.pl('{!} {R}error: strategy is ambiguous {O}%s{R} {W}\r\n' % (
                args.strategy))
            exit(1)

        self.strategy = next(iter(sf), Configuration.StrategyEnum.Unknown)

        if self.strategy == Configuration.StrategyEnum.Unknown:
            Logger.pl('{!} {R}error: strategy is invalid {O}%s{R} {W}\r\n' % (
                args.strategy))
            exit(1)

        Logger.pl('     {C}strategy:{O} %s{W}' % self.strategy.name)

        self.test_crashed = not args.disable_crash_test and os.name == 'nt'

        Logger.pl('     {C}crashed test:{O} %s{W}' % ('Enabled' if self.test_crashed else 'Disabled'))

        self.incremental = not args.disable_incremental
        self.unique = not args.disable_unique
        self.sliced = not args.disable_sliced
        self.linear = args.linear

        Logger.pl('     {C}incremental:{O} %s{W}' % ('Enabled' if self.incremental else 'Disabled'))
        Logger.pl('     {C}unique:{O} %s{W}' % ('Enabled' if self.unique else 'Disabled'))
        Logger.pl('     {C}sliced:{O} %s{W}' % ('Enabled' if self.sliced else 'Disabled'))

        self.db = self.open_db(args)

        return True

    def run(self):

        shutil.rmtree(Configuration.path, ignore_errors=True)
        if not os.path.isdir(Configuration.path):
            os.mkdir(Configuration.path)

        # Put on blacklist non finished checking
        self.db.execute(sql=(
            "INSERT or IGNORE into black_list (src_file_id, sha256_hash, encoded_string, encoding) "
            "select s.src_file_id, s.sha256_hash, s.encoded_string, s.encoding  from test_file tf "
            "inner join string s on s.string_id = tf.string_id "
            "where flagged = 'C'"), args=[])

        self.db.execute(sql="delete FROM test_file", args=[])

        sql = "select sf.src_file_id, sf.sha256_hash, sf.md5_hash, sf.data as src_file_data from [src_file] sf"
        db_src_data = self.db.select_raw(sql=sql, args=[])

        for f_row in db_src_data:
            f_data = StringPart.b64decode(f_row['src_file_data'])
            file_id = f_row['src_file_id']

            rnd = StringPart.random_string(8, 'S').decode("UTF-8")
            filename = os.path.join(Configuration.path, f'0000_original_{file_id}_{rnd}.exe')
            with(open(filename, 'wb')) as f:
                f.write(f_data)

            md5_hash = hashlib.md5(f_data).hexdigest().lower()
            if md5_hash != f_row['md5_hash']:
                raise Exception((f"Integrity check error at file ID: {f_row['src_file_id']}. "
                                 f"MD5 Hash {md5_hash}, expected {f_row['md5_hash']} bytes, "
                                 f"data length {len(f_data)}"))

            sql = ("select s.string_id, s.address, s.bytes_size, s.encoding, s.encoded_string, "
                   "ifnull(bl.bl_id, -1) as bl_id "
                   "from [string] as s "
                   "left join [black_list] as bl "
                   "on bl.src_file_id == s.src_file_id and bl.sha256_hash == s.sha256_hash "
                   "and bl.encoding == s.encoding "
                   "where s.src_file_id = ? ") \
                   + ("order by s.tree_idx asc" if not self.linear else "order by s.address asc")
            args = [file_id]
            db_data = self.db.select_raw(sql=sql, args=args)

            if not self.incremental and not self.unique and not self.sliced:
                Logger.pl('{!} {R}Zero files generated{W}')
                return

            Logger.pl('{+} {C}Generating PE files{W}')

            _, _, free = shutil.disk_usage(Configuration.path)
            s_size = len(db_data) * len(f_data)
            factor = (1 if self.incremental else 0) + (1 if self.unique else 0) + (1 if self.sliced else 0)
            estimated_size = s_size * factor
            while estimated_size >= free and factor > 1:
                if self.unique:
                    self.unique = False
                    Logger.pl('{*} {GR}Disabling strategy {O}unique{GR} trying to fit free disk space{W}')
                elif self.sliced:
                    self.sliced = False
                    Logger.pl('{*} {GR}Disabling strategy {O}sliced{GR} trying to fit free disk space{W}')
                elif self.incremental:
                    self.incremental = False
                    Logger.pl('{*} {GR}Disabling strategy {O}incremental{GR} trying to fit free disk space{W}')

                factor = (1 if self.incremental else 0) + (1 if self.unique else 0) + (1 if self.sliced else 0)
                if factor == 0:
                    self.incremental = True
                    factor += 1

                estimated_size = s_size * factor

            Logger.pl('{+} {C}Estimated disk usage: {O}%s{W}' % Tools.sizeof_fmt(estimated_size))
            if estimated_size >= free:
                needs = estimated_size - free
                raise Exception((f"No space left on device: Free space {Tools.sizeof_fmt(free)}. "
                                 f"Needed at least more {Tools.sizeof_fmt(needs)}"))

            nocert_data = None
            nocert_pos = []
            try:
                nocert_data = Tools.pe_strip_certificate(f_data)
                if nocert_data is None:
                    raise Exception('Return is empty')

                nocert_pos = [cd for cd in Tools.pe_certificate_positions(f_data)]

                # As fully stripped file, always put it as direct strategy
                self.save_file(name='0000000_cert_stripped.exe', data=nocert_data, string_id=0, file_id=file_id,
                               type='SIG', strategy=Configuration.StrategyEnum.Direct.value,
                               strip_positions=nocert_pos)
                Logger.pl('{+} {C}Certificate stripped file saved as {O}0000000_cert_stripped.exe{W}')

            except Exception as e:
                nocert_data = None
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip certificates: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            res_ok = True
            try:
                ft = [
                    MicrosoftPe.DirectoryEntryType.icon,
                    MicrosoftPe.DirectoryEntryType.group_cursor4,
                    MicrosoftPe.DirectoryEntryType.version,
                    MicrosoftPe.DirectoryEntryType.manifest
                ]
                nores_data = Tools.pe_strip_resources(f_data, ft)
                if nores_data is None:
                    raise Exception('Return is empty')

                dt = [res_entry for res_entry in Tools.pe_resources_positions(f_data, ft)]

                # As fully stripped file, always put it as direct strategy
                self.save_file(name='0000000_res_stripped.exe', data=nores_data, string_id=0, file_id=file_id,
                               type='RES', strategy=Configuration.StrategyEnum.Direct.value,
                               strip_positions=dt)
                Logger.pl('{+} {C}Resources stripped file saved as {O}0000000_res_stripped.exe{W}')

                res_ok = True

            except Exception as e:
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip resources: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            if res_ok and nocert_data:
                try:
                    ft = [
                        MicrosoftPe.DirectoryEntryType.icon,
                        MicrosoftPe.DirectoryEntryType.group_cursor4,
                        MicrosoftPe.DirectoryEntryType.version,
                        MicrosoftPe.DirectoryEntryType.manifest
                    ]
                    nores_data = Tools.pe_strip_resources(nocert_data, ft)
                    if nores_data is None:
                        raise Exception('Return is empty')

                    dt = nocert_pos + [
                        res_entry for res_entry in Tools.pe_resources_positions(nocert_data, ft)]

                    # As fully stripped file, always put it as direct strategy
                    self.save_file(name='0000000_cert_res_stripped.exe', data=nores_data, string_id=0, file_id=file_id,
                                   type='CERT_RES', strategy=Configuration.StrategyEnum.Direct.value,
                                   strip_positions=dt)
                    Logger.pl(('{+} {C}Resources and Certificate stripped file saved as '
                               '{O}0000000_cert_res_stripped.exe{W}'))

                except Exception as e:
                    if Configuration.verbose >= 1:
                        Logger.pl('{*} {GR}Cannot strip resources and certificate: {O}%s{W}' % str(e))
                    if Configuration.verbose >= 3:
                        Tools.print_error(e)

            if nocert_data is not None:
                # Use binary without digital certificates
                if Configuration.verbose >= 2:
                    Logger.pl('{*} {GR}Replacing original data with certificate stripped{W}')
                f_data = nocert_data

            try:
                nodebug_data = Tools.pe_strip_debug(f_data)
                if nodebug_data is None:
                    raise Exception('Return is empty')

                dt = nocert_pos + [
                    dbg_entry for dbg_entry in Tools.pe_debug_positions(f_data)]

                # As fully stripped file, always put it as direct strategy
                self.save_file(name='0000000_debug_stripped.exe', data=nodebug_data, string_id=0, file_id=file_id,
                               type='DEBUG', strategy=Configuration.StrategyEnum.Direct.value,
                               strip_positions=dt)
                Logger.pl('{+} {C}Debug stripped file saved as {O}0000000_debug_stripped.exe{W}')

                if Configuration.verbose >= 2:
                    Logger.pl('{*} {GR}Replacing original data with debug stripped{W}')

                f_data = nodebug_data

            except Exception as e:
                if Configuration.verbose >= 1:
                    Logger.pl('{*} {GR}Cannot strip debug: {O}%s{W}' % str(e))
                if Configuration.verbose >= 3:
                    Tools.print_error(e)

            Logger.pl('{+} {C}Generating stripped files{W}')
            st_data = f_data.copy()

            if res_ok:
                try:
                    ft = [
                        MicrosoftPe.DirectoryEntryType.icon,
                        MicrosoftPe.DirectoryEntryType.group_cursor4,
                        MicrosoftPe.DirectoryEntryType.version,
                        MicrosoftPe.DirectoryEntryType.manifest
                    ]
                    nores_data = Tools.pe_strip_resources(st_data, ft)
                    if nores_data is None:
                        raise Exception('Return is empty')

                    st_data = nores_data

                except Exception:
                    pass

            for row in db_data:
                addr = row['address']
                bytes_size = row['bytes_size']

                # Decode and check integrity, but now not use this
                dec = StringPart.b64decode(row['encoded_string'])
                if len(dec) != int(row['bytes_size']):
                    raise Exception((f"Integrity check error at string ID: {row['string_id']}. "
                                     f"Decoded {len(dec)}, expected {row['bytes_size']} bytes"))

                # Fill with ransom string with same size
                rnd = StringPart.random_string(raw_size=bytes_size, encoding=row['encoding'])
                #print(len(f_data), addr, bytes_size, len(rnd))
                for i in range(0, bytes_size):
                    st_data[addr + i] = rnd[i]

            # As fully stripped file, always put it as direct strategy
            self.save_file(name='0000000_stripped.exe', data=st_data, string_id=0, file_id=file_id,
                           type='Z', strategy=Configuration.StrategyEnum.Direct.value)
            Logger.pl('{+} {C}Fully stripped file saved as {O}0000000_stripped.exe{W}')

            if self.strategy == Configuration.StrategyEnum.Reversed:
                base_data = f_data.copy()
            else:
                base_data = st_data.copy()

            inc_data = base_data.copy()
            count = 0
            slice_strings = []
            with progress.Bar(label=" Saving files ",
                              expected_size=len(db_data),
                              show_percent=True,
                              no_tty_every_percent=10,
                              auto_hide_cursor=True) as bar:
                try:
                    Cursor.hide()
                    for rl, row in enumerate(db_data):

                        tmp_data = base_data.copy()
                        slice_data = base_data.copy()

                        addr = row['address']
                        bytes_size = row['bytes_size']
                        if self.strategy == Configuration.StrategyEnum.Reversed:
                            dec = StringPart.random_string(raw_size=bytes_size, encoding=row['encoding'])
                        else:
                            dec = StringPart.b64decode(row['encoded_string'])

                        if int(row['bl_id']) == -1:
                            for i in range(0, bytes_size):
                                tmp_data[addr + i] = dec[i]
                                inc_data[addr + i] = dec[i]
                                slice_data[addr + i] = dec[i]

                        else:
                            Tools.clear_line()
                            Logger.pl('{*} {GR}Ignoring black listed string id {O}%s{GR}\n{GR}     %s\n{W}' % (
                                row["string_id"],
                                hexdump.hexdump(
                                    StringPart.b64decode(row['encoded_string']),
                                    result='return'
                                ).replace('\n', '\n     ')))

                        for s_row in slice_strings:
                            addr2 = s_row['address']
                            bytes_size2 = s_row['bytes_size']
                            if self.strategy == Configuration.StrategyEnum.Reversed:
                                dec2 = StringPart.random_string(raw_size=bytes_size2, encoding=s_row['encoding'])
                            else:
                                dec2 = StringPart.b64decode(s_row['encoded_string'])

                            for i in range(0, bytes_size2):
                                slice_data[addr2 + i] = dec2[i]

                        rnd = StringPart.random_string(4, 'S').decode("UTF-8")
                        if self.unique:
                            self.save_file(name=f'{row["string_id"]:07d}_unique_{rnd}.exe', data=tmp_data,
                                           string_id=row['string_id'], file_id=file_id, type='U',
                                           strategy=self.strategy.value)
                        if self.incremental:
                            self.save_file(name=f'{row["string_id"]:07d}_incremental_{rnd}.exe', data=inc_data,
                                           string_id=row['string_id'], file_id=file_id, type='I',
                                           strategy=self.strategy.value)
                        if self.sliced:
                            self.save_file(name=f'{row["string_id"]:07d}_slice_{rnd}.exe', data=tmp_data,
                                           string_id=row['string_id'], file_id=file_id, type='S',
                                           strategy=self.strategy.value)

                        slice_strings.append(row)

                        if rl > 30:
                            slice_strings.pop(0)

                        count += 1

                        bar.show(count)

                except KeyboardInterrupt as e:
                    raise e
                finally:
                    bar.hide = True
                    bar.no_tty_every_percent = None
                    Tools.clear_line()
                    Cursor.show()

        # Check for crashed files
        if self.test_crashed:
            Logger.pl('{+} {C}Checking if EXE files are runnable or crashed{W}')
            sql = ("select t.* from [test_file] as t "
                   "where crashed = 'F' "
                   "order by t.string_id asc, t.test_id asc")
            args = []
            db_data = self.db.select_raw(sql=sql, args=args)

            self.count = 0
            with Worker(callback=self.file_callback, per_thread_callback=self.thread_start_callback,
                        threads=10) as t:
                t.start()

                with progress.Bar(label=" Checking files ",
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
                        Logger.pl('{+} {C}file list finished, waiting processors...{W}')

                        t.wait_finish()

                    except KeyboardInterrupt as e:
                        bar.hide = True
                        time.sleep(0.4)
                        bar.clear_line()
                        raise e
                    finally:
                        t.close()
                        t1.join()
                        bar.hide = True
                        bar.no_tty_every_percent = None
                        Tools.clear_line()
                        Cursor.show()

        sql = ("select t.type, count(t.string_id) as qty, sum(IIF(t.crashed == 'T', 1, 0)) as crashed "
               "from test_file t group by t.type order by qty desc")
        s_type = {
            'SIG': 'Signature stripped',
            'RES': 'Resources stripped',
            'DEBUG': 'Debug stripped',
            'CERT_RES': 'Signature + Resources stripped',
            'Z': 'All stripped',
            'I': 'Incremental',
            'S': 'Sliced',
            'U': 'Unique'
        }
        db_data = [
            {k: v if k != 'type' or v not in s_type.keys() else s_type[v] for k, v in r.items()}
            for r in self.db.select_raw(sql=sql, args=[])
        ]

        if len(db_data) > 0:
            Logger.pl('{+} {C}Generated files:\n{GR}%s{W}\n' % Tools.get_ansi_tabulated(db_data, "     "))
        else:
            Logger.pl('{!} {R}Zero files generated{W}')
            return

    def save_file(self, name: str, data: bytearray, **kwargs):
        filename = os.path.join(Configuration.path, name)
        with(open(filename, 'wb')) as f:
            f.write(data)
        md5_hash = hashlib.md5(data).hexdigest().lower()
        self.db.insert_test_file(file_name=name, md5_hash=md5_hash, crashed=False, **kwargs)

    def thread_start_callback(self, index, **kwargs):
        return self.db.clone()

    def file_callback(self, worker, entry, thread_callback_data, thread_count, **kwargs):

        t_db = thread_callback_data

        try:

            if self.test_crashed:
                filename = os.path.join(Configuration.path, entry["file_name"])
                if not ExeRunner.execute(filename):  # is crashed
                    for idx in range(5):
                        try:
                            t_db.update(
                                table_name='test_file',
                                filter_data=dict(test_id=entry['test_id']),
                                crashed='T'
                            )
                            break

                        except sqlite3.OperationalError as e1:
                            if idx < 4:
                                time.sleep(idx * 0.5)
                            else:
                                raise e1
                        except Exception as e2:
                            raise e2

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
