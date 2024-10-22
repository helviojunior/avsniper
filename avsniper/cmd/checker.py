import json
import os
import sqlite3
import threading
import time
import hexdump
from argparse import _ArgumentGroup, Namespace
from typing import Union
from clint.textui import progress

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.cursor import Cursor
from avsniper.util.worker import Worker
from avsniper.cmdbase import CmdBase
from avsniper.config import Configuration
from avsniper.util.color import Color
from avsniper.util.logger import Logger
from avsniper.util.sniperdb import SniperDB
from avsniper.util.strings import StringPart
from avsniper.util.tools import Tools


class Checker(CmdBase):
    help_show = False
    db = None
    force = False
    file_name = None
    check_database = True
    no_db = False
    execute_exe = False
    strict = False
    continue_on_flag = False
    skip_check = False
    just_check = False
    quiet = False
    count = 0
    flagged_count = 0
    tasks = 1
    sleep = 20
    insert_black_list = True

    def __init__(self, name='None', description='', help_show=True):
        super().__init__(name, description, help_show)

    def add_flags(self, flags: _ArgumentGroup):

        flags.add_argument('--execute',
                           action='store_true',
                           default=False,
                           dest=f'execute',
                           help=Color.s('Execute each EXE in SUSPENDED mode'))

        flags.add_argument('--strict',
                           action='store_true',
                           default=False,
                           dest=f'strict',
                           help=Color.s('Test only non crashed files and execute each EXE in SUSPENDED mode'))

        flags.add_argument('-sleep',
                           action='store',
                           dest='sleep',
                           default=1,
                           metavar='[seconds]',
                           type=int,
                           help=Color.s('number of seconds to wait after execution (default: {G}1{W})'))

        flags.add_argument('-T',
                           action='store',
                           dest='tasks',
                           default=1,
                           metavar='[tasks]',
                           type=int,
                           help=Color.s('number of threads in parallel (default: {G}1{W})'))

        flags.add_argument('--continue',
                           action='store_true',
                           default=False,
                           dest=f'continue_on_flag',
                           help=Color.s('Continue checking after the identification (default: {G}False{W})'))

        flags.add_argument('--skip',
                           action='store_true',
                           default=False,
                           dest=f'skip_check',
                           help=Color.s('Skip initial check (default: {G}False{W})'))

        flags.add_argument('--initial-check',
                           action='store_true',
                           default=False,
                           dest=f'just_check',
                           help=Color.s('Do just initial check (default: {G}False{W})'))

    def add_commands(self, cmds: _ArgumentGroup):
        pass

    def load_from_arguments(self, args: Namespace) -> bool:

        self.execute_exe = (args.execute and os.name == 'nt') or args.strict
        self.strict = args.strict

        if not self.no_db:
            self.db = self.open_db(args)

        self.tasks = args.tasks
        if self.tasks < 1:
            self.tasks = 1

        self.sleep = args.sleep
        if self.sleep < 1:
            self.sleep = 1
        if self.sleep > 900:
            self.sleep = 900

        self.continue_on_flag = args.continue_on_flag
        self.skip_check = args.skip_check
        self.just_check = args.just_check

        if self.just_check and self.skip_check:
            Color.pl('{!} {R}error: parameters {O}--skip{R} and {O}--initial-check{R} are mutual exclusive{W}\r\n')
            exit(1)

        if not self.quiet:
            Logger.pl('     {C}worker tasks:{O} %s{W}' % self.tasks)
            Logger.pl('     {C}continue after flag:{O} %s{W}' % self.continue_on_flag)
            Logger.pl('     {C}AV product:{O} %s{W}' % self.get_avname())

        return True

    def thread_start_callback(self, index, **kwargs):
        time.sleep(0.5 * float(index))
        return self.db.clone()

    def file_callback(self, worker, entry, thread_callback_data, thread_count, **kwargs):

        t_db = thread_callback_data

        try:

            flag = self.proc_check_file(t_db, entry, wait_time=self.sleep)
            if flag and not self.continue_on_flag:
                worker.close()

            self.count += 1
            if flag:
                self.flagged_count += 1

        except KeyboardInterrupt as e:
            worker.close()
        except Exception as e:
            Tools.print_error(e)

    def status(self, sync, bar):
        try:
            last_data = 0
            last_flag = 0
            while sync.running:
                if self.count != last_data:
                    bar.show(self.count)
                    last_data = self.count
                    if self.flagged_count != last_flag and "Checking files" in bar.label:
                        bar.label = Color.s((f" \033[0m\033[36mChecking files\033[0m\033[2m\033[90m, "
                                             f"flagged: \033[31m{self.flagged_count} "))
                        last_flag = self.flagged_count
                time.sleep(0.3)
        except KeyboardInterrupt as e:
            raise e
        except:
            pass
        finally:
            Tools.clear_line()

    def run(self):

        av = self.get_avname()
        if av == "Unknown":
            av = None

        updated = list()

        Logger.pl('{+} {C}Checking files{W}')
        s_type = {
            'Z': 'All stripped',
            'SIG': 'Signature stripped',
            'RES': 'Resource stripped',
            'DEBUG': 'Debug stripped',
            'CERT_RES': 'Signature + Resources stripped',
            'I': 'Incremental',
            'S': 'Sliced',
            'U': 'Unique'
        }
        if not self.skip_check:
            sql = "select t.* from [test_file] as t where t.type = 'Z'"
            args = []
            db_data = self.db.select_raw(sql=sql, args=args)

            for row in db_data:
                if av is not None and row["src_file_id"] not in updated:
                    self.db.update('src_file', filter_data=dict(src_file_id=row["src_file_id"]), last_av=av)
                    updated.append(row["src_file_id"])

                if Configuration.verbose >= 2:
                    Logger.pl('{*} {C}Checking fully stripped file "{O}%s{C}"{W}' % row['file_name'])

                if self.proc_check_file(self.db, row, wait_time=self.sleep, force_execution=True):
                    Logger.pl('{!} {R}Fail: {O}The fully stripped file have been flagged as malicious, '
                              'so we cannot continue!{W}')
                    Configuration.exit_code = 99999
                    return

            sql = ("select 0 as test_id, 0 as string_id, f.src_file_id, "
                   "'Z' as [type], f.name as file_name, f.md5_hash, 'F' as crashed, "
                   "1 as strategy, 'F' as flagged, 'F' as finished, f.data "
                   "from [src_file] as f ")
            args = []
            db_data = self.db.select_raw(sql=sql, args=args)

            for row in db_data:
                Logger.pl('{*} {C}Checking original file "{O}%s{C}", this process will take up to 1 minute.{W}' %
                          row['file_name'])

                if not self.proc_check_file(self.db, row, wait_time=40, force_execution=True):
                    Logger.pl('{!} {R}Fail: {O}The original file have not been flagged as malicious, '
                              'so we cannot continue!{W}')
                    Configuration.exit_code = 99999
                    return

        # Checking special files stripped
        sql = ("select t.*, sf.data as src_file_data "
               "from [test_file] as t "
               "inner join [src_file] as sf "
               "    on sf.src_file_id == t.src_file_id "
               "where t.type not in ('I', 'U', 'S', 'Z') and t.finished == 'F' "
               "order by t.test_id")
        args = []
        db_data = self.db.select_raw(sql=sql, args=args)

        args = []
        sql_filters = []
        for row in db_data:
            row_type = s_type[row['type']]
            if Configuration.verbose >= 2:
                Logger.pl('{*} {C}Checking %s file "{O}%s{C}"{W}' % (row_type, row['file_name']))

            if av is not None and row["src_file_id"] not in updated:
                self.db.update('src_file', filter_data=dict(src_file_id=row["src_file_id"]), last_av=av)
                updated.append(row["src_file_id"])

            if not self.proc_check_file(self.db, row, wait_time=self.sleep, force_execution=True):
                Logger.pl('{!} {R}WARNING! {O}The file {G}%s{O} have not been flagged as malicious, '
                          'so the problem is related to {G}%s{O}!{W}' % (row['file_name'], row_type))
                Logger.pl('{*} {GR}Filtering only related address...{W}')

                additional_data = Tools.try_or(json.loads, dict(strip_positions=[]), s=row['additional_data'])

                for pos in additional_data.get('strip_positions', []):
                    sql_filters.append(f" (s.address >= {pos['start_addr']} and s.address <= {pos['end_addr']}) ")

                if len(sql_filters) == 0:
                    Logger.pl('{!} {R}Fail: {O}None strings found to strip, '
                              'so we cannot continue!{W}')
                    Configuration.exit_code = 99999
                    return

                sql = ("update [test_file] "
                       "set finished = 'C' "
                       "where finished == 'F' "
                       "  and string_id in ( "  # If is NOT in
                       "    select string_id from [string] as s"
                       f"   where s.src_file_id = {row['src_file_id']} and (")
                sql += ' or '.join(sql_filters)
                sql += f")) and src_file_id = {row['src_file_id']} "
                self.db.execute(sql=sql, args=args)

        if self.just_check:
            Configuration.exit_code = 0
            return

        sql = ("update [test_file] "
               "set finished = 'T' "
               "where finished != 'C' "
               "and (select count(*) as q from [test_file] where finished == 'C') > 0")
        self.db.execute(sql=sql, args=[])

        sql = ("update [test_file] "
               "set finished = 'F' "
               "where finished == 'C'")
        self.db.execute(sql=sql, args=[])

        if Configuration.verbose >= 2:
            Logger.pl('{*} {C}Checking strings related files...{W}')

        sql_strings = "select t.*, s.address, s.sha256_hash, s.encoded_string, s.encoding from [test_file] as t " \
                      + "inner join [string] as s on t.string_id == s.string_id " \
                      + "where t.finished == ? and t.type in ('I', 'U', 'S') " \
                      + ("and t.crashed == 'F' " if self.strict else "") \
                      + "order by s.tree_idx asc"
        db_data = self.db.select_raw(sql=sql_strings, args=['F'])
        s_wait = int(len(db_data) * 0.1)
        if s_wait < self.tasks:
            s_wait = self.tasks

        if len(db_data) == 0:
            Logger.pl('{!} {R}Fail: {O}Test file list is empty!{W}')
            if Configuration.verbose >= 6:
                Logger.pl('{GR}%s{W}' % sql)

        e_tasks = self.tasks
        if len(db_data) < 30:
            e_tasks = 1
        elif len(db_data) < 60:
            e_tasks = 2

        self.insert_black_list = True
        with Worker(callback=self.file_callback, per_thread_callback=self.thread_start_callback,
                    threads=e_tasks) as t:
            t.start()

            with progress.Bar(label=" \033[0m\033[36mChecking files ",
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
                    for rl, row in enumerate(db_data):
                        if not t.running:
                            break

                        t.add_item(row)

                        while t.count > s_wait and t.running:
                            time.sleep(0.3)

                    t.wait_finish()

                except KeyboardInterrupt as e:
                    bar.hide = True
                    time.sleep(0.4)
                    bar.clear_line()

                    raise e
                finally:
                    t.close()
                    t1.join()
                    # Define all interrupted files as flagged
                    self.db.execute(sql="update test_file set flagged = 'T' WHERE flagged = 'C'", args=[])
                    bar.hide = True
                    bar.no_tty_every_percent = None
                    Tools.clear_line()
                    Cursor.show()

        sql = ("select "
               "    sum(case "
               "        when tf.flagged == 'T' and tf.strategy == 1 then 1 "
               "        when tf.flagged == 'F' and tf.strategy == 2 then 1 "
               "        else 0 end) as flagged, "
               "    sum(case "
               "        when tf.flagged == 'F' and tf.strategy == 1 then 1 "
               "        when tf.flagged == 'T' and tf.strategy == 2 then 1 "
               "        else 0 end) as clean, "
               "    tf.type "
               "from test_file tf "
               "where tf.finished == 'T' "
               "group by tf.type order by 1 desc")  # and tf.type not in ('Z', 'SIG')

        fl_count = sum([
            int(r['flagged'])
            for r in self.db.select_raw(sql=sql, args=[])
            if r['type'] in ('I', 'U', 'S')
        ])
        db_data = [
            {k: v if k != 'type' or v not in s_type.keys() else s_type[v] for k, v in r.items()}
            for r in self.db.select_raw(sql=sql, args=[])
        ]

        if len(db_data) > 0:
            Logger.pl('{+} {C}Flagged files:\n{GR}%s{W}\n' % Tools.get_ansi_tabulated(db_data, "     "))
        else:
            Logger.pl('{+} {O}Zero flagged file found! {C}\\{G}o{C}/{W}')

        #Configuration.exit_code = self.flagged_count

        '''
        if fl_count == 0 and self.db.select_raw(sql="select count(*) as count from black_list", args=[])[0]['count'] == 0:
            Logger.pl('{!} {R}WARNING: {O}Zero files flagged and Black List is empty!{W}')
            Logger.pl('{*} {GR}Selecting the first string as black list{W}')
            db_data = self.db.select_raw(sql=sql_strings, args=['T'])
            self.db.insert_black_list(
                file_id=db_data[0]['src_file_id'],
                sha256_hash=db_data[0]['sha256_hash'],
                encoding=db_data[0]['encoding'],
                encoded_string=db_data[0]['encoded_string']
            )
            fl_count += 1
        '''

        Configuration.exit_code = fl_count

    def proc_check_file(self, db: SniperDB, entry: dict,
                        wait_time: float = 20, force_execution: bool = False) -> bool:
        step1 = False
        step2 = False
        ret_value = False
        flag = 'F'

        for idx in range(5):
            try:

                if not step1:
                    file_name = entry['file_name']
                    md5_hash = entry['md5_hash']
                    crashed = entry['crashed'] == 'T'

                    r_check = not self.check_file(test_id=entry['test_id'], name=file_name,
                                                  hash=md5_hash, crashed=crashed,
                                                  data=entry['data'] if 'data' in entry else None,
                                                  wait_time=wait_time,
                                                  force_execution=force_execution)
                    if r_check:
                        flag = 'T'

                    if Configuration.StrategyEnum(entry["strategy"]) == Configuration.StrategyEnum.Reversed:
                        r_check = not r_check

                    ret_value = r_check

                    if r_check and Configuration.verbose >= 4:
                        Tools.clear_line()
                        Logger.pl('{*} {C}bad string id {O}%s{C} for test id {O}%s{C}\n{GR}     %s{W}\n' %
                                  (entry['string_id'],
                                   entry['test_id'],
                                   hexdump.hexdump(
                                       StringPart.b64decode(entry['encoded_string']),
                                       result='return'
                                   ).replace('\n', '\n     ') if 'encoded_string' in entry else ''))

                    if r_check and self.insert_black_list:
                        if 'encoded_string' in entry:
                            res = db.insert_black_list(
                                file_id=entry['src_file_id'],
                                sha256_hash=entry['sha256_hash'],
                                encoding=entry['encoding'],
                                encoded_string=entry['encoded_string']
                            )
                            self.insert_black_list = self.continue_on_flag or res.get('inserted', 0) == 0
                            ret_value = ret_value if res.get('inserted', 0) > 0 else False

                    step1 = True

                if not step2:
                    db.update(
                        table_name='test_file',
                        filter_data=dict(test_id=entry['test_id']),
                        flagged=flag,
                        finished='T'
                    )
                    step1 = True

                break

            except (sqlite3.OperationalError, ConnectionResetError) as e1:
                if idx < 4:
                    time.sleep(idx * 0.5)
                else:
                    raise e1
            except Exception as e2:
                raise e2

        return ret_value

    def check_file(self, test_id: int, name: str, hash: str,
                   crashed: bool = False, wait_time: float = 0.3,
                   data: Union[bytearray, bytes, str] = None,
                   force_execution: bool = False) -> bool:

        raise Exception("Not implemented yet!")

    def get_avname(self) -> str:
        return 'Unknown'

    def get_osinfo(self) -> str:
        return 'Unknown'
