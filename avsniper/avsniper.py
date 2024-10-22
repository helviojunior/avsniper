#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import datetime
import json
import re

import codecs
import sqlite3
import sys, os
from .util.color import Color

from .util.logger import Logger
from .util.sniperdb import SniperDB

try:
    from .config import Configuration
except (ValueError, ImportError) as e:
    raise Exception('You may need to run avsniper from the root directory (which includes README.md)', e)


class AVSniper(object):
    db = None

    def __init__(self):
        pass

    def main(self):
        ''' Either performs action based on arguments, or starts attack scanning '''
        Configuration.initialize()

        self.run()

    def run(self):

        try:

            timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            Logger.pl('{+} {C}Start time {O}%s{W}' % timestamp)

            # Execute the specific actions
            Configuration.module.run()

        except Exception as e:
            Color.pl("\n{!} {R}Error: {O}%s" % str(e))
            if Configuration.verbose > 0 or True:
                Color.pl('\n{!} {O}Full stack trace below')
                from traceback import format_exc
                Color.p('\n{!}    ')
                err = format_exc().strip()
                err = err.replace('\n', '\n{W}{!} {W}   ')
                err = err.replace('  File', '{W}{D}File')
                err = err.replace('  Exception: ', '{R}Exception: {O}')
                Color.pl(err)
        except KeyboardInterrupt as e:
            raise e

        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        Logger.pl('{+} {C}End time {O}%s{W}' % timestamp)
        print(' ')

    def print_banner(self):
        """ Displays ASCII art of the highest caliber.  """
        Color.pl(Configuration.get_banner())


def run():
    from .util.tools import Tools

    # Explicitly changing the stdout encoding format
    if sys.stdout.encoding is None:
        # Output is redirected to a file
        sys.stdout = codecs.getwriter('latin-1')(sys.stdout)

    o = AVSniper()
    o.print_banner()

    try:
        o.main()

    except Exception as e:
        Configuration.exit_code = 1
        Color.pl('\n{!} {R}Error:{O} %s{W}' % str(e))

        if Configuration.verbose > 0 or True:
            Color.pl('\n{!} {O}Full stack trace below')
            from traceback import format_exc
            Color.p('\n{!}    ')
            err = format_exc().strip()
            err = err.replace('\n', '\n{W}{!} {W}   ')
            err = err.replace('  File', '{W}{D}File')
            err = err.replace('  Exception: ', '{R}Exception: {O}')
            Color.pl(err)

        Color.pl('\n{!} {R}Exiting{W}\n')

    except KeyboardInterrupt:
        Configuration.exit_code = 1
        Color.pl('\n{!} {O}interrupted, shutting down...{W}')
        Tools.kill_all_running()

    sys.exit(Configuration.exit_code)
