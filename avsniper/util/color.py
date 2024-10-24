#!/usr/bin/python3
# -*- coding: UTF-8 -*-
import os
import sys
import colorama
from colorama import Fore, Back, Style
colorama.init(strip=False)

class Color(object):
    ''' Helper object for easily printing colored text to the terminal. '''

    # Basic console colors
    colors = {
        'W' : '\033[0m',  # white (normal)
        'R' : '\033[31m', # red
        'G' : '\033[32m', # green
        'O' : '\033[33m', # orange
        'B' : '\033[34m', # blue
        'P' : '\033[35m', # purple
        'C' : '\033[36m', # cyan
        'GR': '\033[90m', # gray
        'D' : '\033[2m'   # dims current color. {W} resets.
    }

    # Replace table to unix systems
    color_table = {
        '\033[30m': '\033[30m',  # Black
        '\033[31m': '\033[38;5;1m',  # Red
        '\033[32m': '\033[38;5;34m',  # Green
        '\033[33m': '\033[38;5;214m',  # Yellow
        '\033[34m': '\033[38;5;27m',  # Blue
        '\033[35m': '\033[38;5;5m',  # Magenta
        '\033[36m': '\033[38;5;75m',  # Cyan
        '\033[37m': '\033[38;5;253m',  # White
        '\033[90m': '\033[38;5;247m',  # Bright Black (Gray)
        '\033[91m': '\033[38;5;52m',  # Bright Red
        '\033[92m': '\033[38;5;40m',  # Bright Green
        '\033[93m': '\033[38;5;220m',  # Bright Yellow
        '\033[94m': '\033[38;5;27m',  # Bright Blue
        '\033[95m': '\033[38;5;170m',  # Bright Magenta
        '\033[96m': '\033[38;5;39m',  # Bright Cyan
        '\033[97m': '\033[38;5;255m',  # Bright White

    }

    # Helper string replacements
    replacements = {
        '{+}': ' {W}{D}[{W}{G}+{W}{D}]{W}',
        '{!}': ' {O}[{R}!{O}]{W}',
        '{?}': ' {W}{D}[{W}{C}?{W}{D}]{W}',
        '{*}': ' {W}[{B}*{W}]'
    }

    gray_scale = {
        i: f'\033[38;5;{i}m' for i in range(232, 256)
    }

    last_sameline_length = 0

    @staticmethod
    def p(text, out=sys.stdout):
        '''
        Prints text using colored format on same line.
        Example:
            Color.p("{R}This text is red. {W} This text is white")
        '''
        out.write(Color.s(text))
        out.flush()
        if '\r' in text:
            text = text[text.rfind('\r')+1:]
            Color.last_sameline_length = len(text)
        else:
            Color.last_sameline_length += len(text)

    @staticmethod
    def pl(text, out=sys.stdout):
        '''Prints text using colored format with trailing new line.'''
        Color.p('%s\n' % text, out)
        Color.last_sameline_length = 0

    @staticmethod
    def pe(text):
        '''Prints text using colored format with leading and trailing new line to STDERR.'''
        sys.stderr.write(Color.s('%s\n' % text))
        Color.last_sameline_length = 0

    @staticmethod
    def s(text):
        ''' Returns colored string '''
        output = text
        for key, value in Color.replacements.items():
            output = output.replace(key, value)
        for key, value in Color.colors.items():
            output = output.replace("{%s}" % key, value)
        if os.name != 'nt':
            for key, value in Color.color_table.items():
                output = output.replace(key, value)
        return output

    @staticmethod
    def sc(text):
        ''' Returns non colored string '''
        output = text
        for key, value in Color.replacements.items():
            output = output.replace(key, value)
        for key, value in Color.colors.items():
            output = output.replace("{%s}" % key, '')
        return output

    @staticmethod
    def clear_line():
        spaces = ' ' * Color.last_sameline_length
        sys.stdout.write('\r%s\r' % spaces)
        sys.stdout.flush()
        Color.last_sameline_length = 0

    @staticmethod
    def clear_entire_line():
        import os
        (rows, columns) = os.popen('stty size', 'r').read().split()
        Color.p("\r" + (" " * int(columns)) + "\r")

    @staticmethod
    def pattack(attack_type, target, attack_name, progress):
        '''
        Prints a one-liner for an attack.
        Includes attack type (WEP/WPA), target ESSID & power, attack type, and progress.
        ESSID (Pwr) Attack_Type: Progress
        e.g.: Router2G (23db) WEP replay attack: 102 IVs
        '''
        essid = "{C}%s{W}" % target.essid if target.essid_known else "{O}unknown{W}"
        Color.p("\r{+} {G}%s{W} ({C}%sdb{W}) {G}%s {C}%s{W}: %s " % (
            essid, target.power, attack_type, attack_name, progress))

if __name__ == '__main__':
    Color.pl("{R}Testing{G}One{C}Two{P}Three{W}Done")
    print(Color.s("{C}Testing{P}String{W}"))
    Color.pl("{+} Good line")
    Color.pl("{!} Danger")
