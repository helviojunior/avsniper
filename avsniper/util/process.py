# -*- coding: utf-8 -*-
import platform
import tempfile
import time
import signal
import os
from pathlib import Path

from subprocess import Popen, PIPE
from typing import List

from avsniper.config import Configuration
from avsniper.util.logger import Logger


class Process(object):
    ''' Represents a running/ran process '''

    @staticmethod
    def devnull():
        ''' Helper method for opening devnull '''
        return open('/dev/null', 'w')

    @staticmethod
    def call(command, cwd=None, shell=False, path_list: List[str] = None):
        '''
            Calls a command (either string or list of args).
            Returns tuple:
                (stdout, stderr)
        '''
        if type(command) is not str or ' ' in command or shell:
            shell = True
            if Configuration.verbose >= 3:
                Logger.debug("{GR}Executing (Shell): {G}%s" % command)
        else:
            shell = False
            if Configuration.verbose >= 3:
                Logger.debug("{GR}Executing (Shell): {G}%s" % command)

        # it cause hang on windows
        #pid = Popen(command, cwd=cwd, stdout=PIPE, stderr=PIPE, shell=shell)
        #retcode = pid.wait()
        #(stdout, stderr) = pid.communicate()

        my_env = os.environ.copy()
        my_env["PATH"] = Process.get_path(path_list)

        with tempfile.NamedTemporaryFile(mode="wb+") as tmp_out, tempfile.NamedTemporaryFile(mode="wb+") as tmp_err:

            pid = Popen(command, env=my_env, cwd=cwd, stdout=tmp_out, stderr=tmp_err, shell=shell)
            retcode = pid.wait()

            # Cursor is after the last write call, reset to read output
            tmp_out.seek(0)
            tmp_err.seek(0)
            stdout = tmp_out.read()
            stderr = tmp_err.read()

        if type(stdout) is bytes: stdout = stdout.decode('utf-8')
        if type(stderr) is bytes: stderr = stderr.decode('utf-8')

        if Configuration.verbose >= 5 and stdout is not None and stdout.strip() != '':
            Logger.pl("{P} [stdout] %s{W}" % '\n [stdout] '.join(stdout.strip().split('\n')))
        if Configuration.verbose >= 5 and stderr is not None and stderr.strip() != '':
            Logger.pl("{P} [stderr] %s{W}" % '\n [stderr] '.join(stderr.strip().split('\n')))

        return retcode, stdout, stderr

    @staticmethod
    def get_path(path_list: List[str] = None):
        p = platform.system().lower()
        s = ':'
        if p == 'darwin':
            p = 'macosx'
        if p == "windows":
            s = ';'

        bin_path = os.path.join(Path(os.path.dirname(__file__)).resolve().parent, 'libs', 'binutils', p)
        my_env = os.environ.copy()
        return my_env["PATH"] + s.join([f"{bin_path}"] + (path_list if path_list is not None else []))

    @staticmethod
    def exists(program):
        ''' Checks if program is installed on this system '''
        #p = Process(['which', program])
        #stdout = p.stdout().strip()
        #stderr = p.stderr().strip()

        #if stdout == '' and stderr == '':
        #    return False

        #return True

        from shutil import which
        return which(program, path=Process.get_path()) is not None


    def __init__(self, command, devnull=False, stdout=PIPE, stderr=PIPE, cwd=None, bufsize=0):
        ''' Starts executing command '''

        if type(command) is str:
            # Commands have to be a list
            command = command.split(' ')

        self.command = command

        if Configuration.verbose > 1:
            Logger.pl("\n {C}[?] {W} Executing: {B}%s{W}" % ' '.join(command))

        self.out = None
        self.err = None
        if devnull:
            sout = Process.devnull()
            serr = Process.devnull()
        else:
            sout = stdout
            serr = stderr

        self.start_time = time.time()

        self.pid = Popen(command, stdout=sout, stderr=serr, cwd=cwd, bufsize=bufsize)

    def __del__(self):
        '''
            Ran when object is GC'd.
            If process is still running at this point, it should die.
        '''
        if self.pid and self.pid.poll() is None:
            self.interrupt()

    def stdout(self):
        ''' Waits for process to finish, returns stdout output '''
        self.get_output()
        if Configuration.verbose > 1 and self.out is not None and self.out.strip() != '':
            Logger.pl("{P} [stdout] %s{W}" % '\n [stdout] '.join(self.out.strip().split('\n')))
        return self.out

    def stderr(self):
        ''' Waits for process to finish, returns stderr output '''
        self.get_output()
        if Configuration.verbose > 1 and self.err is not None and self.err.strip() != '':
            Logger.pl("{P} [stderr] %s{W}" % '\n [stderr] '.join(self.err.strip().split('\n')))
        return self.err

    def stdoutln(self):
        return self.pid.stdout.readline()

    def stderrln(self):
        return self.pid.stderr.readline()

    def get_output(self):
        ''' Waits for process to finish, sets stdout & stderr '''
        if self.pid.poll() is None:
            self.pid.wait()
        if self.out is None:
            (self.out, self.err) = self.pid.communicate()

        if type(self.out) is bytes:
            self.out = self.out.decode('utf-8')

        if type(self.err) is bytes:
            self.err = self.err.decode('utf-8')

        return (self.out, self.err)

    def poll(self):
        ''' Returns exit code if process is dead, otherwise "None" '''
        return self.pid.poll()

    def wait(self):
        self.pid.wait()

    def running_time(self):
        ''' Returns number of seconds since process was started '''
        return int(time.time() - self.start_time)

    def interrupt(self, wait_time=2.0):
        '''
            Send interrupt to current process.
            If process fails to exit within `wait_time` seconds, terminates it.
        '''
        try:
            pid = self.pid.pid
            cmd = self.command
            if type(cmd) is list:
                cmd = ' '.join(cmd)

            if Configuration.verbose > 1:
                Logger.pl('\n {C}[?] {W} sending interrupt to PID %d (%s)' % (pid, cmd))

            os.kill(pid, signal.SIGINT)

            start_time = time.time()  # Time since Interrupt was sent
            while self.pid.poll() is None:
                # Process is still running
                time.sleep(0.1)
                if time.time() - start_time > wait_time:
                    # We waited too long for process to die, terminate it.
                    if Configuration.verbose > 1:
                        Logger.pl('\n {C}[?] {W} Waited > %0.2f seconds for process to die, killing it' % wait_time)
                    os.kill(pid, signal.SIGTERM)
                    self.pid.terminate()
                    break

        except OSError as e:
            if 'No such process' in e.__str__():
                return
            raise e  # process cannot be killed

    @staticmethod
    def kill(code=0):
        ''' Deletes temp and exist with the given code '''
        os.kill(os.getpid(), signal.SIGTERM)
