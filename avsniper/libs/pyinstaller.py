"""
PyInstaller Extractor v2.0 (Supports pyinstaller 6.6.0, 6.5.0, 6.4.0, 6.3.0, 6.2.0, 6.1.0, 6.0.0, 5.13.2, 5.13.1, 5.13.0, 5.12.0, 5.11.0, 5.10.1, 5.10.0, 5.9.0, 5.8.0, 5.7.0, 5.6.2, 5.6.1, 5.6, 5.5, 5.4.1, 5.4, 5.3, 5.2, 5.1, 5.0.1, 5.0, 4.10, 4.9, 4.8, 4.7, 4.6, 4.5.1, 4.5, 4.4, 4.3, 4.2, 4.1, 4.0, 3.6, 3.5, 3.4, 3.3, 3.2, 3.1, 3.0, 2.1, 2.0)
Author : Extreme Coders
E-mail : extremecoders(at)hotmail(dot)com
Web    : https://0xec.blogspot.com
Date   : 26-March-2020
Url    : https://github.com/extremecoders-re/pyinstxtractor

Adjusted to match this project
"""

from __future__ import print_function

import errno
import os
import struct
import marshal
import zlib
import sys
from io import BytesIO
from typing import Union
from uuid import uuid4 as uniquename

from avsniper.formats.microsoft_pe import MicrosoftPe
from avsniper.util.microsoft_pe_holder import MicrosoftPeHolder


class CTOCEntry:
    def __init__(self, header_position, header_size, position, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name):
        self.header_position = header_position
        self.header_size = header_size
        self.position = position
        self.cmprsdDataSize = cmprsdDataSize
        self.uncmprsdDataSize = uncmprsdDataSize
        self.cmprsFlag = cmprsFlag
        self.typeCmprsData = typeCmprsData
        self.name = name


class PyInstArchive:
    PYINST20_COOKIE_SIZE = 24  # For pyinstaller 2.0
    PYINST21_COOKIE_SIZE = 24 + 64  # For pyinstaller 2.1+
    MAGIC = b'MEI\014\013\012\013\016'  # Magic number which identifies pyinstaller
    _io = None

    def __init__(self, data: Union[bytes, bytearray, str, MicrosoftPe]):
        self.pycMagic = b'\0' * 4
        self.barePycList = []  # List of pyc's whose headers have to be fixed
        if isinstance(data, str):
            try:
                with open(data, 'rb') as f:
                    data_bytes = bytearray(f.read())
                    pass
            except IOError as x:
                if x.errno == errno.EACCES:
                    raise Exception('could not open PE file permission denied')
                elif x.errno == errno.EISDIR:
                    raise Exception('could not open PE file it is an directory')
                else:
                    raise Exception('could not open PE file')
        else:
            data_bytes = data

        if not isinstance(data_bytes, MicrosoftPe):
            mz = b"MZ"
            if data[0x0:0x2] != mz:
                raise Exception('File is not a PE file')

            pe_file = MicrosoftPe.from_bytes(data_bytes)
        else:
            pe_file = data_bytes

        # Get PE raw bytes
        data_bytes = bytearray(MicrosoftPeHolder.from_pe(pe_file).to_bytes())

        self.tocList = []
        self._io = BytesIO(data_bytes)
        self.fileSize = len(data_bytes)
        self._check_file()
        self._parse_archive_info()
        self._parse_toc()

    @property
    def version(self) -> str:
        return f'{self.pymaj}.{self.pymin}'

    @property
    def overlay_size(self) -> int:
        return self.overlaySize

    def close(self):
        if self._io is not None:
            self._io.close()

    def _check_file(self):

        searchChunkSize = 8192
        endPos = self.fileSize
        self.cookiePos = -1

        if endPos < len(self.MAGIC):
            raise Exception('File is too short or truncated')

        while True:
            startPos = endPos - searchChunkSize if endPos >= searchChunkSize else 0
            chunkSize = endPos - startPos

            if chunkSize < len(self.MAGIC):
                break

            self._io.seek(startPos, os.SEEK_SET)
            data = self._io.read(chunkSize)

            offs = data.rfind(self.MAGIC)

            if offs != -1:
                self.cookiePos = startPos + offs
                break

            endPos = startPos + len(self.MAGIC) - 1

            if startPos == 0:
                break

        if self.cookiePos == -1:
            raise Exception('Missing cookie, unsupported pyinstaller version or not a pyinstaller archive')

        self._io.seek(self.cookiePos + self.PYINST20_COOKIE_SIZE, os.SEEK_SET)

        if b'python' in self._io.read(64).lower():
            #print('[+] Pyinstaller version: 2.1+')
            self.pyinstVer = 21  # pyinstaller 2.1+
        else:
            #print('[+] Pyinstaller version: 2.0')
            self.pyinstVer = 20  # pyinstaller 2.0

    def _parse_archive_info(self):
        magic = None
        lengthofPackage = 0
        toc = 0
        tocLen = 0
        pyver = 0

        try:
            if self.pyinstVer == 20:
                self._io.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver) = \
                    struct.unpack('!8siiii', self._io.read(self.PYINST20_COOKIE_SIZE))

            elif self.pyinstVer == 21:
                self._io.seek(self.cookiePos, os.SEEK_SET)

                # Read CArchive cookie
                (magic, lengthofPackage, toc, tocLen, pyver, pylibname) = \
                    struct.unpack('!8sIIii64s', self._io.read(self.PYINST21_COOKIE_SIZE))

        except:
            raise Exception('The file is not a pyinstaller archive')

        self.pymaj, self.pymin = (pyver // 100, pyver % 100) if pyver >= 100 else (pyver // 10, pyver % 10)
        #print('[+] Python version: {0}.{1}'.format(self.pymaj, self.pymin))

        # Additional data after the cookie
        tailBytes = self.fileSize - self.cookiePos - (
            self.PYINST20_COOKIE_SIZE if self.pyinstVer == 20 else self.PYINST21_COOKIE_SIZE)

        # Overlay is the data appended at the end of the PE
        self.overlaySize = lengthofPackage + tailBytes
        self.overlayPos = self.fileSize - self.overlaySize
        self.tableOfContentsPos = self.overlayPos + toc
        self.tableOfContentsSize = tocLen

        #print('[+] Length of package: {0} bytes'.format(lengthofPackage))
        #return True

    def _parse_toc(self):

        # Go to the table of contents
        self._io.seek(self.tableOfContentsPos, os.SEEK_SET)

        self.tocList = []
        parsedLen = 0

        # Parse table of contents
        while parsedLen < self.tableOfContentsSize:
            hp = self._io.tell()
            (entrySize,) = struct.unpack('!i', self._io.read(4))
            nameLen = struct.calcsize('!iIIIBc')

            (entryPos, cmprsdDataSize, uncmprsdDataSize, cmprsFlag, typeCmprsData, name) = \
                struct.unpack('!IIIBc{0}s'.format(entrySize - nameLen), self._io.read(entrySize - 4))

            try:
                name = name.decode("utf-8").rstrip("\0")
            except UnicodeDecodeError:
                newName = str(uniquename())
                #print('[!] Warning: File name {0} contains invalid bytes. Using random name {1}'.format(name, newName))
                name = newName

            # Prevent writing outside the extraction directory
            if name.startswith("/"):
                name = name.lstrip("/")

            if len(name) == 0:
                name = str(uniquename())
                #print('[!] Warning: Found an unamed file in CArchive. Using random name {0}'.format(name))

            self.tocList.append(
                CTOCEntry(
                    hp,
                    entrySize + 4,
                    self.overlayPos + entryPos,
                    cmprsdDataSize,
                    uncmprsdDataSize,
                    cmprsFlag,
                    typeCmprsData,
                    name
                ))

            parsedLen += entrySize

        if len(self.tocList) == 0:
            raise Exception('CArchive file list is empty!')

        #print('[+] Found {0} files in CArchive'.format(len(self.tocList)))

    def _writeRawData(self, filepath, data):
        nm = filepath.replace('\\', os.path.sep).replace('/', os.path.sep).replace('..', '__')
        nmDir = os.path.dirname(nm)
        if nmDir != '' and not os.path.exists(nmDir):  # Check if path exists, create if not
            os.makedirs(nmDir)

        with open(nm, 'wb') as f:
            f.write(data)

    def extractFiles(self):
        print('[+] Beginning extraction...please standby')
        extractionDir = os.path.join(os.getcwd(), os.path.basename(self.filePath) + '_extracted')

        if not os.path.exists(extractionDir):
            os.mkdir(extractionDir)

        os.chdir(extractionDir)

        for entry in self.tocList:
            self.fPtr.seek(entry.position, os.SEEK_SET)
            data = self.fPtr.read(entry.cmprsdDataSize)

            if entry.cmprsFlag == 1:
                try:
                    data = zlib.decompress(data)
                except zlib.error:
                    print('[!] Error : Failed to decompress {0}'.format(entry.name))
                    continue
                # Malware may tamper with the uncompressed size
                # Comment out the assertion in such a case
                assert len(data) == entry.uncmprsdDataSize  # Sanity Check

            if entry.typeCmprsData == b'd' or entry.typeCmprsData == b'o':
                # d -> ARCHIVE_ITEM_DEPENDENCY
                # o -> ARCHIVE_ITEM_RUNTIME_OPTION
                # These are runtime options, not files
                continue

            basePath = os.path.dirname(entry.name)
            if basePath != '':
                # Check if path exists, create if not
                if not os.path.exists(basePath):
                    os.makedirs(basePath)

            if entry.typeCmprsData == b's':
                # s -> ARCHIVE_ITEM_PYSOURCE
                # Entry point are expected to be python scripts
                print('[+] Possible entry point: {0}.pyc'.format(entry.name))

                if self.pycMagic == b'\0' * 4:
                    # if we don't have the pyc header yet, fix them in a later pass
                    self.barePycList.append(entry.name + '.pyc')
                self._writePyc(entry.name + '.pyc', data)

            elif entry.typeCmprsData == b'M' or entry.typeCmprsData == b'm':
                # M -> ARCHIVE_ITEM_PYPACKAGE
                # m -> ARCHIVE_ITEM_PYMODULE
                # packages and modules are pyc files with their header intact

                # From PyInstaller 5.3 and above pyc headers are no longer stored
                # https://github.com/pyinstaller/pyinstaller/commit/a97fdf
                if data[2:4] == b'\r\n':
                    # < pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        self.pycMagic = data[0:4]
                    self._writeRawData(entry.name + '.pyc', data)

                else:
                    # >= pyinstaller 5.3
                    if self.pycMagic == b'\0' * 4:
                        # if we don't have the pyc header yet, fix them in a later pass
                        self.barePycList.append(entry.name + '.pyc')

                    self._writePyc(entry.name + '.pyc', data)

            else:
                self._writeRawData(entry.name, data)

                if entry.typeCmprsData == b'z' or entry.typeCmprsData == b'Z':
                    self._extractPyz(entry.name)

        # Fix bare pyc's if any
        self._fixBarePycs()

    def _fixBarePycs(self):
        for pycFile in self.barePycList:
            with open(pycFile, 'r+b') as pycFile:
                # Overwrite the first four bytes
                pycFile.write(self.pycMagic)

    def _writePyc(self, filename, data):
        with open(filename, 'wb') as pycFile:
            pycFile.write(self.pycMagic)  # pyc magic

            if self.pymaj >= 3 and self.pymin >= 7:  # PEP 552 -- Deterministic pycs
                pycFile.write(b'\0' * 4)  # Bitfield
                pycFile.write(b'\0' * 8)  # (Timestamp + size) || hash

            else:
                pycFile.write(b'\0' * 4)  # Timestamp
                if self.pymaj >= 3 and self.pymin >= 3:
                    pycFile.write(b'\0' * 4)  # Size parameter added in Python 3.3

            pycFile.write(data)

    def _extractPyz(self, name):
        dirName = name + '_extracted'
        # Create a directory for the contents of the pyz
        if not os.path.exists(dirName):
            os.mkdir(dirName)

        with open(name, 'rb') as f:
            pyzMagic = f.read(4)
            assert pyzMagic == b'PYZ\0'  # Sanity Check

            pyzPycMagic = f.read(4)  # Python magic value

            if self.pycMagic == b'\0' * 4:
                self.pycMagic = pyzPycMagic

            elif self.pycMagic != pyzPycMagic:
                self.pycMagic = pyzPycMagic
                print('[!] Warning: pyc magic of files inside PYZ archive are different from those in CArchive')

            # Skip PYZ extraction if not running under the same python version
            if self.pymaj != sys.version_info.major or self.pymin != sys.version_info.minor:
                print(
                    '[!] Warning: This script is running in a different Python version than the one used to build the executable.')
                print(
                    '[!] Please run this script in Python {0}.{1} to prevent extraction errors during unmarshalling'.format(
                        self.pymaj, self.pymin))
                print('[!] Skipping pyz extraction')
                return

            (tocPosition,) = struct.unpack('!i', f.read(4))
            f.seek(tocPosition, os.SEEK_SET)

            try:
                toc = marshal.load(f)
            except:
                print('[!] Unmarshalling FAILED. Cannot extract {0}. Extracting remaining files.'.format(name))
                return

            print('[+] Found {0} files in PYZ archive'.format(len(toc)))

            # From pyinstaller 3.1+ toc is a list of tuples
            if type(toc) == list:
                toc = dict(toc)

            for key in toc.keys():
                (ispkg, pos, length) = toc[key]
                f.seek(pos, os.SEEK_SET)
                fileName = key

                try:
                    # for Python > 3.3 some keys are bytes object some are str object
                    fileName = fileName.decode('utf-8')
                except:
                    pass

                # Prevent writing outside dirName
                fileName = fileName.replace('..', '__').replace('.', os.path.sep)

                if ispkg == 1:
                    filePath = os.path.join(dirName, fileName, '__init__.pyc')

                else:
                    filePath = os.path.join(dirName, fileName + '.pyc')

                fileDir = os.path.dirname(filePath)
                if not os.path.exists(fileDir):
                    os.makedirs(fileDir)

                try:
                    data = f.read(length)
                    data = zlib.decompress(data)
                except:
                    print('[!] Error: Failed to decompress {0}, probably encrypted. Extracting as is.'.format(filePath))
                    open(filePath + '.encrypted', 'wb').write(data)
                else:
                    self._writePyc(filePath, data)
