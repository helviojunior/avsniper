from io import BytesIO
from typing import Union

from kaitaistruct import KaitaiStream

from avsniper.formats.microsoft_pe import MicrosoftPe


class MicrosoftPeHolder(MicrosoftPe):

    def to_bytes(self) -> bytes:
        _pos = self._io.pos()
        self._io.seek(0)
        tmp = self._io.read_bytes_full()
        self._io.seek(_pos)
        return tmp

    @classmethod
    def from_pe(cls, pe: MicrosoftPe):
        _pos = pe._io.pos()
        pe._io.seek(0)
        buf = pe._io.read_bytes_full()
        pe._io.seek(_pos)

        return cls(KaitaiStream(BytesIO(buf)))

    @classmethod
    def from_bytes(cls, data: Union[bytes, bytearray]):

        # Convert to bytes
        if isinstance(data, bytes):
            data = b'' + data

        mz = b"MZ"
        if data[0x0:0x2] != mz:
            raise Exception('File is not a PE file')

        pe = MicrosoftPe.from_bytes(data)

        _pos = pe._io.pos()
        pe._io.seek(0)
        buf = pe._io.read_bytes_full()
        pe._io.seek(_pos)

        return cls(KaitaiStream(BytesIO(buf)))

