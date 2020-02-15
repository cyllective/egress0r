import io
import os

from egress0r import constants


class ExfilPayload:

    DEFAULT_READ_MODE = "rb"

    def __init__(
        self, filename, read_mode=DEFAULT_READ_MODE, chunk_size=None, max_chunks=None
    ):
        self.filename = filename
        self.read_mode = read_mode
        self.filepath = os.path.join(constants.data_dir, filename)
        self.chunk_size = chunk_size
        self.max_chunks = max_chunks
        self._fh = None
        self._data = None
        self._data_length = 0

    @property
    def filehandle(self):
        if not self._fh:
            if "b" in self.read_mode:
                newline = None
            else:
                newline = ""
            self._fh = open(self.filepath, self.read_mode, newline=newline)
        return self._fh

    @property
    def data_length(self):
        return len(self.data)

    @property
    def chunks_total_length(self):
        try:
            return self.max_chunks * self.chunk_size
        except TypeError:
            return 0

    @property
    def data(self):
        if not self._data:
            self.filehandle.seek(0, 0)
            self._data = self.filehandle.read()
            self.filehandle.seek(0, 0)
        return self._data

    def to_bytes_io(self):
        return io.BytesIO(self.data)

    def to_string_io(self):
        return io.StringIO(self.data)

    def to_io(self):
        if "b" in self.read_mode:
            return self.to_bytes_io()
        else:
            return self.to_string_io()

    def chunk_iter(self, chunk_size=None, max_chunks=None):
        if not chunk_size and not max_chunks and self.max_chunks and self.chunk_size:
            chunk_size = self.chunk_size
            max_chunks = self.max_chunks

        self.filehandle.seek(0, 0)
        if max_chunks is None:
            return [chunk for chunk in self.filehandle.read(chunk_size)]

        for _ in range(max_chunks):
            yield self.filehandle.read(chunk_size)
        self.filehandle.seek(0, 0)

    def line_iter(self, max_lines=None):
        self.filehandle.seek(0, 0)
        if max_lines is None:
            return [chunk.rstrip() for chunk in self.filehandle.readlines()]

        return [self.filehandle.readline().rstrip() for _ in range(max_lines)]

    def read(self, nbytes=None):
        return self.filehandle.read(nbytes)


class DNSExfilPayload(ExfilPayload):

    DEFAULT_READ_MODE = "rb"
    DEFAULT_RECORD_TYPE = "A"
    DEFAULT_CHUNK_SIZE = 30
    DEFAULT_MAX_CHUNKS = 30

    def __init__(
        self,
        filename,
        domain,
        nameserver,
        record_type=DEFAULT_RECORD_TYPE,
        read_mode=DEFAULT_READ_MODE,
        chunk_size=DEFAULT_CHUNK_SIZE,
        max_chunks=DEFAULT_MAX_CHUNKS,
    ):
        super().__init__(
            filename, read_mode, chunk_size=int(chunk_size), max_chunks=int(max_chunks)
        )
        self.domain = domain
        self.record_type = record_type
        self.nameserver = nameserver


class SMTPExfilPayload(ExfilPayload):

    DEFAULT_READ_MODE = "rb"
    DEFAULT_EXFIL_MODE = "inline"
    VALID_EXFIL_MODES = ("inline", "attachment")

    def __init__(
        self, filename, exfil_mode=DEFAULT_EXFIL_MODE, read_mode=DEFAULT_READ_MODE
    ):
        if exfil_mode not in self.VALID_EXFIL_MODES:
            raise ValueError(
                f"SMTPExfilPayload expects argument exfil_mode "
                f"to be one of {self.VALID_EXFIL_MODES}, got {exfil_mode!r}"
            )
        if exfil_mode == "attachment":
            read_mode = "rb"
        super().__init__(filename, read_mode)
        self.exfil_mode = exfil_mode or self.DEFAULT_EXFIL_MODE
