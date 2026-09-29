"""Small expect-style PTY runner (POSIX PTY or Windows ConPTY, stdlib only).

The caller owns the command and the isolated environment. This module never
guesses an answer: each expected prompt has an explicit regular expression and
reply. A missing prompt or timeout is an incomplete measurement.
"""
from __future__ import annotations

import codecs
import os
import queue
import re
import subprocess
import threading
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence


ANSI = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


@dataclass(frozen=True)
class Exchange:
    pattern: str
    answer: str
    timeout_s: float = 30.0
    stop: bool = False


@dataclass
class PtyResult:
    exit: Optional[int]
    output: str
    matched: List[str]
    pending: List[str]
    timed_out: bool
    backend: str


def visible(text: str) -> str:
    return ANSI.sub("", text).replace("\r", "\n")


class _Posix:
    backend = "posix-pty"

    def __init__(self, argv: Sequence[str], cwd: str, env: Dict[str, str]):
        import pty
        master, slave = pty.openpty()
        try:
            self.proc = subprocess.Popen(list(argv), cwd=cwd, env=env, stdin=slave, stdout=slave,
                                         stderr=slave, start_new_session=True, close_fds=True)
        finally:
            os.close(slave)
        self.master = master
        self.events: "queue.Queue[bytes]" = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        while True:
            try:
                data = os.read(self.master, 8192)
            except OSError:
                data = b""
            if not data:
                self.events.put(b"")
                return
            self.events.put(data)

    def write(self, data: bytes):
        os.write(self.master, data)

    def poll(self) -> Optional[int]:
        return self.proc.poll()

    def terminate(self):
        if self.proc.poll() is None:
            self.proc.terminate()

    def close(self):
        try:
            os.close(self.master)
        except OSError:
            pass
        if self.proc.poll() is None:
            self.proc.kill()
        self.proc.wait(timeout=5)


class _Windows:
    backend = "windows-conpty"

    def __init__(self, argv: Sequence[str], cwd: str, env: Dict[str, str]):
        import ctypes as c
        from ctypes import wintypes as w

        if not hasattr(c.WinDLL("kernel32"), "CreatePseudoConsole"):
            raise OSError("Windows ConPTY is unavailable on this host")
        self.c, self.w, self.k = c, w, c.WinDLL("kernel32", use_last_error=True)
        k = self.k
        H = w.HANDLE
        SIZE = c.c_size_t

        class COORD(c.Structure):
            _fields_ = [("X", c.c_short), ("Y", c.c_short)]

        class STARTUPINFOW(c.Structure):
            _fields_ = [("cb", w.DWORD), ("lpReserved", w.LPWSTR), ("lpDesktop", w.LPWSTR),
                        ("lpTitle", w.LPWSTR), ("dwX", w.DWORD), ("dwY", w.DWORD),
                        ("dwXSize", w.DWORD), ("dwYSize", w.DWORD), ("dwXCountChars", w.DWORD),
                        ("dwYCountChars", w.DWORD), ("dwFillAttribute", w.DWORD),
                        ("dwFlags", w.DWORD), ("wShowWindow", w.WORD), ("cbReserved2", w.WORD),
                        ("lpReserved2", c.POINTER(c.c_byte)), ("hStdInput", H),
                        ("hStdOutput", H), ("hStdError", H)]

        class STARTUPINFOEXW(c.Structure):
            _fields_ = [("StartupInfo", STARTUPINFOW), ("lpAttributeList", c.c_void_p)]

        class PROCESS_INFORMATION(c.Structure):
            _fields_ = [("hProcess", H), ("hThread", H), ("dwProcessId", w.DWORD), ("dwThreadId", w.DWORD)]

        k.CreatePipe.argtypes = [c.POINTER(H), c.POINTER(H), c.c_void_p, w.DWORD]
        k.CreatePipe.restype = w.BOOL
        k.CreatePseudoConsole.argtypes = [COORD, H, H, w.DWORD, c.POINTER(H)]
        k.CreatePseudoConsole.restype = c.c_long
        k.InitializeProcThreadAttributeList.argtypes = [c.c_void_p, w.DWORD, w.DWORD, c.POINTER(SIZE)]
        k.InitializeProcThreadAttributeList.restype = w.BOOL
        k.UpdateProcThreadAttribute.argtypes = [c.c_void_p, w.DWORD, SIZE, c.c_void_p, SIZE,
                                                c.c_void_p, c.POINTER(SIZE)]
        k.UpdateProcThreadAttribute.restype = w.BOOL
        k.CreateProcessW.argtypes = [w.LPCWSTR, w.LPWSTR, c.c_void_p, c.c_void_p, w.BOOL,
                                     w.DWORD, c.c_void_p, w.LPCWSTR,
                                     c.POINTER(STARTUPINFOW), c.POINTER(PROCESS_INFORMATION)]
        k.CreateProcessW.restype = w.BOOL
        k.ReadFile.argtypes = [H, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        k.ReadFile.restype = w.BOOL
        k.WriteFile.argtypes = [H, c.c_void_p, w.DWORD, c.POINTER(w.DWORD), c.c_void_p]
        k.WriteFile.restype = w.BOOL
        k.GetExitCodeProcess.argtypes = [H, c.POINTER(w.DWORD)]
        k.GetExitCodeProcess.restype = w.BOOL
        k.TerminateProcess.argtypes = [H, w.UINT]
        k.CloseHandle.argtypes = [H]
        k.DeleteProcThreadAttributeList.argtypes = [c.c_void_p]
        k.ClosePseudoConsole.argtypes = [H]

        self.input_write = H()
        input_read, output_write, self.output_read = H(), H(), H()
        if not k.CreatePipe(c.byref(input_read), c.byref(self.input_write), None, 0):
            raise c.WinError(c.get_last_error())
        if not k.CreatePipe(c.byref(self.output_read), c.byref(output_write), None, 0):
            k.CloseHandle(input_read)
            k.CloseHandle(self.input_write)
            raise c.WinError(c.get_last_error())
        self.pseudo = H()
        hr = k.CreatePseudoConsole(COORD(120, 40), input_read, output_write, 0, c.byref(self.pseudo))
        if hr:
            k.CloseHandle(input_read)
            k.CloseHandle(output_write)
            k.CloseHandle(self.input_write)
            k.CloseHandle(self.output_read)
            raise OSError(f"CreatePseudoConsole failed: HRESULT 0x{hr & 0xffffffff:08x}")
        self.input_read, self.output_write = input_read, output_write
        size = SIZE()
        k.InitializeProcThreadAttributeList(None, 1, 0, c.byref(size))
        self.attributes = c.create_string_buffer(size.value)
        if not k.InitializeProcThreadAttributeList(self.attributes, 1, 0, c.byref(size)):
            self.close()
            raise c.WinError(c.get_last_error())
        self.attributes_ready = True
        if not k.UpdateProcThreadAttribute(self.attributes, 0, 0x00020016, self.pseudo,
                                           c.sizeof(self.pseudo), None, None):
            self.close()
            raise c.WinError(c.get_last_error())
        startup = STARTUPINFOEXW()
        startup.StartupInfo.cb = c.sizeof(startup)
        startup.StartupInfo.dwFlags = 0x00000100  # STARTF_USESTDHANDLES
        startup.lpAttributeList = c.cast(self.attributes, c.c_void_p)
        self.process = PROCESS_INFORMATION()
        command = c.create_unicode_buffer(subprocess.list2cmdline(list(argv)))
        envblock = c.create_unicode_buffer("\0".join(f"{key}={value}" for key, value in sorted(env.items())) + "\0\0")
        flags = 0x00080000 | 0x00000400  # EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT
        created = k.CreateProcessW(str(argv[0]), command, None, None, False, flags, envblock, cwd,
                                   c.byref(startup.StartupInfo), c.byref(self.process))
        k.CloseHandle(self.input_read)
        k.CloseHandle(self.output_write)
        self.input_read = self.output_write = None
        if not created:
            self.close()
            raise c.WinError(c.get_last_error())
        self.events: "queue.Queue[bytes]" = queue.Queue()
        self.reader = threading.Thread(target=self._read, daemon=True)
        self.reader.start()

    def _read(self):
        c, w, k = self.c, self.w, self.k
        while True:
            buf, count = c.create_string_buffer(8192), w.DWORD()
            if not k.ReadFile(self.output_read, buf, 8192, c.byref(count), None) or not count.value:
                self.events.put(b"")
                return
            self.events.put(buf.raw[:count.value])

    def write(self, data: bytes):
        c, w = self.c, self.w
        written = w.DWORD()
        if not self.k.WriteFile(self.input_write, c.c_char_p(data), len(data), c.byref(written), None):
            raise c.WinError(c.get_last_error())

    def poll(self) -> Optional[int]:
        if not getattr(self, "process", None) or not self.process.hProcess:
            return None
        code = self.w.DWORD()
        if not self.k.GetExitCodeProcess(self.process.hProcess, self.c.byref(code)):
            raise self.c.WinError(self.c.get_last_error())
        return None if code.value == 259 else int(code.value)

    def terminate(self):
        if getattr(self, "process", None) and self.process.hProcess and self.poll() is None:
            self.k.TerminateProcess(self.process.hProcess, 1)

    def close(self):
        if getattr(self, "process", None) and self.process.hProcess:
            self.terminate()
            self.k.CloseHandle(self.process.hThread)
            self.k.CloseHandle(self.process.hProcess)
        if getattr(self, "attributes_ready", False):
            self.k.DeleteProcThreadAttributeList(self.attributes)
        for handle in (getattr(self, "pseudo", None), getattr(self, "input_write", None),
                       getattr(self, "output_read", None), getattr(self, "input_read", None),
                       getattr(self, "output_write", None)):
            if handle:
                if handle is getattr(self, "pseudo", None):
                    self.k.ClosePseudoConsole(handle)
                else:
                    self.k.CloseHandle(handle)


def run(argv: Sequence[str], *, cwd: str, env: Dict[str, str], exchanges: Sequence[Exchange] = (),
        timeout_s: float = 120.0, output_limit: int = 2_000_000) -> PtyResult:
    """Run one command in a terminal, answering only explicitly matched prompts."""
    if not argv or not os.path.isabs(str(argv[0])):
        raise ValueError("PTY command must start with an absolute executable path")
    terminal = _Windows(argv, cwd, env) if os.name == "nt" else _Posix(argv, cwd, env)
    decoder = codecs.getincrementaldecoder("utf-8")("replace")
    output = ""
    matched: List[str] = []
    index = 0
    deadline = time.monotonic() + timeout_s
    step_deadline = time.monotonic() + exchanges[0].timeout_s if exchanges else deadline
    timed_out = False
    exited_at = None
    try:
        while True:
            now = time.monotonic()
            if terminal.poll() is not None:
                exited_at = exited_at or now
                if now - exited_at >= 0.5 and terminal.events.empty():
                    break
            if now >= min(deadline, step_deadline):
                timed_out = True
                terminal.terminate()
                break
            try:
                chunk = terminal.events.get(timeout=min(0.1, deadline - now, step_deadline - now))
            except queue.Empty:
                continue
            if not chunk:
                break
            output += decoder.decode(chunk)
            if len(output) > output_limit:
                timed_out = True
                terminal.terminate()
                break
            if index < len(exchanges):
                match = re.search(exchanges[index].pattern, visible(output), re.IGNORECASE | re.DOTALL)
                if match:
                    matched.append(match.group(0)[-160:])
                    if exchanges[index].stop:
                        index += 1
                        terminal.terminate()
                        break
                    terminal.write(exchanges[index].answer.encode("utf-8"))
                    index += 1
                    step_deadline = time.monotonic() + (exchanges[index].timeout_s if index < len(exchanges)
                                                        else timeout_s)
        code = terminal.poll()
        return PtyResult(code, output + decoder.decode(b"", final=True), matched,
                         [x.pattern for x in exchanges[index:]], timed_out, terminal.backend)
    finally:
        terminal.close()
