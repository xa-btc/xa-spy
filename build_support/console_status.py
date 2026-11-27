"""
Color status messages on terminals; preserve plain captured output.

SETUP: Keep this file in build_support/ beside the root build launcher. No PLACEHOLDER
replacement or project configuration is needed. Import print_status from the
build script; this helper has no standalone action. Optional NO_COLOR in the
environment disables color; captured output remains plain automatically.
Derived from the maintained Normal Builds console_status.py template.
Last Updated: 2026-10-27 22:52:06
XA Spy v1.00 - blue stages; plain redirected/NO_COLOR output and logs.
"""
import builtins
import os
import re
import sys


COLORS = {'error': '\x1b[91m', 'warning': '\x1b[38;2;255;165;0m',
          'success': '\x1b[92m', 'stage': '\x1b[94m'}
RESET = '\x1b[0m'
_ANSI = re.compile(r'\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-?]*[ -/]*[@-~]')


def strip_ansi(text):
    """Keep child-tool color/title escapes out of captured output and log files."""
    return _ANSI.sub('', str(text))


def status_kind(text):
    line = text.strip()
    # Successful compiler summaries contain the words warning/error too.
    if re.fullmatch(r'0 (?:Warning|Error)\(s\)', line, re.IGNORECASE):
        return None
    if re.search(r'\bFAILED\b|\bFAIL:|\[ERROR\]|\[CRITICAL ERROR\]|^error\b|^Unhandled exception|: error\b|\bfatal error\b|^CMake Error\b', line, re.IGNORECASE):
        return 'error'
    if re.search(r'\bWARNING\b|^warn:|\[WARN\]|\[RETRY\]|\b[1-9][0-9]* Warning\(s\)', line, re.IGNORECASE):
        return 'warning'
    if re.search(r'\bSUCCESSFUL\b|\[OK\]|^PASS:|^Build succeeded|\bVERSION UPDATED:|\bFINISHED\b', line, re.IGNORECASE):
        return 'success'
    if re.match(r'\[STAGE(?:\s+\d+/\d+)?\]', line, re.IGNORECASE):
        return 'stage'
    return None


def color_enabled(stream):
    if 'NO_COLOR' in os.environ or not getattr(stream, 'isatty', lambda: False)():
        return False
    if os.name != 'nt':
        return os.environ.get('TERM') != 'dumb'
    # Enable VT output for Windows consoles when supported. Pipes stay plain.
    try:
        import ctypes
        import msvcrt
        from ctypes import wintypes
        kernel = ctypes.WinDLL('kernel32', use_last_error=True)
        kernel.GetConsoleMode.argtypes = (wintypes.HANDLE, ctypes.POINTER(wintypes.DWORD))
        kernel.GetConsoleMode.restype = wintypes.BOOL
        kernel.SetConsoleMode.argtypes = (wintypes.HANDLE, wintypes.DWORD)
        kernel.SetConsoleMode.restype = wintypes.BOOL
        handle = msvcrt.get_osfhandle(stream.fileno())
        mode = wintypes.DWORD()
        return bool(kernel.GetConsoleMode(handle, ctypes.byref(mode)) and
                    kernel.SetConsoleMode(handle, mode.value | 0x0004))
    except (AttributeError, OSError, ValueError):
        return False


def print_status(*values, sep=' ', end='\n', file=None, flush=False):
    stream = sys.stdout if file is None else file
    if not color_enabled(stream):
        return builtins.print(*(strip_ansi(value) for value in values), sep=sep, end=end,
                              file=stream, flush=flush)
    text = (' ' if sep is None else sep).join(str(value) for value in values)
    lines = []
    for line in text.splitlines(keepends=True):
        kind = status_kind(line)
        # Preserve colors already emitted by a child tool.
        if kind and '\x1b[' not in line:
            body = line.rstrip('\r\n')
            line = COLORS[kind] + body + RESET + line[len(body):]
        lines.append(line)
    builtins.print(''.join(lines), end=end, file=stream, flush=flush)
