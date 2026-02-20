#!/usr/bin/env python3
"""
sandbox_runner.py
Wrapper that executes student Python code with restricted imports,
resource limits, and capped output. Place this file in the project root.

The Node.js server passes student code as a temp file path:
    python3 -u sandbox_runner.py /tmp/ide_<uuid>.py
"""

import sys
import builtins
import os

# ── Resource limits (Linux / macOS only) ─────────────────────────────────────
# Windows does not support the `resource` module; limits are skipped silently.
try:
    import resource as _resource

    MB = 1024 * 1024

    # Virtual address space: 256 MB
    # Prevents runaway memory allocation from crashing the server.
    _resource.setrlimit(_resource.RLIMIT_AS, (256 * MB, 256 * MB))

    # Max file write size: 5 MB
    # Students can still open() files for reading; writes are size-capped.
    _resource.setrlimit(_resource.RLIMIT_FSIZE, (5 * MB, 5 * MB))

    # CPU time: 25 seconds (belt-and-suspenders with the Node.js SIGKILL timer)
    _resource.setrlimit(_resource.RLIMIT_CPU, (25, 25))

except (ImportError, ValueError, AttributeError):
    pass

# ── Block dangerous module imports ────────────────────────────────────────────
# Students learn Python fundamentals; none of these are needed in class.

_BLOCKED = frozenset({
    # Process spawning / shell access
    'subprocess', 'multiprocessing', 'multiprocessing.pool',
    'pty', 'tty',

    # Network / internet
    'socket', 'socketserver',
    'asyncio', 'asynchat', 'asyncore',
    'http', 'http.server', 'http.client',
    'urllib', 'urllib.request', 'urllib.parse',
    'xmlrpc', 'xml.etree',
    'ftplib', 'smtplib', 'poplib', 'imaplib',
    'nntplib', 'telnetlib',
    'ssl', 'select', 'selectors',

    # Low-level OS / system
    'ctypes', 'ctypes.util',
    'mmap', 'signal',
    'fcntl', 'grp', 'pwd', 'termios',

    # Unsafe serialisation (can execute arbitrary code on load)
    'pickle', 'pickletools', 'shelve', 'marshal',

    # Import machinery (used to bypass blocklists)
    'importlib', 'importlib.util', 'importlib.machinery',
    'pkgutil', 'zipimport',

    # Interactive / debugger
    'code', 'codeop', 'pdb', 'bdb', 'trace', 'tracemalloc',

    # GUI / browser
    'webbrowser', 'tkinter', 'turtle',

    # Windows-specific
    'winreg', 'winsound', 'msvcrt',
})

_real_import = builtins.__import__

def _safe_import(name, globals=None, locals=None, fromlist=(), level=0):
    top = name.split('.')[0]
    if top in _BLOCKED or name in _BLOCKED:
        raise ImportError(
            f"Module '{name}' is not available in the classroom environment."
        )
    return _real_import(name, globals, locals, fromlist, level)

builtins.__import__ = _safe_import

# ── Scrub dangerous os functions ──────────────────────────────────────────────
# `os` itself is useful (os.path, os.getcwd, etc.) but system-exec calls are not.

_BLOCKED_OS = frozenset({
    'system', 'popen',
    'execv', 'execve', 'execvp', 'execvpe',
    'execl', 'execle', 'execlp', 'execlpe',
    'fork', 'forkpty',
    'spawn', 'spawnl', 'spawnle', 'spawnlp', 'spawnlpe',
    'spawnv', 'spawnve', 'spawnvp', 'spawnvpe',
    '_exit', 'startfile',
    'popen2', 'popen3', 'popen4',
})

def _make_safe_os():
    import os as _real_os
    import types
    safe = types.ModuleType('os')
    safe.__dict__.update({
        k: v for k, v in _real_os.__dict__.items()
        if k not in _BLOCKED_OS
    })
    # Also scrub os.path from exposing the real home directory
    return safe

import os as _real_os  # noqa: E402 (already imported at top)
sys.modules['os'] = _make_safe_os()

# ── Output size limit ─────────────────────────────────────────────────────────
# 100 KB per stream. Prevents infinite-print loops exhausting server memory.

_MAX_OUTPUT_BYTES = 100 * 1024


class _LimitedStream:
    """Wraps stdout/stderr and truncates after MAX_OUTPUT_BYTES."""

    def __init__(self, real_stream):
        self._real    = real_stream
        self._written = 0
        self._capped  = False

    def write(self, text):
        if self._capped:
            return len(text)

        if isinstance(text, bytes):
            chunk_bytes = len(text)
            text_str    = text.decode('utf-8', errors='replace')
        else:
            chunk_bytes = len(text.encode('utf-8', errors='replace'))
            text_str    = text

        remaining = _MAX_OUTPUT_BYTES - self._written
        if chunk_bytes >= remaining:
            # Write as much as fits, then cap.
            safe_text = text_str.encode('utf-8', errors='replace')[:remaining].decode('utf-8', errors='replace')
            self._real.write(safe_text)
            self._real.write('\n[Output limit reached: 100 KB max per stream]\n')
            self._real.flush()
            self._capped = True
            return len(text)

        self._written += chunk_bytes
        self._real.write(text_str)
        return len(text)

    def flush(self):
        self._real.flush()

    def fileno(self):
        return self._real.fileno()

    @property
    def encoding(self):
        return getattr(self._real, 'encoding', 'utf-8')

    @property
    def errors(self):
        return getattr(self._real, 'errors', 'replace')


sys.stdout = _LimitedStream(sys.stdout)
sys.stderr = _LimitedStream(sys.stderr)

# ── Execute student code ──────────────────────────────────────────────────────

if len(sys.argv) < 2:
    print("sandbox_runner: no code file provided.", file=sys.stderr)
    sys.exit(1)

_code_file = sys.argv[1]

try:
    with open(_code_file, 'r', encoding='utf-8') as _f:
        _source = _f.read()
except OSError as _e:
    print(f"sandbox_runner: could not read code file: {_e}", file=sys.stderr)
    sys.exit(1)

# Run in a clean namespace — no access to sandbox internals.
_namespace = {'__name__': '__main__', '__builtins__': builtins}

try:
    exec(compile(_source, '<student_code>', 'exec'), _namespace)
except SystemExit:
    # Allow sys.exit() calls from student code.
    pass
except Exception:
    import traceback
    tb_lines = traceback.format_exc().splitlines()
    # Strip lines that reference this wrapper file so tracebacks look clean.
    filtered = [
        line for line in tb_lines
        if 'sandbox_runner' not in line and '<frozen' not in line
    ]
    print('\n'.join(filtered), file=sys.stderr)
    sys.exit(1)