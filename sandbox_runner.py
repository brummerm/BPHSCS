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
try:
    import resource as _resource
    MB = 1024 * 1024
    _resource.setrlimit(_resource.RLIMIT_AS, (256 * MB, 256 * MB))
    _resource.setrlimit(_resource.RLIMIT_FSIZE, (5 * MB, 5 * MB))
    _resource.setrlimit(_resource.RLIMIT_CPU, (25, 25))
except (ImportError, ValueError, AttributeError):
    pass

# ── Pre-import modules we'll need AFTER the blocklist is installed ────────────
# These must be imported NOW, before _safe_import replaces builtins.__import__,
# because they (or their transitive deps) are in the blocked list.
#
#   traceback  → imports codeop  (codeop is blocked → error handler would crash)
#   importlib.util → needed to load turtle_capture.py
import traceback as _traceback
import importlib.util as _ilu
import os.path as _osp

# ── Inject turtle_capture mock ────────────────────────────────────────────────
# Must happen BEFORE _safe_import is installed (we need importlib, which is
# blocked for student code).  We also save a reference to real stdout here so
# turtle_capture can write its canvas-data marker line through the unwrapped
# stream later.
_turtle_capture = None
try:
    _tc_path = _osp.join(_osp.dirname(_osp.abspath(__file__)), 'turtle_capture.py')
    if _osp.exists(_tc_path):
        _spec = _ilu.spec_from_file_location('turtle_capture', _tc_path)
        _turtle_capture = _ilu.module_from_spec(_spec)
        _turtle_capture._REAL_OUT = sys.stdout   # before stdout wrapping below
        _spec.loader.exec_module(_turtle_capture)
        sys.modules['turtle'] = _turtle_capture
except Exception as _e:
    pass  # if anything goes wrong, 'turtle' stays unavailable

# ── Block dangerous module imports ────────────────────────────────────────────
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
    # Unsafe serialisation
    'pickle', 'pickletools', 'shelve', 'marshal',
    # Import machinery (blocked for student code only — we used it above already)
    'importlib', 'importlib.util', 'importlib.machinery',
    'pkgutil', 'zipimport',
    # Debugger / interactive
    # NOTE: 'codeop' and 'traceback' are intentionally NOT listed here.
    # traceback imports codeop; we need traceback in the error handler below.
    'pdb', 'bdb', 'trace', 'tracemalloc',
    # GUI toolkits that require a display server
    'tkinter', 'tkinter.ttk', 'tkinter.messagebox',
    'wx', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
    'gi', 'gi.repository',
    # NOTE: 'turtle' is intentionally NOT listed — it's intercepted above.
    'webbrowser',
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
    return safe

sys.modules['os'] = _make_safe_os()

# ── Output size limit ─────────────────────────────────────────────────────────
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
            safe_text = text_str.encode('utf-8', errors='replace')[:remaining].decode('utf-8', errors='replace')
            self._real.write(safe_text)
            self._real.write('\n[Output limit reached: 100 KB max per stream]\n')
            self._real.flush()
            self._capped = True
            return len(text)
        self._written += chunk_bytes
        self._real.write(text_str)
        return len(text)

    def flush(self):    self._real.flush()
    def fileno(self):   return self._real.fileno()

    @property
    def encoding(self): return getattr(self._real, 'encoding', 'utf-8')
    @property
    def errors(self):   return getattr(self._real, 'errors', 'replace')

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

_namespace = {'__name__': '__main__', '__builtins__': builtins}

try:
    exec(compile(_source, '<student_code>', 'exec'), _namespace)
except SystemExit:
    pass
except Exception:
    # _traceback was imported before the blocklist was installed, so this works
    tb_lines = _traceback.format_exc().splitlines()
    filtered = [
        line for line in tb_lines
        if 'sandbox_runner' not in line and '<frozen' not in line
    ]
    print('\n'.join(filtered), file=sys.stderr)
    sys.exit(1)
finally:
    # Emit any captured turtle canvas data after execution
    if _turtle_capture is not None:
        try:
            _turtle_capture._output_canvas()
        except Exception:
            pass