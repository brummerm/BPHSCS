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
    # Import machinery (used to bypass blocklists)
    'importlib', 'importlib.util', 'importlib.machinery',
    'pkgutil', 'zipimport',
    # Interactive / debugger
    'code', 'codeop', 'pdb', 'bdb', 'trace', 'tracemalloc',
    # GUI toolkits that require a display server
    'tkinter', 'tkinter.ttk', 'tkinter.messagebox',
    'wx', 'PyQt5', 'PyQt6', 'PySide2', 'PySide6',
    'gi', 'gi.repository',
    # NOTE: 'turtle' is intentionally NOT listed here.
    # It is intercepted below by injecting our turtle_capture mock.
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

import os as _real_os
sys.modules['os'] = _make_safe_os()

# ── Inject turtle_capture mock ────────────────────────────────────────────────
# We inject BEFORE wrapping stdout so the mock can save a reference
# to the real stdout for writing its canvas-data marker line.
_turtle_capture = None
try:
    import importlib.util as _ilu
    import os.path as _osp
    _tc_path = _osp.join(_osp.dirname(_osp.abspath(__file__)), 'turtle_capture.py')
    if _osp.exists(_tc_path):
        _spec = _ilu.spec_from_file_location('turtle_capture', _tc_path)
        _turtle_capture = _ilu.module_from_spec(_spec)
        # Temporarily restore real import so turtle_capture can import math/json
        builtins.__import__ = _real_import
        _spec.loader.exec_module(_turtle_capture)
        builtins.__import__ = _safe_import
        # Give the mock a handle to real stdout before we wrap it
        _turtle_capture._REAL_OUT = sys.stdout
        # Inject as 'turtle' so `import turtle` in student code uses our mock
        sys.modules['turtle'] = _turtle_capture
except Exception:
    pass  # If anything goes wrong, turtle remains unresolvable

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
    import traceback
    tb_lines = traceback.format_exc().splitlines()
    filtered = [
        line for line in tb_lines
        if 'sandbox_runner' not in line and '<frozen' not in line
    ]
    print('\n'.join(filtered), file=sys.stderr)
    sys.exit(1)
finally:
    # After exec, emit any captured turtle canvas data
    if _turtle_capture is not None:
        try:
            _turtle_capture._output_canvas()
        except Exception:
            pass