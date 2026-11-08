import errno
import base64
import json
import os
from pathlib import Path
import sys
import threading
import time
import uuid


STDERR_LIMIT = 16384
_channel = None
_lock = None
_phase = None


def exception_record(error):
    frames = []
    trace = error.__traceback__
    while trace is not None:
        code = trace.tb_frame.f_code
        path = Path(code.co_filename)
        parts = path.parts
        relative = '/'.join(parts[parts.index('malpdf'):]) if 'malpdf' in parts else path.name
        frames.append({'file': relative, 'function': code.co_name, 'line': trace.tb_lineno})
        trace = trace.tb_next
    name = type(error).__name__
    number = getattr(error, 'errno', None)
    return {'exception_type': name if name.isidentifier() and len(name) <= 80 else 'OtherError',
        'exception_errno': number if type(number) is int else None, 'traceback': frames[-32:]}


def _emit(message):
    if _channel is not None:
        try:
            with _lock:
                _channel.send_bytes(json.dumps(message, allow_nan=False).encode())
        except (OSError, EOFError, ValueError):
            pass


def report_phase(phase):
    global _phase
    _phase = phase
    _emit({'phase': phase})


def report_exception(error):
    _emit({**exception_record(error), 'exception_phase': _phase})


def run_child(channel, target, arguments):
    global _channel, _lock
    _channel, _lock = channel, threading.Lock()
    read_fd, write_fd = os.pipe()
    saved_stderr = os.dup(2)
    os.dup2(write_fd, 2)
    os.close(write_fd)

    def collect_stderr():
        remaining = STDERR_LIMIT
        truncated = False
        try:
            while chunk := os.read(read_fd, 4096):
                overflow = len(chunk) > remaining
                if remaining:
                    kept = chunk[:remaining]
                    _emit({'stderr': base64.b64encode(kept).decode('ascii')})
                    remaining -= len(kept)
                if overflow and not truncated:
                    _emit({'stderr_truncated': True})
                    truncated = True
        finally:
            os.close(read_fd)

    collector = threading.Thread(target=collect_stderr, daemon=True)
    collector.start()
    try:
        report_phase('worker_bootstrap')
        target(*arguments)
    except BaseException as error:
        report_exception(error)
    finally:
        sys.stderr.flush()
        os.dup2(saved_stderr, 2)
        os.close(saved_stderr)
        collector.join(timeout=0.2)
        _emit({'stderr_capture_complete': not collector.is_alive()})
        channel.close()


class WorkerDiagnostics:
    def __init__(self, sample_id, run_id=None, entry_point='profile_pdf'):
        self.started = time.monotonic()
        self.receiver = self.sender = None
        self.data = {'schema_version': 'pdf-worker-diagnostic-v1', 'sample_id': sample_id,
            'run_id': run_id if run_id is not None else uuid.uuid4().hex, 'entry_point': entry_point,
            'worker_exit_code': None, 'cleanup_exit_code': None, 'exception_type': None,
            'exception_errno': None, 'exception_phase': None, 'traceback': None, 'stderr': None, 'stderr_truncated': None,
            'stderr_capture_complete': None,
            'stderr_scope': 'private LAB artifact; untrusted text; never numeric export',
            'elapsed_ms': None, 'last_phase': 'validation', 'timeout_reason': None,
            'failure_kind': None, 'checkpoint_received': False, 'checkpoint_status': None,
            'peak_rss_bytes': None, 'resource_limits': None, 'preserved_before_cleanup': False}
        self.stderr = bytearray()

    def phase(self, phase):
        self.data['last_phase'] = phase

    def exception(self, error):
        if self.data['exception_type'] is None:
            self.data.update(exception_record(error))

    def open_channel(self, context):
        self.receiver, self.sender = context.Pipe(duplex=False)
        return self.sender

    def drain(self):
        if self.receiver is None:
            return
        for _ in range(32):
            try:
                if not self.receiver.poll():
                    break
                message = json.loads(self.receiver.recv_bytes(maxlength=65536))
            except (EOFError, OSError, ValueError):
                break
            if 'stderr' in message:
                self.stderr.extend(base64.b64decode(message['stderr'], validate=True)[:max(0, STDERR_LIMIT - len(self.stderr))])
                self.data['stderr'] = self.stderr.decode('utf-8', errors='replace')
            else:
                self.data.update({key: value for key, value in message.items() if key in (
                    'exception_type', 'exception_errno', 'exception_phase', 'traceback', 'stderr_truncated', 'stderr_capture_complete')})
                if message.get('stderr_capture_complete'):
                    if self.data['stderr_truncated'] is None:
                        self.data['stderr_truncated'] = False
                    if self.data['stderr'] is None:
                        self.data['stderr'] = ''
                if 'phase' in message:
                    self.phase(message['phase'])

    def preserve(self, result, process=None):
        self.drain()
        self.data['elapsed_ms'] = int((time.monotonic() - self.started) * 1000)
        if process is not None:
            self.data['worker_exit_code'] = process.exitcode
        self.data['preserved_before_cleanup'] = True
        if result is not None:
            self.data['peak_rss_bytes'] = result.get('peak_rss_bytes') or None
            self.data['resource_limits'] = result.get('resource_limits')
            errors = result.get('errors', [])
            if 'wall_timeout' in errors:
                self.data.update(timeout_reason='wall_timeout', failure_kind='timeout')
            elif 'extraction_cancelled' in errors:
                self.data['failure_kind'] = 'cancelled'
            elif self.data['exception_type'] == 'MemoryError':
                self.data['failure_kind'] = 'memory_error'
            elif self.data['exception_phase'] in {'checkpoint_serialization', 'result_serialization'}:
                self.data['failure_kind'] = 'ipc_serialization_error'
            elif self.data['exception_phase'] is not None:
                self.data['failure_kind'] = 'worker_exception'
            elif self.data['worker_exit_code'] not in (None, 0) and self.data['exception_type'] in (None, 'BrokenPipeError', 'EOFError'):
                self.data['failure_kind'] = 'worker_crash'
            elif 'invalid_worker_response' in errors:
                self.data['failure_kind'] = 'ipc_serialization_error'
            elif self.data['exception_type'] is not None:
                self.data['failure_kind'] = ('admission_error' if self.data['last_phase'] == 'worker_admission'
                    else 'worker_start_error' if self.data['last_phase'] == 'worker_start' else 'worker_exception')
            elif result.get('status') in {'worker_error', 'resource_limit_or_signal'}:
                self.data['failure_kind'] = 'worker_crash' if self.data['worker_exit_code'] not in (None, 0) else 'unresolved'
        if self.data['exception_errno'] == errno.ENOMEM:
            self.data['failure_kind'] = 'allocation_failure'

    def close(self):
        for channel in (self.receiver, self.sender):
            if channel is not None:
                channel.close()
