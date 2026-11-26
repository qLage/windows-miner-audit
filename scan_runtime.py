"""Cancellable, bounded collection. Only a subprocess created here can be terminated."""
import json
import os
from pathlib import Path
import subprocess
import threading
import time


def scan(deep, cancel, notify, timeout=90):
    if os.name != 'nt':
        raise RuntimeError('Live inspection requires Windows')
    powershell = Path(os.environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    command = [str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
               '-File', str(Path(__file__).with_name('collect.ps1'))] + (['-Deep'] if deep else [])
    process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                               creationflags=subprocess.CREATE_NO_WINDOW)
    latest = [None]
    diagnostic = []
    def read_output():
        for raw in process.stdout:
            try:
                value = json.loads(raw.decode('utf-8-sig'))
                if isinstance(value, dict) and value.get('schema_version') == 1:
                    latest[0] = value
                    notify(dict(type='coverage', count=len(set(value)-{'schema_version','scan_mode','errors'})))
            except (ValueError, UnicodeError):
                pass
    def read_errors():
        for raw in process.stderr:
            line = raw.decode('utf-8', errors='replace').strip()
            if line.startswith('Collecting: '):
                notify(dict(type='progress', section=line.split(': ', 1)[1]))
            else:
                diagnostic.append(line[:1000])
    readers = [threading.Thread(target=read_output, daemon=True), threading.Thread(target=read_errors, daemon=True)]
    for thread in readers:
        thread.start()
    start = time.monotonic()
    timed_out = False
    try:
        while process.poll() is None:
            if cancel.wait(0.15) or time.monotonic()-start > timeout:
                timed_out = not cancel.is_set()
                process.terminate()
                try:
                    process.wait(3)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait(3)
                break
        for thread in readers:
            thread.join(2)
        if cancel.is_set():
            return None
        snapshot = latest[0]
        if snapshot is None:
            raise RuntimeError('Collector returned no usable snapshot. '+ ' '.join(diagnostic)[-1200:])
        if timed_out:
            snapshot.setdefault('errors', []).append('Collection timed out; remaining sections were not checked.')
        elif process.returncode:
            snapshot.setdefault('errors', []).append('Collector exited with an error: '+str(process.returncode))
        snapshot['scan_mode'] = 'deep' if deep else 'quick'
        return snapshot
    finally:
        if process.poll() is None:
            process.kill(); process.wait(3)
        process.stdout.close(); process.stderr.close()
