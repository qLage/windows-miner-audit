"""Exercise the actual portable executable; no real scan or download is started."""
import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import tempfile


def verify(directory):
    root=Path(__file__).resolve().parent
    name='VortexDownloadHelper.exe' if (root/'Helper.Core.psm1').is_file() else 'WindowsMinerAudit.exe'
    exe=Path(directory).resolve()/name
    expected=(exe.parent/'SHA256SUMS.txt').read_text(encoding='ascii').split()[0]
    actual=hashlib.sha256(exe.read_bytes()).hexdigest()
    if actual!=expected:raise RuntimeError('Executable checksum does not match SHA256SUMS.txt')
    with tempfile.TemporaryDirectory(prefix='portable-package-qa-') as folder:
        folder=Path(folder)
        subprocess.run([str(exe),'--self-test','--artifacts',str(folder/'ui')],check=True,timeout=90)
        ui=json.loads((folder/'ui/self-test.json').read_text(encoding='utf-8'))
        if ui.get('ok') is not True:raise RuntimeError('Packaged GUI self-test did not pass')
        subprocess.run([str(exe),'--benchmark',str(folder/'idle.json')],check=True,timeout=30)
        idle=json.loads((folder/'idle.json').read_text(encoding='utf-8'))
        if idle.get('background_worker_started') is not False:raise RuntimeError('Idle application started background work')
    result=dict(executable=name,size_bytes=exe.stat().st_size,sha256=actual,gui=ui,idle=idle)
    (exe.parent/'verification.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--directory',default='dist')
    args=parser.parse_args();print(json.dumps(verify(args.directory)))
