"""Build a portable Windows EXE with its own Python/Tk runtime."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

def build(output, work):
    root=Path(__file__).resolve().parent
    helper=(root/'Helper.Core.psm1').is_file()
    app_id='VortexDownloadHelper' if helper else 'WindowsMinerAudit'
    exe=app_id+'.exe'
    output=Path(output).resolve(); output.mkdir(parents=True,exist_ok=True)
    work=Path(work).resolve(); work.mkdir(parents=True,exist_ok=True)
    command=[sys.executable,'-m','PyInstaller','--noconfirm','--onefile','--windowed','--noupx',
             '--name',app_id,'--distpath',str(output),'--workpath',str(work/'pyinstaller'),'--specpath',str(work),
             '--log-level','WARN']
    command+=['--icon',str(root/'assets/icon.ico'),'--add-data',str(root/'assets/icon.png')+os.pathsep+'assets']
    resources=['Vortex-download-helper.ps1','Helper.Core.psm1','Helper.Messages.psm1'] if helper else ['collect.ps1','examples/suspicious.json']
    for filename in resources:
        destination='examples' if filename.startswith('examples/') else '.'
        command+=['--add-data',str(root/filename)+os.pathsep+destination]
    command+=[str(root/'gui.py')]
    subprocess.run(command,cwd=root,check=True)
    payload=output/exe
    sha=hashlib.sha256(payload.read_bytes()).hexdigest()
    (output/'SHA256SUMS.txt').write_text(sha+'  '+payload.name+'\n',encoding='ascii')
    print(json.dumps(dict(portable=str(payload),sha256=sha,size_bytes=payload.stat().st_size)))

if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',default='dist')
    parser.add_argument('--work',default='build')
    options=parser.parse_args()
    build(options.output,options.work)
