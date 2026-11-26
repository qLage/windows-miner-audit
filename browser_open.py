"""Open a local report in the registered WEB browser, not the .html editor."""
import ctypes
import os
from pathlib import Path
import subprocess
import webbrowser


def browser_command(uri):
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER,r'Software\Microsoft\Windows\Shell\Associations\UrlAssociations\https\UserChoice') as key:
        progid=winreg.QueryValueEx(key,'ProgId')[0]
    with winreg.OpenKey(winreg.HKEY_CLASSES_ROOT,progid+r'\shell\open\command') as key:
        command=winreg.QueryValue(key,None)
    shell=ctypes.windll.shell32; kernel=ctypes.windll.kernel32
    shell.CommandLineToArgvW.argtypes=[ctypes.c_wchar_p,ctypes.POINTER(ctypes.c_int)]
    shell.CommandLineToArgvW.restype=ctypes.POINTER(ctypes.c_wchar_p)
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    count=ctypes.c_int(); pointer=shell.CommandLineToArgvW(os.path.expandvars(command),ctypes.byref(count))
    if not pointer:raise OSError('Cannot parse the registered web browser command')
    try:args=[pointer[index] for index in range(count.value)]
    finally:kernel.LocalFree(pointer)
    if not args or not Path(args[0]).is_file():raise OSError('Registered browser executable is unavailable')
    substituted=False; result=[]
    for arg in args:
        if arg.lower() in ('%1','%l','%u'):
            result.append(uri);substituted=True
        elif arg!='%*':result.append(arg)
    if not substituted:result.append(uri)
    return result


def open_local_html(path):
    path=Path(path).resolve(strict=True)
    if not path.is_file() or path.suffix.lower() not in ('.html','.htm'):
        raise ValueError('Expected a local HTML report')
    uri=path.as_uri()
    if os.name=='nt':
        try:command=browser_command(uri)
        except OSError:
            command=None
            for root in (os.environ.get('PROGRAMFILES',''),os.environ.get('PROGRAMFILES(X86)','')):
                for suffix in ('Google/Chrome/Application/chrome.exe','Microsoft/Edge/Application/msedge.exe','Mozilla Firefox/firefox.exe'):
                    candidate=Path(root)/suffix
                    if candidate.is_file():command=[str(candidate),uri];break
                if command:break
            if command is None:raise OSError('No registered web browser was found')
        return subprocess.Popen(command,creationflags=subprocess.CREATE_NO_WINDOW)
    if not webbrowser.open(uri,new=2):raise OSError('The web browser could not open this report')
