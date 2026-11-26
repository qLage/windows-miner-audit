"""Small native desktop components. No web engine or runtime dependencies."""
from __future__ import annotations
import ctypes
from datetime import datetime
import json
import os
from pathlib import Path
import queue
import struct
import sys
import tkinter as tk
from tkinter import ttk
import zlib

PALETTES = {
    'dark': dict(bg='#0c121c', side='#111a27', card='#162131', field='#111b29', line='#29374b',
                 text='#eef4ff', muted='#94a6c1', hover='#22324a', accent='#68e0b6', ink='#092a21',
                 red='#ff939c', amber='#f4c574', blue='#90baff', selected='#283e50'),
    'light': dict(bg='#f1f4f9', side='#ffffff', card='#ffffff', field='#f5f7fb', line='#d9e1ed',
                  text='#19283f', muted='#60718a', hover='#e7edf7', accent='#137d60', ink='#ffffff',
                  red='#b42c45', amber='#916013', blue='#2868ae', selected='#dbeee7'),
}


def app_data(name):
    base=Path(sys.executable).resolve().parent if getattr(sys,'frozen',False) else Path(__file__).resolve().parent
    return base/(name+'-data')


def read_settings(path):
    try:
        data = json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(data, dict):
            return {}
        return {k: v for k, v in data.items() if k in {'language', 'theme', 'vortex_path'}}
    except (OSError, ValueError):
        return {}


def write_settings(path, data):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    pending = path.with_suffix('.tmp')
    pending.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    pending.replace(path)


def windows_setup(root, dark):
    if sys.platform != 'win32':
        return
    try:
        hwnd = ctypes.windll.user32.GetParent(root.winfo_id())
        value = ctypes.c_int(bool(dark))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), 4)
        for attribute, color in ((35, 0x1c120c if dark else 0xf9f4f1), (36, 0xfff4ee if dark else 0x3f2819)):
            native_color=ctypes.c_uint(color)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(native_color), 4)
    except (AttributeError, OSError):
        pass


def label(parent, text, palette, size=10, bold=False, muted=False, **kwargs):
    return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=palette['muted' if muted else 'text'],
                    font=('Segoe UI', size, 'bold' if bold else 'normal'), anchor='w', **kwargs)


def button(parent, text, command, palette, primary=False, width=None):
    kwargs = dict(text=text, command=command, font=('Segoe UI', 10, 'bold'), relief='flat', bd=0,
                  bg=palette['accent'] if primary else palette['field'],
                  fg=palette['ink'] if primary else palette['text'],
                  activebackground=palette['hover'], activeforeground=palette['text'],
                  padx=17, pady=8, cursor='hand2', takefocus=True,
                  highlightthickness=1, highlightbackground=palette['line'], highlightcolor=palette['accent'])
    if width:
        kwargs['width'] = width
    return tk.Button(parent, **kwargs)


def card(parent, palette, **kwargs):
    return tk.Frame(parent, bg=palette['card'], highlightbackground=palette['line'], highlightthickness=1, **kwargs)


def text_area(parent, palette, height=5, expand=False):
    frame = tk.Frame(parent, bg=palette['card'])
    frame.pack(side='bottom', fill='both' if expand else 'x', expand=expand)
    text = tk.Text(frame, height=height, bg=palette['card'], fg=palette['text'], font=('Segoe UI', 10),
                   insertbackground=palette['text'], relief='flat', wrap='word', padx=14, pady=10,
                   selectbackground=palette['selected'], bd=0)
    scrollbar = ttk.Scrollbar(frame, command=text.yview)
    text.configure(yscrollcommand=scrollbar.set)
    scrollbar.pack(side='right', fill='y')
    text.pack(side='left', fill='both', expand=True)
    return text


def put_text(widget, text):
    widget.configure(state='normal')
    widget.delete('1.0', 'end')
    widget.insert('1.0', text)
    widget.configure(state='disabled')


class DesktopApp:
    def __init__(self, root, name, words, storage=None, purple=False):
        self.root, self.name, self.words, self.purple = root, name, words, purple
        self.storage = Path(storage) if storage else app_data(name)
        self.settings_path = self.storage / 'settings.json'
        self.settings = read_settings(self.settings_path)
        self.language = self.settings.get('language', 'ru')
        if self.language not in ('ru', 'en'):
            self.language = 'ru'
        self.theme = self.settings.get('theme', 'dark')
        if self.theme not in PALETTES:
            self.theme = 'dark'
        self.events = queue.Queue()
        self.busy = False
        self.closed = False
        self.nav = 0
        root.title('Vortex Helper' if purple else 'Windows Miner Audit')
        icon_path=Path(__file__).with_name('assets')/'icon.png'
        if icon_path.is_file():
            self.icon=tk.PhotoImage(file=str(icon_path))
            root.iconphoto(True,self.icon)
        root.geometry('1190x820')
        root.minsize(1000, 740)
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.after(150, self.pump)

    def t(self, key, **values):
        return self.words[self.language][key].format(**values)

    def apply_palette(self):
        self.p = dict(PALETTES[self.theme])
        if self.purple:
            self.p['accent'] = '#b5a3ff' if self.theme == 'dark' else '#6750be'
            self.p['ink'] = '#21123e' if self.theme == 'dark' else '#ffffff'
            self.p['selected'] = '#34304f' if self.theme == 'dark' else '#e8e0fc'
        self.root.configure(bg=self.p['bg'])
        style = ttk.Style(self.root)
        style.theme_use('clam')
        style.configure('Treeview', background=self.p['card'], foreground=self.p['text'], fieldbackground=self.p['card'],
                        rowheight=32, font=('Segoe UI', 10), borderwidth=0, bordercolor=self.p['line'],
                        lightcolor=self.p['line'], darkcolor=self.p['line'], relief='flat')
        style.configure('Treeview.Heading', background=self.p['field'], foreground=self.p['muted'],
                        font=('Segoe UI', 9, 'bold'), relief='flat', padding=(12, 7), bordercolor=self.p['line'])
        style.map('Treeview', background=[('selected', self.p['selected'])], foreground=[('selected', self.p['text'])])
        style.configure('TCombobox', fieldbackground=self.p['field'], background=self.p['field'],
                        foreground=self.p['text'], arrowcolor=self.p['muted'], padding=7, borderwidth=0,
                        bordercolor=self.p['line'], lightcolor=self.p['line'], darkcolor=self.p['line'])
        style.map('TCombobox', fieldbackground=[('readonly', self.p['field'])], foreground=[('readonly', self.p['text'])],
                  selectbackground=[('readonly', self.p['field'])], selectforeground=[('readonly', self.p['text'])])
        style.configure('Horizontal.TProgressbar', background=self.p['accent'], troughcolor=self.p['field'],
                        borderwidth=0, thickness=4)
        style.configure('Vertical.TScrollbar', background=self.p['line'], troughcolor=self.p['card'], borderwidth=0, arrowsize=11,
                        arrowcolor=self.p['muted'], bordercolor=self.p['card'], lightcolor=self.p['card'], darkcolor=self.p['card'])
        self.root.option_add('*TCombobox*Listbox.background', self.p['field'])
        self.root.option_add('*TCombobox*Listbox.foreground', self.p['text'])
        windows_setup(self.root, self.theme == 'dark')
        self.root.after_idle(lambda: windows_setup(self.root, self.theme == 'dark'))

    def shell(self, brand, subtitle, navigation):
        for child in self.root.winfo_children():
            child.destroy()
        self.apply_palette()
        p = self.p
        side = tk.Frame(self.root, bg=p['side'], width=206)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        mark = tk.Canvas(side, width=44, height=44, bg=p['side'], highlightthickness=0)
        mark.pack(anchor='w', padx=24, pady=(30, 12))
        if self.purple:
            for offset in range(3):
                mark.create_arc(3+offset*5, 3+offset*5, 40-offset*5, 40-offset*5,
                                start=25+offset*65, extent=255, style='arc', width=3, outline=p['accent'])
        else:
            mark.create_polygon(22, 2, 40, 9, 37, 28, 22, 42, 7, 28, 4, 9, fill=p['accent'], outline='')
            mark.create_line(13, 21, 20, 28, 31, 15, fill=p['ink'], width=3)
        label(side, brand, p, 14, True).pack(anchor='w', padx=24,pady=(0,28))
        for index, title in enumerate(navigation):
            active = index == self.nav
            nav = tk.Button(side, text=('  ●  ' if active else '  ○  ')+title, command=lambda i=index: self.select_nav(i),
                            bg=p['selected'] if active else p['side'], fg=p['accent'] if active else p['muted'],
                            activebackground=p['hover'], activeforeground=p['text'], font=('Segoe UI', 10, 'bold'),
                            relief='flat', anchor='w', bd=0, padx=12, pady=13, cursor='hand2')
            nav.pack(fill='x', padx=12, pady=3)
        bottom = tk.Frame(side, bg=p['side'])
        bottom.pack(side='bottom', fill='x', padx=24, pady=25)
        label(bottom, 'v0.2.0', p, 9, bold=True, muted=True).pack(anchor='w')
        self.main = tk.Frame(self.root, bg=p['bg'])
        self.main.pack(side='left', fill='both', expand=True, padx=28, pady=18)
        top = tk.Frame(self.main, bg=p['bg'])
        top.pack(fill='x', pady=(0, 14))
        label(top, self.t('workspace'), p, 10, muted=True).pack(side='left')
        self.theme_button = button(top, self.t('light' if self.theme == 'dark' else 'dark'), self.toggle_theme, p)
        self.theme_button.pack(side='right', padx=(10, 0))
        self.language_box = ttk.Combobox(top, values=['Русский', 'English'], state='readonly', width=11, font=('Segoe UI', 10))
        self.language_box.set('Русский' if self.language == 'ru' else 'English')
        self.language_box.pack(side='right')
        self.language_box.bind('<<ComboboxSelected>>', lambda _: self.set_language('ru' if self.language_box.get() == 'Русский' else 'en'))
        return self.main

    def metrics(self, parent, items):
        row = tk.Frame(parent, bg=self.p['bg'])
        row.pack(fill='x', pady=(0, 20))
        for index, (heading, value, caption) in enumerate(items):
            box = card(row, self.p, padx=17, pady=9)
            box.pack(side='left', fill='both', expand=True, padx=(0 if index == 0 else 10, 0))
            label(box, heading, self.p, 9, muted=True).pack(anchor='w')
            label(box, str(value), self.p, 21, True).pack(anchor='w', pady=(4, 0))
            label(box, caption, self.p, 9, muted=True).pack(anchor='w')

    def table(self, parent, columns, heights=5):
        frame = tk.Frame(parent, bg=self.p['card'])
        frame.pack(fill='both', expand=True)
        tree = ttk.Treeview(frame, columns=[c[0] for c in columns], show='headings', height=heights, selectmode='browse')
        for key, heading, width in columns:
            tree.heading(key, text=heading, anchor='w')
            tree.column(key, width=width, minwidth=60, anchor='w', stretch=key == columns[-1][0])
        scroll = ttk.Scrollbar(frame, command=tree.yview)
        tree.configure(yscrollcommand=scroll.set)
        scroll.pack(side='right', fill='y')
        tree.pack(side='left', fill='both', expand=True)
        return tree

    def save_settings(self):
        self.settings.update(language=self.language, theme=self.theme)
        try:
            write_settings(self.settings_path, self.settings)
        except OSError:
            pass

    def set_language(self, language):
        if language not in ('ru', 'en'):
            raise ValueError('Unsupported language')
        self.language = language
        self.save_settings()
        self.render()

    def toggle_theme(self):
        self.theme = 'light' if self.theme == 'dark' else 'dark'
        self.save_settings()
        self.render()

    def select_nav(self, index):
        self.nav = index
        self.render()

    def pump(self):
        if self.closed:
            return
        try:
            for _ in range(40):
                self.handle_event(self.events.get_nowait())
        except queue.Empty:
            pass
        self.root.after(120 if self.busy else 600, self.pump)

    def close(self):
        self.closed = True
        self.cancel()
        self.root.destroy()


def capture_window(root, path):
    """Capture this application's own window for reproducible visual QA on Windows."""
    if sys.platform != 'win32':
        return False
    from ctypes import wintypes
    user, gdi = ctypes.windll.user32, ctypes.windll.gdi32
    user.GetParent.argtypes = [wintypes.HWND]; user.GetParent.restype = wintypes.HWND
    user.GetWindowDC.argtypes = [wintypes.HWND]; user.GetWindowDC.restype = wintypes.HDC
    gdi.CreateCompatibleDC.argtypes = [wintypes.HDC]; gdi.CreateCompatibleDC.restype = wintypes.HDC
    gdi.CreateCompatibleBitmap.argtypes = [wintypes.HDC, ctypes.c_int, ctypes.c_int]; gdi.CreateCompatibleBitmap.restype = wintypes.HBITMAP
    gdi.SelectObject.argtypes = [wintypes.HDC, wintypes.HANDLE]; gdi.SelectObject.restype = wintypes.HANDLE
    user.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    gdi.GetDIBits.argtypes = [wintypes.HDC, wintypes.HBITMAP, wintypes.UINT, wintypes.UINT, ctypes.c_void_p, ctypes.c_void_p, wintypes.UINT]
    gdi.DeleteObject.argtypes = [wintypes.HANDLE]; gdi.DeleteDC.argtypes = [wintypes.HDC]
    user.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    root.update()
    hwnd = user.GetParent(root.winfo_id()) or root.winfo_id()
    rect = wintypes.RECT(); user.GetWindowRect(hwnd, ctypes.byref(rect))
    width, height = rect.right-rect.left, rect.bottom-rect.top
    dc = user.GetWindowDC(hwnd); memory = gdi.CreateCompatibleDC(dc)
    bitmap = gdi.CreateCompatibleBitmap(dc, width, height); previous = gdi.SelectObject(memory, bitmap)
    try:
        if not user.PrintWindow(hwnd, memory, 2):
            raise OSError('Window capture failed')
        info = struct.pack('<IiiHHIIiiII', 40, width, -height, 1, 32, 0, width*height*4, 0, 0, 0, 0)
        raw = ctypes.create_string_buffer(width*height*4)
        header = ctypes.create_string_buffer(info)
        if not gdi.GetDIBits(memory, bitmap, 0, height, raw, header, 0):
            raise OSError('Bitmap extraction failed')
        pixels = raw.raw
        rows = bytearray()
        for y in range(height):
            rows.append(0)
            for x in range(width):
                at = (y*width+x)*4
                rows.extend((pixels[at+2], pixels[at+1], pixels[at]))
        def chunk(kind, data):
            return struct.pack('>I', len(data)) + kind + data + struct.pack('>I', zlib.crc32(kind+data)&0xffffffff)
        png = b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>IIBBBBB', width, height, 8, 2, 0, 0, 0))
        png += chunk(b'IDAT', zlib.compress(rows, 6)) + chunk(b'IEND', b'')
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_bytes(png)
        return True
    finally:
        gdi.SelectObject(memory, previous); gdi.DeleteObject(bitmap); gdi.DeleteDC(memory); user.ReleaseDC(hwnd, dc)


def benchmark(app, output, seconds=3):
    """Measure this app at rest. Never starts a scan or helper process."""
    import time
    from ctypes import wintypes
    class Counters(ctypes.Structure):
        _fields_=[('cb',wintypes.DWORD),('faults',wintypes.DWORD)]+[(name,ctypes.c_size_t) for name in
            ('peak','working','peak_paged','paged','peak_nonpaged','nonpaged','pagefile','peak_pagefile','private')]
    def memory():
        if os.name!='nt':return None
        counters=Counters();counters.cb=ctypes.sizeof(counters)
        get=ctypes.windll.psapi.GetProcessMemoryInfo
        get.argtypes=[wintypes.HANDLE,ctypes.POINTER(Counters),wintypes.DWORD]
        if not get(wintypes.HANDLE(-1),ctypes.byref(counters),counters.cb):return None
        return round(counters.working/1024/1024,1)
    start={}
    def begin():
        start.update(wall=time.monotonic(),cpu=time.process_time(),rss=memory())
        app.root.after(int(seconds*1000),finish)
    def finish():
        elapsed=time.monotonic()-start['wall']
        data=dict(seconds=round(elapsed,2),cpu_percent_of_one_core=round((time.process_time()-start['cpu'])/elapsed*100,3),
                  memory_rss_mb=memory(),background_worker_started=app.busy)
        Path(output).parent.mkdir(parents=True,exist_ok=True)
        Path(output).write_text(json.dumps(data,indent=2),encoding='utf-8')
        app.close()
    app.root.after(500,begin)
    app.root.mainloop()
