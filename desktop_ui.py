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
from tkinter import font as tkfont
import zlib

PALETTES = {
    'dark': dict(bg='#111113', side='#17171b', card='#202025', field='#29292f', line='#35353d',
                 text='#f3f3f7', muted='#a2a2b2', hover='#34343e', accent='#68e0b6', ink='#092a21',
                 red='#ff939c', amber='#f4c574', blue='#90baff', selected='#283e50'),
    'light': dict(bg='#f3f4f7', side='#ffffff', card='#ffffff', field='#edeff4', line='#e0e3eb',
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
        from ctypes import wintypes
        user=ctypes.windll.user32; dwm=ctypes.windll.dwmapi
        user.GetAncestor.argtypes=[wintypes.HWND,wintypes.UINT];user.GetAncestor.restype=wintypes.HWND
        dwm.DwmSetWindowAttribute.argtypes=[wintypes.HWND,wintypes.DWORD,ctypes.c_void_p,wintypes.DWORD]
        hwnd=user.GetAncestor(root.winfo_id(),2)
        value = ctypes.c_int(bool(dark))
        ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, 20, ctypes.byref(value), 4)
        for attribute, color in ((35, 0x1b1717 if dark else 0xf7f4f3), (36, 0xf7f3f3 if dark else 0x3f2819)):
            native_color=ctypes.c_uint(color)
            ctypes.windll.dwmapi.DwmSetWindowAttribute(hwnd, attribute, ctypes.byref(native_color), 4)
    except (AttributeError, OSError):
        pass


def label(parent, text, palette, size=10, bold=False, muted=False, **kwargs):
    return tk.Label(parent, text=text, bg=parent.cget('bg'), fg=palette['muted' if muted else 'text'],
                    font=('Segoe UI', size, 'bold' if bold else 'normal'), anchor='w', **kwargs)


def round_shape(canvas,x1,y1,x2,y2,radius,**kwargs):
    r=min(radius,(x2-x1)/2,(y2-y1)/2)
    return canvas.create_polygon(x1+r,y1,x2-r,y1,x2,y1,x2,y1+r,x2,y2-r,x2,y2,x2-r,y2,
        x1+r,y2,x1,y2,x1,y2-r,x1,y1+r,x1,y1,smooth=True,splinesteps=24,**kwargs)


class RoundedButton(tk.Canvas):
    def __init__(self,parent,text,command,palette,primary=False,width=None,anchor='center',active=False):
        self.palette=palette;self.primary=primary;self.command=command;self.text=text;self.state='normal'
        self.padx=18;self.pady=10;self.hovered=False;self.focused=False;self.anchor=anchor;self.active=active
        self.font=tkfont.Font(family='Segoe UI',size=10,weight='bold')
        self.minimum_width=(width or 0)*8
        super().__init__(parent,bg=parent.cget('bg'),highlightthickness=0,bd=0,takefocus=1,cursor='hand2')
        self.bind('<Configure>',lambda _:self.draw())
        self.bind('<Enter>',lambda _:self.hover(True));self.bind('<Leave>',lambda _:self.hover(False))
        self.bind('<Button-1>', self.press)
        self.bind('<ButtonRelease-1>', self.release)
        self.bind('<KeyRelease-space>',lambda _:self.invoke());self.bind('<KeyRelease-Return>',lambda _:self.invoke())
        self.bind('<FocusIn>',lambda _:self.show_focus(True));self.bind('<FocusOut>',lambda _:self.show_focus(False))
        self.pressed = False
        self.last_paint = None
        self.resize()

    def resize(self):
        super().configure(width=max(self.minimum_width,self.font.measure(self.text)+self.padx*2),height=self.font.metrics('linespace')+self.pady*2)
        self.draw()

    def configure(self,cnf=None,**kwargs):
        if isinstance(cnf,dict):kwargs.update(cnf)
        resized=False
        for key in ('text','command','state','padx','pady','active','primary'):
            if key in kwargs:
                value = kwargs.pop(key)
                if key in ('text','padx','pady') and getattr(self,key) != value:
                    resized = True
                setattr(self,key,value)
        if kwargs:super().configure(**kwargs)
        if resized:self.resize()
        else:self.draw()
    config=configure

    def cget(self,key):
        if key in ('state','text','command'):return getattr(self,key)
        return super().cget(key)

    def invoke(self):
        if self.state!='disabled' and self.command:return self.command()

    def press(self, _):
        if self.state != 'disabled':
            self.focus_set()
            self.pressed = True

    def release(self, event):
        pressed, self.pressed = self.pressed, False
        if pressed and 0 <= event.x < self.winfo_width() and 0 <= event.y < self.winfo_height():
            self.invoke()

    def hover(self,value):self.hovered=value;self.draw()
    def show_focus(self,value):self.focused=value;self.draw()

    def draw(self):
        if not self.winfo_exists():return
        p=self.palette;disabled=self.state=='disabled'
        fill=p['field'] if disabled else p['accent'] if self.primary else p['selected'] if self.active else p['hover'] if self.hovered else p['field']
        foreground=p['muted'] if disabled else p['ink'] if self.primary else p['accent'] if self.active else p['text']
        w=self.winfo_width()
        if w < 2:
            w=int(super().cget('width'))
        h=int(super().cget('height'))
        paint=(w,h,fill,foreground,self.focused,self.text)
        if paint == self.last_paint:
            return
        self.last_paint=paint
        self.delete('all')
        round_shape(self,1,1,w-1,h-1,10,fill=fill,outline=p['accent'] if self.focused and not disabled else '')
        self.create_text(self.padx if self.anchor=='w' else w/2,h/2,text=self.text,font=self.font,fill=foreground,anchor=self.anchor)


def button(parent,text,command,palette,primary=False,width=None):
    return RoundedButton(parent,text,command,palette,primary,width)


def card(parent, palette, **kwargs):
    frame=tk.Frame(parent,bg=palette['card'],bd=0,**kwargs)
    previous=[None]
    def clip(event):
        if os.name!='nt' or (event.width,event.height)==previous[0] or event.width<30 or event.height<30:return
        previous[0]=(event.width,event.height)
        from ctypes import wintypes
        gdi=ctypes.windll.gdi32;user=ctypes.windll.user32
        gdi.CreateRoundRectRgn.restype=wintypes.HANDLE
        gdi.CreateRoundRectRgn.argtypes=[ctypes.c_int]*6
        user.SetWindowRgn.argtypes=[wintypes.HWND,wintypes.HANDLE,wintypes.BOOL]
        region=gdi.CreateRoundRectRgn(0,0,event.width+1,event.height+1,28,28)
        if not user.SetWindowRgn(frame.winfo_id(),region,True):gdi.DeleteObject(region)
    frame.bind('<Configure>',clip)
    return frame


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
        self.shell_frame = None
        self.shell_theme = None
        self.body = None
        root.title('Vortex Helper' if purple else 'Windows Miner Audit')
        icon_path=Path(__file__).with_name('assets')/'icon.png'
        if icon_path.is_file():
            self.icon=tk.PhotoImage(file=str(icon_path))
            root.iconphoto(True,self.icon)
        root.geometry('1190x820')
        root.minsize(1000, 740)
        root.protocol('WM_DELETE_WINDOW', self.close)
        root.bind('<Map>', lambda event: windows_setup(root, self.theme == 'dark') if event.widget == root else None)
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
        if self.shell_frame is None or self.shell_theme != self.theme:
            self.build_shell(brand, navigation)
        self.theme_button.configure(text=self.t('light' if self.theme == 'dark' else 'dark'))
        for language, control in self.language_buttons.items():
            control.configure(primary=language == self.language)
        for index, control in enumerate(self.nav_buttons):
            control.configure(text=navigation[index], active=index == self.nav)
        if self.body is not None:
            self.body.destroy()
        self.body = tk.Frame(self.main, bg=self.p['bg'])
        self.body.pack(fill='both', expand=True)
        return self.body

    def build_shell(self, brand, navigation):
        if self.shell_frame is not None:
            self.shell_frame.destroy()
        self.apply_palette()
        self.shell_theme = self.theme
        self.body = None
        p = self.p
        self.shell_frame = tk.Frame(self.root, bg=p['bg'])
        self.shell_frame.pack(fill='both', expand=True)
        side = tk.Frame(self.shell_frame, bg=p['side'], width=206)
        side.pack(side='left', fill='y')
        side.pack_propagate(False)
        mark = tk.Canvas(side, width=44, height=44, bg=p['side'], highlightthickness=0)
        mark.pack(anchor='w', padx=24, pady=(30, 12))
        round_shape(mark,1,1,43,43,12,fill=p['accent'],outline='')
        mark.create_text(22,22,text='VH' if self.purple else 'MA',fill=p['ink'],font=('Segoe UI',12,'bold'))
        label(side, brand, p, 14, True).pack(anchor='w', padx=24,pady=(0,28))
        self.nav_buttons = []
        for index, title in enumerate(navigation):
            active = index == self.nav
            nav=RoundedButton(side,title,lambda i=index:self.select_nav(i),p,anchor='w',active=active)
            nav.pack(fill='x', padx=12, pady=3)
            self.nav_buttons.append(nav)
        bottom = tk.Frame(side, bg=p['side'])
        bottom.pack(side='bottom', fill='x', padx=24, pady=25)
        label(bottom, 'v0.2.2', p, 9, bold=True, muted=True).pack(anchor='w')
        self.main = tk.Frame(self.shell_frame, bg=p['bg'])
        self.main.pack(side='left', fill='both', expand=True, padx=28, pady=18)
        top = tk.Frame(self.main, bg=p['bg'])
        top.pack(fill='x', pady=(0, 14))
        label(top,self.root.title(),p,20,True).pack(side='left')
        self.theme_button = button(top, self.t('light' if self.theme == 'dark' else 'dark'), self.toggle_theme, p)
        self.theme_button.pack(side='right', padx=(10, 0))
        self.language_switch = card(top, dict(p, card=p['field']), padx=3, pady=3)
        self.language_switch.pack(side='right')
        self.language_buttons = {}
        for language in ('ru', 'en'):
            control = button(self.language_switch, language.upper(), lambda lang=language: self.set_language(lang), p, width=5)
            control.configure(padx=7, pady=7)
            control.pack(side='left', padx=1)
            self.language_buttons[language] = control

    def metrics(self, parent, items):
        row = tk.Frame(parent, bg=self.p['bg'])
        row.pack(fill='x', pady=(0, 20))
        values = []
        for index, (heading, value, caption) in enumerate(items):
            row.columnconfigure(index, weight=1, uniform='metric')
            box = card(row, self.p, padx=17, pady=9)
            box.grid(row=0,column=index,sticky='nsew',padx=(0 if index == 0 else 10, 0))
            label(box, heading, self.p, 9, muted=True).pack(anchor='w')
            value_label = label(box, str(value), self.p, 21, True)
            value_label.pack(anchor='w', pady=(4, 0))
            values.append(value_label)
            label(box, caption, self.p, 9, muted=True).pack(anchor='w')
        return values

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
        if language == self.language:
            return
        self.language = language
        self.save_settings()
        self.render()

    def toggle_theme(self):
        self.theme = 'light' if self.theme == 'dark' else 'dark'
        self.save_settings()
        self.render()
        self.theme_button.focus_set()

    def select_nav(self, index):
        if index == self.nav:
            return
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
