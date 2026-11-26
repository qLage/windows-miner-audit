"""Windows Miner Audit desktop app. Run with python gui.py or the packaged EXE."""
from __future__ import annotations
import argparse
from datetime import datetime
import json
import os
from pathlib import Path
import tempfile
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

import audit
from desktop_ui import DesktopApp, benchmark, button, card, capture_window, label, put_text, text_area
import scan_runtime

WORDS = {
    'ru': dict(local='На вашем компьютере. Без отправки файлов.', workspace='ОБЗОР СИСТЕМЫ', light='Светлая тема', dark='Тёмная тема',
        overview='Обзор', findings='Находки', history='История', title='Windows Miner Audit',
        subtitle='Смотрите, что запускается, закрепляется и меняет защиту Windows.', ready='Готов к проверке', running='Проверка выполняется',
        complete='Отчёт готов', cancelled='Проверка остановлена', failed='Не удалось завершить проверку',
        quick='Быстрая', deep='Расширенная', start='Начать проверку', stop='Остановить', export='Открыть HTML-отчёт',
        intro='Режим проверки: только чтение.',
        scope_quick='8 разделов · процессы, автозапуск, защита и настройки системы', scope_deep='14 разделов · также службы, WMI, перехваты, сеть и замер CPU',
        risk='Предупреждения', sections='Разделы', duration='Время проверки', risk_hint='активных предупреждений', sections_hint='проверено / ожидается', duration_hint='только последний запуск',
        list_title='Результаты проверки', all='Все уровни', high='Высокий приоритет', warning='Предупреждения', info='Сведения',
        search='Поиск в находках', priority='Приоритет', finding='Находка', evidence='Сведения', details='Почему это отмечено',
        empty='Начните проверку — здесь появятся реальные результаты.', selected='Выберите находку, чтобы увидеть причину и рекомендации.',
        inactive='Неактивно', no_matches='Нет активных совпадений правил', attention='Есть сведения для проверки', incomplete='Есть ограничения доступа',
        limit='Отчёты сохраняются в папке рядом с программой.',
        collecting='Сбор: {section}', seconds='{n:.1f} с', reports='Сохранённые отчёты', timestamp='Дата', state='Результат',
        report_empty='История появится после первой завершённой проверки.', errors='Ограничения проверки', folder='Открыть папку отчётов',
        demo='Пример отчёта · вымышленные данные', error_title='Ошибка', saved='Отчёт сохранён локально',
        processes='Процессы', tasks='Планировщик задач', startup='Автозапуск', defender='Microsoft Defender', hosts='Hosts',
        acl_blocks='Разрешения папок', remote='Удалённый доступ', health='Свободное место', services='Службы', wmi='Подписки WMI',
        hijacks='Перехваты запуска', connections='Сетевые соединения', performance='Замер CPU', startup_files='Папки автозапуска'),
    'en': dict(local='On your computer. No file uploads.', workspace='SYSTEM OVERVIEW', light='Light theme', dark='Dark theme',
        overview='Overview', findings='Findings', history='History', title='Windows Miner Audit',
        subtitle='See what runs, persists and changes Windows protection.', ready='Ready to inspect', running='Inspection in progress',
        complete='Report is ready', cancelled='Inspection stopped', failed='Inspection could not finish',
        quick='Quick', deep='Extended', start='Start inspection', stop='Stop', export='Open HTML report',
        intro='Inspection mode: read-only.',
        scope_quick='8 areas · processes, startup, protection and system settings', scope_deep='14 areas · plus services, WMI, hooks, network and CPU sample',
        risk='Warnings', sections='Coverage', duration='Inspection time', risk_hint='active warnings', sections_hint='checked / expected', duration_hint='most recent inspection only',
        list_title='Inspection results', all='All priorities', high='High priority', warning='Warnings', info='Information',
        search='Search findings', priority='Priority', finding='Finding', evidence='Evidence', details='Why this was flagged',
        empty='Start an inspection to see actual results here.', selected='Select a finding to see its evidence and recommended next steps.',
        inactive='Inactive', no_matches='No active rule matches', attention='Findings need review', incomplete='Some areas were inaccessible',
        limit='Reports are saved in a folder beside the executable.',
        collecting='Collecting: {section}', seconds='{n:.1f} s', reports='Saved reports', timestamp='Date', state='Result',
        report_empty='Your first completed inspection will appear here.', errors='Inspection limitations', folder='Open reports folder',
        demo='Sample report · synthetic data', error_title='Error', saved='Report saved locally',
        processes='Processes', tasks='Scheduled tasks', startup='Startup', defender='Microsoft Defender', hosts='Hosts',
        acl_blocks='Directory permissions', remote='Remote access', health='Free storage', services='Services', wmi='WMI subscriptions',
        hijacks='Execution hooks', connections='Network connections', performance='CPU sample', startup_files='Startup folders'),
}


class AuditApp(DesktopApp):
    def __init__(self, root, storage=None, scanner=scan_runtime.scan):
        self.report = None
        self.report_path = None
        self.elapsed = None
        self.mode = 'quick'
        self.stage = ''
        self.collected = 0
        self.state_key = 'ready'
        self.cancel_event = threading.Event()
        self.scanner = scanner
        self.filter_key = 'all'
        self.search_value = ''
        self.demo = False
        super().__init__(root, 'WindowsMinerAudit', WORDS, storage)
        self.render()

    def render(self):
        p = self.shell('Miner Audit', '', [self.t('overview'), self.t('findings'), self.t('history')])
        if self.nav == 2:
            self.render_history(p)
            return
        label(p, self.t('title'), self.p, 21, True).pack(anchor='w')
        tk.Frame(p,bg=self.p['bg'],height=16).pack()
        hero = card(p, self.p, padx=22, pady=14)
        hero.pack(fill='x', pady=(0, 20))
        row = tk.Frame(hero, bg=self.p['card']); row.pack(fill='x')
        dot = label(row, '●  '+self.t(self.state_key), self.p, 13, True)
        dot.configure(fg=self.p['accent'] if not self.busy else self.p['blue'])
        dot.pack(side='left')
        for mode, title in [('deep', 'deep'), ('quick', 'quick')]:
            control = button(row, self.t(title), lambda m=mode: self.set_mode(m), self.p, primary=self.mode == mode)
            control.configure(state='disabled' if self.busy else 'normal', pady=6)
            control.pack(side='right', padx=(8, 0))
        label(hero, self.t('intro'), self.p, 10, muted=True, wraplength=780).pack(anchor='w', pady=(8, 6))
        label(hero, self.t('scope_'+self.mode), self.p, 9, muted=True).pack(anchor='w')
        controls = tk.Frame(hero, bg=self.p['card']); controls.pack(fill='x', pady=(12, 0))
        self.start_button = button(controls, self.t('stop' if self.busy else 'start'), self.cancel if self.busy else self.start, self.p, True)
        self.start_button.pack(side='left')
        export = button(controls, self.t('export'), self.open_report, self.p)
        export.configure(state='normal' if self.report_path else 'disabled')
        export.pack(side='left', padx=(10, 0))
        self.stage_label = label(controls, self.stage_text(), self.p, 9, muted=True, wraplength=300)
        self.stage_label.pack(side='right', padx=(12, 0))
        self.progress = ttk.Progressbar(hero, mode='determinate', maximum=14 if self.mode == 'deep' else 8)
        self.progress['value'] = self.collected
        if self.busy:
            self.progress.pack(fill='x', pady=(15, 0))
        findings = self.report['findings'] if self.report else []
        active = sum(f['active'] and f['severity'] != 'info' for f in findings)
        coverage = self.report['coverage'] if self.report else {}
        count = (sum(v=='complete' for v in self.report['coverage_details'].values()) if self.report and 'coverage_details' in self.report
                 else sum(coverage.values()) if self.report else self.collected)
        expected = len(coverage) if self.report else (14 if self.mode == 'deep' else 8)
        self.metrics(p, [(self.t('risk'), active if self.report else '—', self.t('risk_hint')),
                         (self.t('sections'), f'{count} / {expected}' if count or self.report else '—', self.t('sections_hint')),
                         (self.t('duration'), self.t('seconds', n=self.elapsed) if self.elapsed is not None else '—', self.t('duration_hint'))])
        foot = self.t('demo') if self.demo else self.t('limit')
        label(p, foot, self.p, 9, muted=True, wraplength=870).pack(side='bottom',anchor='w',pady=(13,0))
        panel = card(p, self.p); panel.pack(fill='both', expand=True)
        toolbar = tk.Frame(panel, bg=self.p['card']); toolbar.pack(fill='x', padx=16, pady=13)
        label(toolbar, self.t('list_title'), self.p, 11, True).pack(side='left')
        self.filter_box = ttk.Combobox(toolbar, values=[self.t(k) for k in ('all','high','warning','info')], state='readonly', width=20)
        self.filter_box.set(self.t(self.filter_key)); self.filter_box.pack(side='right')
        self.filter_box.bind('<<ComboboxSelected>>', self.change_filter)
        self.search = tk.StringVar(value=self.search_value)
        search = tk.Entry(toolbar, textvariable=self.search, bg=self.p['field'], fg=self.p['text'],
                          insertbackground=self.p['text'], relief='flat', font=('Segoe UI', 10), width=14)
        search.pack(side='right', padx=10, ipady=6)
        label(toolbar,self.t('search'),self.p,9,muted=True).pack(side='right')
        self.search.trace_add('write', lambda *_: self.refresh_table())
        self.details = text_area(panel, self.p, height=3)
        self.tree = self.table(panel, [('priority', self.t('priority'), 155), ('finding', self.t('finding'), 460)], heights=3)
        self.tree.bind('<<TreeviewSelect>>', self.select_finding)
        for severity, color in [('high','red'), ('warning','amber'), ('info','muted')]:
            self.tree.tag_configure(severity, foreground=self.p[color])
        put_text(self.details, self.t('selected') if self.report else self.t('empty'))
        self.refresh_table()

    def stage_text(self):
        if self.busy:
            return self.t('collecting', section=self.words[self.language].get(self.stage, self.stage or '…'))
        if self.report:
            return self.t({'incomplete':'incomplete','attention':'attention','no_rule_matches':'no_matches'}[self.report['status']])
        return ''

    def set_mode(self, mode):
        if not self.busy:
            self.mode = mode
            self.render()

    def change_filter(self, _=None):
        self.filter_key = ('all','high','warning','info')[self.filter_box.current()]
        self.refresh_table()

    def refresh_table(self):
        if not hasattr(self, 'tree') or not self.tree.winfo_exists():
            return
        self.search_value = self.search.get()
        self.tree.delete(*self.tree.get_children())
        for index, finding in enumerate(self.report['findings'] if self.report else []):
            if self.filter_key != 'all' and finding['severity'] != self.filter_key:
                continue
            if self.search_value.casefold() not in (' '.join(finding['evidence'])+' '+finding['title'][self.language]).casefold():
                continue
            severity = self.t(finding['severity']) if finding['active'] else self.t('inactive')
            self.tree.insert('', 'end', iid=str(index), values=(severity, finding['title'][self.language]), tags=(finding['severity'],))
        if self.report and self.report['errors']:
            put_text(self.details, self.t('errors')+'\n'+'\n'.join(audit.localize_error(e, self.language) for e in self.report['errors']))

    def select_finding(self, _=None):
        selected = self.tree.selection()
        if not selected or not self.report:
            return
        item = self.report['findings'][int(selected[0])]
        put_text(self.details, item['title'][self.language]+'\n\n'+item['advice'][self.language]+'\n\n'+'\n'.join(item['evidence']))

    def start(self):
        if self.busy:
            return
        self.busy = True; self.demo = False; self.state_key = 'running'; self.stage = 'processes'; self.collected = 0
        self.report=None; self.report_path=None; self.elapsed=None
        self.cancel_event = threading.Event()
        mode = self.mode
        self.render()
        def run():
            started = time.monotonic()
            try:
                snapshot = self.scanner(mode == 'deep', self.cancel_event, self.events.put, timeout=150 if mode == 'deep' else 90)
                if snapshot is None:
                    self.events.put(dict(type='cancelled'))
                else:
                    report = audit.analyze(snapshot)
                    self.events.put(dict(type='finished', report=report, elapsed=time.monotonic()-started))
            except Exception as error:
                self.events.put(dict(type='error', message=audit.redact(error)))
        self.worker=threading.Thread(target=run, daemon=True, name='on-demand-inspection')
        self.worker.start()

    def cancel(self):
        self.cancel_event.set()

    def close(self):
        self.closed=True; self.cancel()
        if hasattr(self,'worker') and self.worker.is_alive():
            self.worker.join(4)
        self.root.destroy()

    def handle_event(self, event):
        kind = event['type']
        if kind in ('coverage','progress'):
            if kind == 'coverage':
                self.collected = event['count']
            else:
                self.stage = event['section']
            if self.nav != 2:
                self.progress['value'] = self.collected
                self.stage_label.configure(text=self.stage_text())
            return
        self.busy = False
        if kind == 'finished':
            self.report = event['report']; self.elapsed = event['elapsed']; self.state_key = 'complete'
            self.report['duration_seconds']=self.elapsed
            self.collected = sum(self.report['coverage'].values())
            try:
                folder = self.storage / 'reports'; folder.mkdir(parents=True, exist_ok=True)
                path = folder / ('audit-'+datetime.now().strftime('%Y%m%d-%H%M%S-%f'))
                path.with_suffix('.json').write_text(json.dumps(self.report, ensure_ascii=False, indent=2), encoding='utf-8')
                self.report_path = path.with_suffix('.html')
                self.report_path.write_text(audit.render_html(self.report, self.language), encoding='utf-8')
            except OSError as error:
                self.report_path=None
                messagebox.showerror(self.t('error_title'),str(error),parent=self.root)
        elif kind == 'cancelled':
            self.state_key = 'cancelled'
        elif kind == 'error':
            self.state_key = 'failed'
            self.render()
            messagebox.showerror(self.t('error_title'), audit.localize_error(event['message'], self.language), parent=self.root)
            return
        self.render()

    def open_report(self):
        if self.report_path and self.report:
            self.report_path.write_text(audit.render_html(self.report, self.language), encoding='utf-8')
            os.startfile(self.report_path)

    def render_history(self, parent):
        label(parent, self.t('reports'), self.p, 23, True).pack(anchor='w', pady=(0, 20))
        panel = card(parent, self.p); panel.pack(fill='both', expand=True)
        self.history_paths = sorted((self.storage / 'reports').glob('audit-*.json'), reverse=True)[:100]
        tree = self.table(panel, [('date',self.t('timestamp'),210),('state',self.t('state'),480)], heights=12)
        for index, path in enumerate(self.history_paths):
            try:
                report = json.loads(path.read_text(encoding='utf-8'))
                key = {'incomplete':'incomplete','attention':'attention','no_rule_matches':'no_matches'}[report['status']]
                tree.insert('', 'end', iid=str(index), values=(report['generated_utc'][:19].replace('T',' ')+' UTC', self.t(key)))
            except (OSError, ValueError, KeyError):
                continue
        def load(_):
            if tree.selection():
                path = self.history_paths[int(tree.selection()[0])]
                self.report = json.loads(path.read_text(encoding='utf-8'))
                self.elapsed=self.report.get('duration_seconds')
                self.report_path = path.with_suffix('.html'); self.nav = 1; self.state_key = 'complete'; self.render()
        tree.bind('<Double-1>', load)
        label(parent, self.t('report_empty') if not self.history_paths else self.t('saved'), self.p, 10, muted=True).pack(anchor='w', pady=15)
        def folder():
            path = self.storage / 'reports'; path.mkdir(parents=True, exist_ok=True); os.startfile(path)
        button(parent, self.t('folder'), folder, self.p).pack(anchor='w')


def self_test(artifacts):
    artifacts = Path(artifacts); artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as storage:
        root = tk.Tk(); app = AuditApp(root, storage=storage)
        fixture = json.loads((Path(__file__).parent / 'examples/suspicious.json').read_text(encoding='utf-8'))
        app.report = audit.analyze(fixture); app.state_key = 'complete'; app.elapsed = 4.2; app.demo = True
        checked = []
        for language in ('ru', 'en'):
            for theme in ('dark', 'light'):
                app.language=language; app.theme=theme; app.render(); root.update()
                assert app.start_button.winfo_ismapped()
                assert app.details.winfo_ismapped()
                assert app.tree.get_children()
                app.tree.selection_set(app.tree.get_children()[0]); app.select_finding()
                assert app.details.get('1.0','end').strip()
                capture_window(root, artifacts / f'audit-{language}-{theme}.png')
                checked.append(f'{language}/{theme}')
        app.select_nav(2); root.update(); app.select_nav(0)
        app.filter_key='info'; app.refresh_table(); assert not app.tree.get_children()
        root.geometry('1000x740'); root.update()
        for widget in (app.start_button,app.details,app.language_box,app.theme_button):
            assert widget.winfo_ismapped()
            assert widget.winfo_rooty()+widget.winfo_height() <= root.winfo_rooty()+root.winfo_height()
        app.language_box.set('Русский'); app.language_box.event_generate('<<ComboboxSelected>>'); root.update()
        assert app.language=='ru'
        old=app.theme; app.theme_button.invoke(); root.update(); assert app.theme!=old
        def fake_scanner(deep,cancel,notify,timeout):
            notify(dict(type='coverage',count=8))
            return fixture
        app.scanner=fake_scanner; app.filter_key='all'; app.start_button.invoke()
        deadline=time.monotonic()+5
        while app.busy and time.monotonic()<deadline:
            root.update(); time.sleep(.02)
        assert not app.busy and app.report_path.is_file()
        app.select_nav(2); root.update(); assert app.history_paths
        app.select_nav(0)
        def cancellable(deep,cancel,notify,timeout):
            cancel.wait(3)
            return None
        app.scanner=cancellable; app.start_button.invoke(); app.cancel()
        deadline=time.monotonic()+5
        while app.busy and time.monotonic()<deadline:
            root.update(); time.sleep(.02)
        assert app.state_key=='cancelled' and not app.busy
        app.close()
    return dict(ok=True, views=checked, languages=2, themes=2,minimum_layout=True,start_cancel=True,history=True,language_theme_controls=True)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--self-test', action='store_true')
    parser.add_argument('--artifacts', type=Path, default=Path('gui-artifacts'))
    parser.add_argument('--benchmark',type=Path)
    args = parser.parse_args()
    if args.self_test:
        result=self_test(args.artifacts)
        (args.artifacts/'self-test.json').write_text(json.dumps(result),encoding='utf-8')
        if __import__('sys').stdout is not None:print(json.dumps(result))
        return
    root = tk.Tk(); app=AuditApp(root)
    if args.benchmark:benchmark(app,args.benchmark)
    else:root.mainloop()


if __name__ == '__main__':
    main()
