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
from browser_open import open_local_html

WORDS = {
    'ru': dict(local='На вашем компьютере. Без отправки файлов.', workspace='ОБЗОР СИСТЕМЫ', light='Светлая тема', dark='Тёмная тема',
        overview='Проверка', findings='Находки', history='Отчёты', title='Windows Miner Audit',show='Показать',
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
        overview='Inspection', findings='Findings', history='Reports', title='Windows Miner Audit',show='Show report',
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
    def __init__(self, root, storage=None, scanner=scan_runtime.scan, browser_open=open_local_html):
        self.report = None
        self.report_path = None
        self.elapsed = None
        self.mode = 'quick'
        self.stage = ''
        self.collected = 0
        self.state_key = 'ready'
        self.cancel_event = threading.Event()
        self.scanner = scanner
        self.browser_open=browser_open
        self.filter_key = 'all'
        self.search_value = ''
        self.demo = False
        super().__init__(root, 'WindowsMinerAudit', WORDS, storage)
        self.load_latest()
        self.render()

    def read_report(self,path):
        report=json.loads(Path(path).read_text(encoding='utf-8'))
        if not isinstance(report,dict) or report.get('status') not in ('incomplete','attention','no_rule_matches') or not isinstance(report.get('findings'),list) or not isinstance(report.get('coverage'),dict):
            raise ValueError('Unsupported saved report')
        for item in report['findings']:
            if not isinstance(item,dict) or item.get('severity') not in ('high','warning','info') or not isinstance(item.get('active'),bool):
                raise ValueError('Unsupported saved finding')
            for key in ('title','advice'):
                if not isinstance(item.get(key),dict) or not all(isinstance(item[key].get(language),str) for language in ('ru','en')):
                    raise ValueError('Unsupported finding translation')
            if not isinstance(item.get('evidence'),list) or any(not isinstance(value,str) for value in item['evidence']):
                raise ValueError('Unsupported finding evidence')
        if not isinstance(report.get('errors',[]),list):raise ValueError('Unsupported report errors')
        return report

    def load_latest(self):
        for path in sorted((self.storage/'reports').glob('audit-*.json'),reverse=True):
            try:
                self.report=self.read_report(path);self.report_path=path.with_suffix('.html')
                self.elapsed=self.report.get('duration_seconds');self.state_key='complete'
                self.mode='deep' if self.report.get('scan_mode')=='deep' else 'quick'
                return
            except (OSError,ValueError,KeyError,TypeError):continue

    def render(self):
        p = self.shell('Miner Audit', '', [self.t('overview'), self.t('history')])
        if self.nav == 1:
            self.render_history(p)
            return
        hero = card(p, self.p, padx=22, pady=14)
        hero.pack(fill='x', pady=(0, 20))
        row = tk.Frame(hero, bg=self.p['card']); row.pack(fill='x')
        self.status_label = label(row, '', self.p, 13, True)
        self.status_label.pack(side='left')
        self.mode_buttons = {}
        for mode, title in [('deep', 'deep'), ('quick', 'quick')]:
            control = button(row, self.t(title), lambda m=mode: self.set_mode(m), self.p, primary=self.mode == mode)
            control.configure(state='disabled' if self.busy else 'normal', pady=6)
            control.pack(side='right', padx=(8, 0))
            self.mode_buttons[mode] = control
        label(hero, self.t('intro'), self.p, 10, muted=True, wraplength=780).pack(anchor='w', pady=(8, 6))
        self.scope_label = label(hero, '', self.p, 9, muted=True)
        self.scope_label.pack(anchor='w')
        controls = tk.Frame(hero, bg=self.p['card']); controls.pack(fill='x', pady=(12, 0))
        self.start_button = button(controls, self.t('stop' if self.busy else 'start'), self.cancel if self.busy else self.start, self.p, True)
        self.start_button.pack(side='left')
        self.export_button = button(controls, self.t('export'), self.open_report, self.p)
        self.export_button.configure(state='normal' if self.report else 'disabled')
        self.export_button.pack(side='left', padx=(10, 0))
        self.stage_label = label(controls, self.stage_text(), self.p, 9, muted=True, wraplength=300)
        self.stage_label.pack(side='right', padx=(12, 0))
        progress_slot = tk.Frame(hero, bg=self.p['card'], height=5)
        progress_slot.pack(fill='x', pady=(12, 0))
        progress_slot.pack_propagate(False)
        self.progress = ttk.Progressbar(progress_slot, mode='determinate')
        self.metric_labels = self.metrics(p, [(self.t('risk'), '—', self.t('risk_hint')),
                         (self.t('sections'), '—', self.t('sections_hint')),
                         (self.t('duration'), '—', self.t('duration_hint'))])
        self.foot_label = label(p, '', self.p, 9, muted=True, wraplength=870)
        self.foot_label.pack(side='bottom',anchor='w',pady=(13,0))
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
        self.search.trace_add('write', self.schedule_search)
        self.details = text_area(panel, self.p, height=3)
        self.tree = self.table(panel, [('priority', self.t('priority'), 155), ('finding', self.t('finding'), 460)], heights=3)
        self.tree.bind('<<TreeviewSelect>>', self.select_finding)
        for severity, color in [('high','red'), ('warning','amber'), ('info','muted')]:
            self.tree.tag_configure(severity, foreground=self.p[color])
        self.update_inspection(refresh_findings=True)

    def update_inspection(self, refresh_findings=False):
        self.status_label.configure(text='●  '+self.t(self.state_key),
            fg=self.p['blue'] if self.busy else self.p['accent'])
        for mode, control in self.mode_buttons.items():
            control.configure(primary=mode == self.mode, state='disabled' if self.busy else 'normal')
        self.scope_label.configure(text=self.t('scope_'+self.mode))
        self.start_button.configure(text=self.t('stop' if self.busy else 'start'), command=self.cancel if self.busy else self.start)
        self.export_button.configure(state='normal' if self.report else 'disabled')
        expected = 14 if self.mode == 'deep' else 8
        self.progress.configure(maximum=expected, value=self.collected)
        if self.busy:
            self.progress.pack(fill='both', expand=True)
        else:
            self.progress.pack_forget()
        self.stage_label.configure(text=self.stage_text())
        self.foot_label.configure(text=self.t('demo' if self.demo else 'limit'))
        if self.report:
            active = sum(f['active'] and f['severity'] != 'info' for f in self.report['findings'])
            coverage = self.report['coverage']
            details = self.report.get('coverage_details')
            count = sum(value == 'complete' for value in details.values()) if details else sum(coverage.values())
            values = (str(active), f'{count} / {len(coverage)}', self.t('seconds', n=self.elapsed) if self.elapsed is not None else '—')
        else:
            values = ('—', f'{self.collected} / {expected}' if self.busy else '—', '—')
        for widget, value in zip(self.metric_labels, values):
            widget.configure(text=value)
        if refresh_findings:
            put_text(self.details, self.t('selected') if self.report else self.t('empty'))
            self.refresh_table()

    def schedule_search(self, *_):
        self.search_value = self.search.get()
        pending = getattr(self, 'search_job', None)
        if pending:
            self.root.after_cancel(pending)
        tree = self.tree
        def refresh():
            self.search_job = None
            if tree.winfo_exists():
                self.refresh_table()
        self.search_job = self.root.after(110, refresh)

    def stage_text(self):
        if self.busy:
            return self.t('collecting', section=self.words[self.language].get(self.stage, self.stage or '…'))
        if self.report:
            return self.t({'incomplete':'incomplete','attention':'attention','no_rule_matches':'no_matches'}[self.report['status']])
        return ''

    def set_mode(self, mode):
        if not self.busy:
            self.mode = mode
            self.update_inspection()

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
        self.update_inspection(refresh_findings=True)
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
        self.closed=True
        self.root.withdraw()
        self.cancel()
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
            if self.nav == 0:
                self.progress['value'] = self.collected
                self.stage_label.configure(text=self.stage_text())
                self.metric_labels[1].configure(text=f'{self.collected} / {int(self.progress["maximum"])}')
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
            messagebox.showerror(self.t('error_title'), audit.localize_error(event['message'], self.language), parent=self.root)
        if self.nav == 0:
            self.update_inspection(refresh_findings=True)
        elif kind == 'finished':
            self.render()

    def open_report(self):
        if not self.report:return
        try:
            if not self.report_path:
                folder=self.storage/'reports';folder.mkdir(parents=True,exist_ok=True)
                self.report_path=folder/'report.html'
            self.report_path.write_text(audit.render_html(self.report, self.language), encoding='utf-8')
            return self.browser_open(self.report_path)
        except (OSError,ValueError) as error:
            messagebox.showerror(self.t('error_title'),str(error),parent=self.root)

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
        def load(_=None):
            if tree.selection():
                path = self.history_paths[int(tree.selection()[0])]
                self.report = self.read_report(path)
                self.elapsed=self.report.get('duration_seconds')
                self.report_path = path.with_suffix('.html'); self.nav = 0; self.state_key = 'complete'; self.render()
        tree.bind('<Double-1>', load)
        if tree.get_children():tree.selection_set(tree.get_children()[0])
        label(parent, self.t('report_empty') if not self.history_paths else self.t('saved'), self.p, 10, muted=True).pack(anchor='w', pady=15)
        def folder():
            path = self.storage / 'reports'; path.mkdir(parents=True, exist_ok=True); os.startfile(path)
        actions=tk.Frame(parent,bg=self.p['bg']);actions.pack(fill='x')
        button(actions,self.t('show'),load,self.p,True).pack(side='left')
        def open_saved():
            if tree.selection():
                path=self.history_paths[int(tree.selection()[0])]
                self.report=self.read_report(path);self.report_path=path.with_suffix('.html')
                self.open_report()
        button(actions,self.t('export'),open_saved,self.p).pack(side='left',padx=10)
        button(actions, self.t('folder'), folder, self.p).pack(side='left')


def self_test(artifacts):
    artifacts = Path(artifacts); artifacts.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as storage:
        opened=[]
        root = tk.Tk(); app = AuditApp(root, storage=storage,browser_open=lambda path:opened.append(Path(path)))
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
        app.select_nav(1); root.update(); app.select_nav(0)
        app.filter_key='info'; app.refresh_table(); assert not app.tree.get_children()
        root.geometry('1000x740'); root.update()
        for widget in (app.start_button,app.details,app.language_switch,app.theme_button):
            assert widget.winfo_ismapped()
            assert widget.winfo_rooty()+widget.winfo_height() <= root.winfo_rooty()+root.winfo_height()
        app.language_buttons['ru'].invoke(); root.update()
        assert app.language=='ru'
        old=app.theme; app.theme_button.invoke(); root.update(); assert app.theme!=old
        def fake_scanner(deep,cancel,notify,timeout):
            notify(dict(type='coverage',count=8))
            return fixture
        app.scanner=fake_scanner; app.filter_key='all'
        tree, start_button = app.tree, app.start_button
        app.start_button.invoke()
        deadline=time.monotonic()+5
        while app.busy and time.monotonic()<deadline:
            root.update(); time.sleep(.02)
        assert not app.busy and app.report_path.is_file()
        assert app.tree is tree and app.start_button is start_button
        assert app.language_buttons['ru'].primary and not app.language_buttons['en'].primary
        app.export_button.invoke();assert opened[-1]==app.report_path and opened[-1].is_file()
        app.select_nav(1); root.update(); assert app.history_paths
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
    return dict(ok=True, views=checked, languages=2, themes=2,minimum_layout=True,start_cancel=True,history=True,language_theme_controls=True,browser_button=True)


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
