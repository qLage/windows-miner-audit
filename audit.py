#!/usr/bin/env python3
"""Read-only Windows audit. Python standard library only."""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import html
import ipaddress
import json
from pathlib import Path
import re
import subprocess
import sys

VERSION = '0.1.0'
SEVERITIES = {'high': 0, 'warning': 1, 'info': 2}
EXPECTED_SECTIONS = {'processes', 'tasks', 'startup', 'defender', 'hosts', 'acl_blocks', 'remote', 'health'}
SUSPICIOUS_PATH = re.compile(r'\\(?:WindowsTask|ReaItekHD|Windows Tasks Service)\\', re.I)
MASQUERADE = {'audiodg.exe', 'taskhost.exe', 'taskhostw.exe', 'winlogon.exe',
              'svchost.exe', 'microsofthost.exe', 'apphost.exe', 'steamwebhelper.exe'}
SECURITY_DOMAINS = ('download.microsoft.com', 'update.microsoft.com', 'windowsupdate.microsoft.com',
                    'security.microsoft.com', 'defender.microsoft.com', 'wdcp.microsoft.com',
                    'wdcpalt.microsoft.com', 'definitionupdates.microsoft.com',
                    'windowsupdate.com', 'defender.com', 'malwarebytes.com',
                    'kaspersky.com', 'kaspersky.ru', 'avast.com', 'avira.com', 'eset.com',
                    'drweb.com', 'drweb.ru', 'norton.com', 'mcafee.com', 'bitdefender.com')


def redact(value: object) -> str:
    """Reduce accidental disclosure; reports can still contain private paths and names."""
    text = str(value)
    text = re.sub(r'(?i)((?:--(?:cc-access-token|token|password|api-key|apikey|wallet|user)|-[up])\s*[= ]\s*)("[^"]*"|\S+)', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)((?:https?|stratum\+(?:tcp|ssl))://)[^\s/@:]+:[^\s/@]+@', r'\1[REDACTED]@', text)
    text = re.sub(r'(?i)([?&](?:token|key|password|auth)=)[^&\s]+', r'\1[REDACTED]', text)
    text = re.sub(r'(?i)([A-Z]:\\Users\\)[^\\\s"]+', r'\1<user>', text)
    return text[:1400]


def miner_command(command: str) -> bool:
    pool = re.search(r'(?:^|\s)(?:-o|--url|--pool)(?:[=\s])|stratum\+(?:tcp|ssl)://', command, re.I)
    tuning = re.search(r'--(?:cpu-max-threads-hint|donate-level|randomx|algo|coin|cpu-priority|cc-url)(?:[=\s])', command, re.I)
    return bool(pool and tuning)


def risky_path(path: str) -> bool:
    return bool(re.search(r'\\(?:ProgramData|AppData|Temp|Users\\Default(?: User)?)\\', path, re.I))


def analyze(snapshot: dict) -> dict:
    if not isinstance(snapshot, dict) or snapshot.get('schema_version') != 1:
        raise ValueError('Unsupported snapshot: schema_version must be 1')
    findings = []
    errors = [redact(e) for e in snapshot.get('errors', [])]
    for section in EXPECTED_SECTIONS:
        if section not in snapshot:
            errors.append(f'Missing collection section: {section}')
    for section in ('processes', 'tasks', 'startup', 'hosts', 'acl_blocks', 'health'):
        if not isinstance(snapshot.get(section, []), list):
            raise ValueError(f'{section} must be an array')
    for section in ('defender', 'remote'):
        if not isinstance(snapshot.get(section, {}), dict):
            raise ValueError(f'{section} must be an object')
    for section in ('processes', 'tasks', 'startup', 'acl_blocks', 'health'):
        if any(not isinstance(row, dict) for row in snapshot.get(section, [])):
            raise ValueError(f'{section} entries must be objects')
    for key in ('paths', 'policy_paths', 'extensions', 'policy_extensions'):
        if not isinstance(snapshot.get('defender', {}).get(key, []), list):
            raise ValueError(f'defender.{key} must be an array')
    if not isinstance(snapshot.get('errors', []), list):
        raise ValueError('errors must be an array')

    def add(rule, severity, en, ru, evidence, advice_en, advice_ru, active=True):
        findings.append(dict(rule=rule, severity=severity, active=active,
                             title={'en': en, 'ru': ru}, evidence=[redact(v) for v in evidence],
                             advice={'en': advice_en, 'ru': advice_ru}))

    for proc in snapshot.get('processes', []):
        path, command = str(proc.get('path') or ''), str(proc.get('command') or '')
        evidence = [f'PID {proc.get("pid", "?")}: {path}', command]
        if miner_command(command):
            add('miner-command', 'high', 'Running process has mining pool and tuning options',
                'У процесса есть параметры пула и настройки майнинга', evidence,
                'Verify whether you intentionally run a miner. Preserve evidence before stopping an unknown process.',
                'Проверьте, запускали ли вы майнер сами. Сохраните сведения перед остановкой неизвестного процесса.')
        name = path.replace('/', '\\').rsplit('\\', 1)[-1].lower()
        if proc.get('signature') in ('NotSigned', 'HashMismatch', 'NotTrusted') and risky_path(path) and (name in MASQUERADE or SUSPICIOUS_PATH.search(path)):
            add('process-masquerade', 'high', 'Untrusted executable imitates a familiar process',
                'Недоверенный файл имитирует знакомый процесс', evidence[:1] + [f'Signature: {proc.get("signature")}'],
                'Check the file publisher, installation source and related startup entries. An unsigned file alone does not prove malware.',
                'Проверьте издателя, источник установки и автозапуск. Отсутствие подписи само по себе не доказывает заражение.')

    for kind in ('tasks', 'startup'):
        for entry in snapshot.get(kind, []):
            command = str(entry.get('command') or '')
            if not (SUSPICIOUS_PATH.search(command) or miner_command(command)):
                continue
            active = entry.get('enabled') is not False
            add('suspicious-persistence', 'high' if active else 'info',
                'Suspicious startup reference' if active else 'Inactive suspicious startup reference',
                'Подозрительная запись автозапуска' if active else 'Неактивная подозрительная запись автозапуска',
                [kind, entry.get('name', ''), command],
                'Inspect the target and task state. A disabled reference is not evidence of a running infection.',
                'Проверьте цель и состояние задачи. Отключённая запись не означает активное заражение.', active)

    defender = snapshot.get('defender', {})
    for key in ('paths', 'policy_paths', 'extensions', 'policy_extensions'):
        for exclusion in defender.get(key, []):
            value = str(exclusion).replace('/', '\\').rstrip('\\').lower()
            broad = bool(re.fullmatch(r'[a-z]:', value) or re.fullmatch(r'[a-z]:\\(?:users|programdata|windows)', value)
                         or re.fullmatch(r'[a-z]:\\users\\[^\\]+', value)
                         or value in {'exe', '.exe', '*.exe', '*', '*.*'}
                         or value.endswith('\\system32\\config\\systemprofile'))
            if broad:
                add('defender-broad-exclusion', 'high', 'Broad antivirus exclusion', 'Слишком широкое исключение антивируса',
                    [key, exclusion], 'Review effective settings AND policy exclusions. Confirm the source before narrowing an exclusion.',
                    'Проверьте действующие настройки И политики исключений. Уточните источник перед изменением исключения.')
    for key, en, ru in (
        ('realtime_enabled', 'Real-time protection is disabled', 'Защита в реальном времени отключена'),
        ('script_scanning_enabled', 'Script scanning is disabled', 'Проверка скриптов отключена'),
    ):
        if defender.get(key) is False:
            add('defender-protection', 'warning', en, ru, [f'{key}=False'],
                'Check whether another antivirus or an intentional policy explains this setting.',
                'Проверьте, связано ли это с другим антивирусом или намеренной политикой.')
    if defender.get('tamper_protected') is False:
        add('defender-tamper', 'warning', 'Tamper protection is off', 'Защита от подделки отключена',
            ['IsTamperProtected=False'], 'Review Windows Security settings; this alone is not evidence of malware.',
            'Проверьте настройки «Безопасности Windows»; это само по себе не признак заражения.')
    if defender.get('cloud_reporting') == 0:
        add('defender-cloud', 'info', 'Cloud reporting is disabled', 'Отправка облачных отчётов отключена',
            ['MAPSReporting=0'], 'May be an intentional privacy preference. Do not enable sample uploads without consent.',
            'Это может быть настройкой конфиденциальности. Не включайте отправку образцов без согласия.')

    for line in snapshot.get('hosts', []):
        content = str(line).split('#', 1)[0].strip().split()
        if len(content) < 2:
            continue
        try:
            address = ipaddress.ip_address(content[0])
        except ValueError:
            continue
        for domain in content[1:]:
            domain = domain.lower().rstrip('.')
            if any(domain == base or domain.endswith('.' + base) for base in SECURITY_DOMAINS):
                add('security-hosts-redirect', 'warning', 'Security or update website overridden in hosts',
                    'Адрес защитного сайта или обновлений переопределён в hosts', [f'{address} {domain}'],
                    'Check whether this is intentional filtering. Back up hosts before editing; unrelated entries should be preserved.',
                    'Уточните, намеренная ли это фильтрация. Перед правкой сохраните hosts и оставьте остальные записи.')

    for block in snapshot.get('acl_blocks', []):
        add('security-directory-deny', 'warning', 'Explicit write denial on a security product directory',
            'Явный запрет записи в папку защитного продукта',
            [block.get('path', ''), block.get('identity', ''), block.get('rights', '')],
            'Compare with the product installer and your administrator policy. Do not reset all directory permissions.',
            'Сверьте с установщиком продукта и политиками администратора. Не сбрасывайте все разрешения папки.')
    remote = snapshot.get('remote', {})
    if remote.get('rdp_enabled') or remote.get('rdp_listening'):
        add('rdp-exposure', 'info', 'Remote Desktop is enabled or listening', 'Удалённый рабочий стол включён или слушает порт',
            [f'Enabled: {remote.get("rdp_enabled")}; port 3389: {remote.get("rdp_listening")}'],
            'Confirm this is needed. Remote access is a configuration finding, not a malware verdict.',
            'Уточните, нужен ли удалённый вход. Это настройка доступа, а не вердикт о вредоносной программе.')
    for disk in snapshot.get('health', []):
        if disk.get('free_gb') is not None and disk['free_gb'] < 2:
            add('disk-space', 'warning', 'Drive is critically low on free space', 'Критически мало свободного места',
                [f'{disk.get("drive")}: {disk["free_gb"]} GB free'],
                'Review large files and application storage. Do not delete unfamiliar system files.',
                'Проверьте крупные файлы и хранилища приложений. Не удаляйте незнакомые системные файлы.')
    findings.sort(key=lambda item: SEVERITIES[item['severity']])
    attention = any(f['active'] and f['severity'] != 'info' for f in findings)
    return dict(schema_version=1, version=VERSION, generated_utc=datetime.now(timezone.utc).isoformat(),
                status='incomplete' if errors else ('attention' if attention else 'no_rule_matches'),
                findings=findings, errors=errors,
                coverage={section: section in snapshot for section in sorted(EXPECTED_SECTIONS)})


def render_html(report: dict, lang: str) -> str:
    ru = lang == 'ru'
    esc = html.escape
    cards = []
    for item in report['findings']:
        cards.append('<article class="' + item['severity'] + '"><span class="badge">' + esc(item['severity'])
                     + (' · неактивно' if ru and not item['active'] else ' · inactive' if not item['active'] else '')
                     + '</span><h2>' + esc(item['title'][lang]) + '</h2><pre>'
                     + esc('\n'.join(item['evidence'])) + '</pre><p>' + esc(item['advice'][lang])
                     + '</p><small>' + esc(item['rule']) + '</small></article>')
    errors = ''.join('<li>' + esc(error) + '</li>' for error in report['errors'])
    heading = 'Проверка Windows' if ru else 'Windows audit'
    intro = ('Локальный отчёт • Только чтение • Без отправки данных' if ru else 'Local report • Read-only inspection • No data uploads')
    limitation = ('Эвристическая проверка, не замена антивирусу. Отсутствие совпадений не доказывает, что компьютер чист.' if ru else
                  'A heuristic audit, not an antivirus replacement. No matches do not prove that the computer is clean.')
    return f'''<!doctype html><html lang="{lang}"><meta charset="utf-8"><meta name="viewport" content="width=device-width">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>{heading} · Miner Audit</title><style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#101521;color:#e8edf7;font:16px/1.6 system-ui,sans-serif}}
main{{max-width:1000px;margin:auto;padding:48px 24px}}header{{border-bottom:1px solid #334155;padding-bottom:24px}}h1{{font-size:42px;margin:8px 0}}
h2{{font-size:21px;margin:12px 0}}.sub,small{{color:#aebbd0}}.summary{{display:flex;gap:16px;flex-wrap:wrap;margin:28px 0}}
.summary div{{background:#1d2738;padding:16px 24px;border-radius:12px}}article{{margin:18px 0;padding:24px;background:#192233;border-radius:12px;border-left:4px solid #6ba9ff}}
article.high{{border-color:#ff7b87}}article.warning{{border-color:#f9c66e}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#101827;padding:14px;border-radius:8px;font-size:13px}}
.badge{{font-size:12px;text-transform:uppercase;letter-spacing:1px}}aside{{background:#282338;border-radius:12px;padding:20px}}footer{{margin:32px 0;color:#aebbd0}}</style>
<main><header><div class="sub">WINDOWS MINER AUDIT / {VERSION}</div><h1>{heading}</h1><p>{intro}</p></header>
<div class="summary"><div>Status: <strong>{esc(report['status'])}</strong></div><div>{'Находки' if ru else 'Findings'}: <strong>{len(report['findings'])}</strong></div>
<div>{'Ошибки сбора' if ru else 'Collection errors'}: <strong>{len(report['errors'])}</strong></div></div>
<aside>{limitation}</aside>{''.join(cards)}<h2>{'Ограничения сбора' if ru else 'Collection limitations'}</h2><ul>{errors or '<li>—</li>'}</ul>
<footer>{esc(report['generated_utc'])} · UTC · {'Отчёт может содержать личные пути. Проверьте перед публикацией.' if ru else 'Reports may contain private paths. Review before sharing.'}</footer></main></html>'''


def collect(timeout: int) -> dict:
    if sys.platform != 'win32':
        raise RuntimeError('Live collection requires Windows. Use --snapshot for offline analysis.')
    powershell = Path(__import__('os').environ['SystemRoot']) / 'System32/WindowsPowerShell/v1.0/powershell.exe'
    try:
        completed = subprocess.run([str(powershell), '-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass',
                                    '-File', str(Path(__file__).with_name('collect.ps1'))],
                                   capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired as error:
        snapshot = decode_collector(error.stdout or b'')
        snapshot.setdefault('errors', []).append('Collection timed out; remaining sections were not checked.')
        return snapshot
    if completed.returncode:
        raise RuntimeError('Windows collector failed: ' + redact(completed.stderr.decode('utf-8', errors='replace')))
    try:
        return decode_collector(completed.stdout)
    except (ValueError, UnicodeError) as error:
        raise RuntimeError('Collector did not return valid UTF-8 JSON') from error


def decode_collector(data: bytes) -> dict:
    for line in reversed(data.decode('utf-8-sig', errors='replace').splitlines()):
        try:
            value = json.loads(line)
        except ValueError:
            continue
        if isinstance(value, dict) and value.get('schema_version') == 1:
            return value
    raise RuntimeError('Collector returned no usable snapshot; inspection did not complete.')


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--snapshot', type=Path, help='Analyze an existing schema v1 JSON instead of this PC')
    parser.add_argument('--output', type=Path, default=Path('reports'))
    parser.add_argument('--lang', choices=['ru', 'en'], default='en')
    parser.add_argument('--timeout', type=int, default=90)
    parser.add_argument('--version', action='version', version=VERSION)
    args = parser.parse_args(argv)
    try:
        snapshot = json.loads(args.snapshot.read_text(encoding='utf-8-sig')) if args.snapshot else collect(args.timeout)
        report = analyze(snapshot)
        args.output.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now().strftime('%Y%m%d-%H%M%S-%f')
        base = args.output / f'audit-{stamp}'
        base.with_suffix('.json').write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding='utf-8')
        base.with_suffix('.html').write_text(render_html(report, args.lang), encoding='utf-8')
        print(f'{report["status"]}: {len(report["findings"])} findings, {len(report["errors"])} collection errors')
        print(base.with_suffix('.html').resolve())
        return 2 if report['errors'] else 1 if report['status'] == 'attention' else 0
    except (OSError, RuntimeError, ValueError, subprocess.TimeoutExpired) as error:
        print('Audit failed / Проверка не завершена: ' + redact(error), file=sys.stderr)
        return 2


if __name__ == '__main__':
    raise SystemExit(main())
