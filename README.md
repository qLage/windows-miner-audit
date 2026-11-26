# Windows Miner Audit

**Русский / English**

[Русская инструкция](README.ru.md) · [English guide](README.en.md) · [Проверки / Verification](VERIFICATION.md)

## Русский

**Проверка подозрительной активности Windows с объяснением каждой находки.**

[English documentation](README.en.md) · [Главная / Home](README.md) · Python 3.10+ · Windows 10/11 · Без сторонних Python-библиотек

Лёгкая утилита для первичной проверки, созданная по мотивам реального поиска замаскированных майнеров, вредоносных задач и изменений защиты. Создаёт красивый автономный HTML-отчёт и JSON. Работает только на чтение: не удаляет файлы, не завершает процессы, не меняет настройки защиты и не отправляет данные.

> Это эвристическая проверка, а не антивирус. Отсутствие совпадений не гарантирует отсутствие заражения. Намеренно запущенный майнер тоже может попасть в отчёт; настройки нужно оценивать в контексте.

## Быстрый запуск

1. Установите Python 3.10 или новее с [python.org](https://www.python.org/downloads/windows/), добавив Python в PATH.
2. Скачайте репозиторий и распакуйте его в отдельную папку.
3. Запустите `Start-Audit.cmd` двойным щелчком либо откройте терминал в этой папке:

```powershell
python audit.py --lang ru
```

Откройте HTML-файл по выведенному пути. Отчёты сохраняются в `reports/`, каждый запуск создаёт новые файлы. Для доступа к защищённым процессам и настройкам можно открыть терминал от имени администратора. Если что-то прочитать нельзя, результат будет **incomplete**, а ограничения будут перечислены в отчёте.

PowerShell запускается с обходом политики выполнения только для своего процесса. Постоянная политика Windows не меняется. Отключать антивирус для работы программы не нужно.

## Что проверяется

| Область | Признаки | Как понимать |
|---|---|---|
| Процессы | Одновременно адрес пула и параметры настройки майнинга | Сильный признак майнинга; уточните, разрешён ли он |
| Подмена имени | Знакомое имя, нетипичная доступная для записи папка и недоверенная подпись | Совокупность подозрительных признаков |
| Автозапуск | Задачи планировщика и Run/RunOnce с известными шаблонами подозрительных путей или командами майнинга | Отключённые записи отмечаются как неактивные; название папки не освобождает работающий процесс от проверки |
| Defender | Обычные исключения и исключения политик; защита в реальном времени, скриптов, от подделки | Широкие исключения требуют проверки |
| Hosts | Действующие перенаправления защитных сайтов и обновлений | Возможна намеренная фильтрация; комментарии пропускаются |
| Разрешения папок | Явные запреты записи в папки ряда антивирусов | Могут мешать установке; автоматического сброса нет |
| Удалённый доступ | Настройка RDP и прослушивание порта 3389 | Сведения о доступе, а не доказательство заражения |
| Диски | Менее 2 ГБ свободного места на локальном диске | Возможная причина тормозов и ошибок установки |

Отдельная неподписанная программа, Steam, VPN или высокая загрузка CPU не объявляются вирусом. Программа не исследует пароли, профили браузеров, сетевой трафик, память ядра и все возможные способы закрепления. Она не находит все майнеры, руткиты и средства удалённого управления. Проверенные разделы и ошибки сбора видны в отчёте.

## Команды и результаты

```powershell
python audit.py --lang ru --output reports --timeout 90
python audit.py --snapshot examples/suspicious.json --output reports/demo --lang ru
python -m unittest discover -s tests -v
```

`--snapshot` проверяет готовый JSON схемы v1 вместо текущего компьютера. Пример полностью вымышленный. Тесты и анализ JSON работают также в Linux/macOS. Сбор сведений с ПК требует Windows PowerShell 5.1 и стандартных модулей CIM, ScheduledTasks, Defender и NetTCPIP.

| Код завершения | Значение |
|---|---|
| 0 | Нет активных совпадений уровня high/warning; информационные находки возможны |
| 1 | Есть активные находки для проверки |
| 2 | Неполная проверка, ошибка входных данных, таймаут или другая ошибка выполнения |

Статусы: `no_rule_matches` — нет совпадений правил, `attention` — есть находки, `incomplete` — проверка неполная. Уровень находки задаёт приоритет разбора, а не точность антивирусного вердикта. При таймауте сохраняются уже собранные разделы, если доступны; пропущенные перечисляются. Если сборщик не успел выдать ни одного контрольного результата, полноценного отчёта проверки не будет.

## Как разбирать находки

Сопоставляйте путь файла, подпись, источник установки и автозапуск. Сохраните отчёт до изменений. Если обнаружен неизвестный майнер, ограничьте ненужный сетевой доступ и получите второе мнение надёжного защитного ПО. Не удаляйте подряд системные файлы и не сбрасывайте все разрешения папок. Корпоративная политика, другой антивирус и настройки приватности могут объяснять часть предупреждений.

Отчёты локальные, без внешних изображений, скриптов и аналитики. Типичные секреты командной строки и имена в стандартных путях профилей скрываются, но **это не полная анонимизация**: необычные секреты, названия задач и нестандартные пути могут сохраниться. Перед публикацией проверьте отчёт вручную. Личные журналы и материалы расследования не следует добавлять в репозиторий.

## Разработка

`audit.py` — правила, отчёты и CLI. `collect.ps1` — сборщик, который только читает состояние Windows. Тесты проверяют обнаружение, безопасные случаи, неактивные записи, исключения политик, экранирование HTML, скрытие секретов, создание отчётов и коды завершения. CI работает в Windows и Linux; живые вирусы и права администратора для тестов не нужны.

[SECURITY.md](SECURITY.md) · Лицензия MIT · Независимый проект, не связан с Microsoft.

---

## English

**Understand suspicious Windows activity before changing anything.**

[Русский](README.ru.md) · [Bilingual home](README.md) · Python 3.10+ · Windows 10/11 · No third-party Python packages

Windows Miner Audit is a lightweight, read-only triage tool inspired by a real investigation involving disguised miners, malicious scheduled tasks, broad Defender exclusions and blocked security websites. It produces a self-contained HTML report and machine-readable JSON. It does not delete files, stop processes, change Defender settings or upload data.

> This is a heuristic audit, not an antivirus or a certificate that a computer is clean. A legitimate miner can match the mining rule. Configuration findings need human review.

## Quick start

1. Install Python 3.10 or newer from [python.org](https://www.python.org/downloads/windows/), with Python available on PATH.
2. Download or clone this repository and extract it to a folder.
3. Double-click `Start-Audit.cmd` for a Russian report, or open a terminal in this folder:

```powershell
python audit.py --lang en
```

Open the HTML path printed in the terminal. Reports are stored in `reports/`; each run uses a unique filename. A normal terminal works, but protected processes and some security settings may be inaccessible. For broader coverage, use a terminal opened as administrator. Errors remain visible as **incomplete**, never silently interpreted as a clean result.

The collector runs Windows PowerShell with a process-scoped execution-policy bypass. It does not change the machine's execution policy. Do not disable antivirus protection to run this tool.

## What it checks

| Area | Signals | Interpretation |
|---|---|---|
| Running processes | Pool endpoint **and** mining tuning arguments | Strong mining indication; verify authorization |
| Process identity | Familiar executable name, unusual writable location and untrusted signature | Corroborated impersonation heuristic |
| Persistence | Scheduled tasks and Run/RunOnce references to known suspicious path patterns or mining commands | Disabled references are informational; running processes are never exempted by a folder name |
| Defender | Effective and policy exclusions; realtime/script/tamper protection | Broad exclusions and disabled protection need review |
| Hosts | Active redirects affecting security and update domains | Could be deliberate filtering; comments are ignored |
| Folder permissions | Explicit write-deny ACLs on selected antivirus directories | Can obstruct installation; never automatically reset |
| Remote access | RDP configuration and port 3389 listener | Informational exposure, not a malware verdict |
| Storage | Local fixed drives with under 2 GB free | Possible performance or installation problem |

Rules do not classify every unsigned app, Steam subprocess, VPN driver, optimizer setting or high-CPU process as malware. The tool does not inspect passwords, browser profiles, file contents across the disk, network payloads, kernel memory or all possible persistence methods. It does not detect every miner, rootkit or remote-access tool. Reports show coverage and collection errors.

## CLI and results

```powershell
python audit.py --lang ru --output reports --timeout 90
python audit.py --snapshot examples/suspicious.json --output reports/demo --lang en
python -m unittest discover -s tests -v
```

`--snapshot` analyzes an existing schema-v1 JSON instead of the live computer. The included example is entirely synthetic. Offline analysis and tests also run on Linux/macOS; live collection requires Windows PowerShell 5.1 with the standard CIM, ScheduledTasks, Defender and NetTCPIP modules.

| Exit code | Meaning |
|---|---|
| 0 | No active high/warning rule matches; informational findings may exist |
| 1 | Active findings need review |
| 2 | Collection incomplete, invalid input, timeout or another execution failure |

`status` is `no_rule_matches`, `attention` or `incomplete`. Severity is a review priority, not an antivirus confidence score. A timed-out collector preserves completed sections when available; missing sections are explicitly listed. A collector that fails before the first checkpoint cannot produce an inspection report.

## Reviewing findings safely

Verify the executable path, signature, installation source and related persistence together. Preserve a report before making changes. For an unknown miner, disconnect unnecessary network access and seek a second opinion using trusted security software. Do not indiscriminately delete Windows files or reset all permissions. Corporate policy, another antivirus or privacy choices can explain some findings.

Reports stay local and have no remote images, scripts or analytics. Common command-line secrets and usernames in standard profile paths are redacted, but **redaction is incomplete by design**: custom paths, task names and unusual secret formats may remain. Review every report before sharing it. Raw investigation files and personal logs do not belong in this repository.

## Development

`audit.py` contains pure detection/reporting functions and the CLI; `collect.ps1` only reads Windows state. Tests exercise detection, benign cases, inactive references, policy exclusions, HTML escaping, redaction, report output and exit codes. CI runs on Windows and Linux. No administrator rights or live malware are required for unit tests.

For security reports, see [SECURITY.md](SECURITY.md). MIT license. Independent project; not affiliated with Microsoft.
