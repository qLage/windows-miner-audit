# Методы проверки / Detection methods

## Русский

Программа сопоставляет команды процессов, параметры майнинга, подписи ограниченного набора файлов, автозапуск и изменения защиты. Расширенная проверка добавляет службы, WMI, перехваты запуска, папки автозапуска и корреляцию сети/CPU.

Направления проверки соответствуют областям, описанным в [Microsoft Sysinternals Autoruns](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns). Autoruns не включён в программу, его полный набор возможностей не повторяется, обращения к VirusTotal не выполняются.

Исследование [Microsoft о кампании GPU-майнинга](https://www.microsoft.com/en-us/security/blog/2026/05/26/poisoned-search-results-gpu-mining-cryptojacking-campaign-abusing-screenconnect-microsoft-net-utilities/) показывает, почему одного имени файла недостаточно: майнинг может сочетаться с подменой программ и злоупотреблением легитимными компонентами. Это основание искать совокупность признаков, а не блокировать все неподписанные файлы.

Командные признаки сверены с документацией [XMRig](https://xmrig.com/docs/miner/command-line-options) и исходным репозиторием [T-Rex](https://github.com/trexminer/T-Rex). Это индикаторы майнинга, а не доказательство его несанкционированности. Конфигурационные файлы, переименование, внедрение в процесс и другие протоколы могут скрыть признаки.

PowerShell Base64-команды разбираются как UTF-16LE согласно [документации Microsoft](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_powershell_exe). Вход ограничен 65 536 символами Base64, текст не исполняется. Прочие способы обфускации не покрываются полностью.

Лимит расширенной проверки подписей — 40 уникальных путей из доступных для записи папок. Секундный замер CPU не является мониторингом и может пропустить кратковременную активность. Порт без дополнительного признака недоверенного процесса не повышает приоритет.

Скрытые в ядре угрозы нельзя исключить такой проверкой работающей Windows. [Microsoft Defender Offline](https://learn.microsoft.com/en-us/defender-endpoint/microsoft-defender-offline) использует отдельную доверенную среду. Его запуск и возможная перезагрузка остаются решением пользователя. Программа не перезагружает ПК, не удаляет файлы и не меняет настройки антивируса.

## English

The engine correlates process commands, mining options, bounded signature checks, persistence and protection settings. Extended mode adds services, WMI, launch hooks, startup folders and network/CPU correlations.

These areas follow categories described by Microsoft Autoruns, linked above. Autoruns itself is not bundled or invoked, its full feature set is not replicated and no VirusTotal requests are made. Microsoft's GPU-mining campaign analysis illustrates why filenames and legitimate component names alone are insufficient.

Command heuristics were checked against the original XMRig documentation and T-Rex repository above. Mining indicators do not establish authorization. Configuration-only mining, renamed binaries, injection and different protocols may evade them. Conventional PowerShell Base64 commands are decoded as UTF-16LE text only, capped at 65,536 encoded characters; decoded content is never executed.

Extended mode verifies at most 40 distinct writable-location executable paths. The one-second CPU sample is not monitoring and can miss intermittent activity. A port match alone is insufficient. Kernel-level concealment cannot be ruled out by this tool. Defender Offline uses a separate trusted environment; its launch and any reboot remain the user's choice. This app never deletes files, restarts Windows or changes antivirus settings.
