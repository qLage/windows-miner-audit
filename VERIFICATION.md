# Проверка / Verification

## Русский

Версия 0.2.1 проверена из исходников и как portable EXE: русский/английский, тёмная/светлая тема, минимальный размер окна, настоящие переключатели языка/темы, запуск и отмена проверки, история и сохранение отчётов. Снимки интерфейса содержат помеченные вымышленные данные.

Модульные тесты проверяют признаки CPU/GPU-майнинга, текстовое декодирование PowerShell, службы, WMI, перехваты, сеть/CPU, безопасные случаи, неполную проверку, скрытие типичных секретов, экранирование HTML, UTF-8, ссылки README и команды CLI на обоих языках.

```powershell
python -m unittest discover -s tests -v
python gui.py --self-test --artifacts gui-artifacts
python gui.py --benchmark gui-artifacts/idle.json
```

Самопроверка GUI использует имитацию сборщика. Живой сбор Windows проверен отдельно, включая расширенный режим; недоступные защищённые процессы отражаются как неполное покрытие. `--benchmark` измеряет только покой окна: время, CPU одного ядра и рабочую память процесса. Результаты зависят от компьютера и состояния Windows.

## English

Version 0.2.1 was tested from source and as a portable EXE: Russian/English, dark/light themes, minimum window size, actual language/theme controls, start/cancel, report history and saved output. Screenshots contain clearly marked synthetic data.

Unit tests cover CPU/GPU mining indicators, text-only PowerShell decoding, services, WMI, hooks, network/CPU correlations, benign cases, partial coverage, common-secret redaction, HTML escaping, UTF-8, README links and CLI commands in both languages.

Run the commands above. GUI self-test uses a simulated collector. Live Windows collection was checked separately, including extended mode; inaccessible protected processes remain explicit partial coverage. The benchmark records idle elapsed time, single-core CPU percentage and process working-set memory. Results vary by machine and Windows state.
