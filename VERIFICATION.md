# Проверка / Verification

## Русский

Проверены инструкции, локальные ссылки Markdown и кодировка UTF-8 в русском, английском и общем README. Тесты отдельно проверяют справку, вывод консоли и HTML-отчёт с `--lang ru` и `--lang en`, включая создание отчёта из вымышленного примера. Названия правил и поля JSON сохраняют стабильные машинные идентификаторы на английском.

```powershell
python -m unittest discover -s tests -v
python audit.py --lang ru --help
python audit.py --lang en --help
python audit.py --snapshot examples/suspicious.json --lang ru --output reports/ru
python audit.py --snapshot examples/suspicious.json --lang en --output reports/en
```

Для примера ожидается код завершения `1`: это обнаруженные признаки в тестовом JSON, а не ошибка программы. Сбор с реального Windows-ПК также проверен; недоступные защищённые процессы отражаются как ограничение. Технические сообщения самой ОС могут сохранять исходный язык. Проверка не доказывает отсутствие всех угроз.

## English

The Russian, English and combined README files are checked for UTF-8 integrity and working local Markdown links. Tests independently exercise help, console output and HTML reports with `--lang ru` and `--lang en`, including report generation from a synthetic fixture. JSON fields and rule names keep stable English machine identifiers.

Run the same commands above. The synthetic example intentionally exits with code `1`, indicating findings rather than execution failure. Live Windows collection was also checked; inaccessible protected processes are recorded as a coverage limitation. Native OS diagnostics may retain their original language. These checks do not prove the absence of all threats.
