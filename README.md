# BGP Policy Checker

BGP Policy Checker — инструмент для проверки соответствия BGP-политик на маршрутизаторах с опубликованными политиками AS на Route Server (RR). Скрипт загружает политики, анализирует их и генерирует отчёты в текстовом, JSON или YAML формате.

---

## Особенности

- Получение политики AS с Route Server через WHOIS-запросы  
- Сравнение политик с реальными настройками маршрутизаторов  
- Поддержка фильтрации по адресным семействам (AFI): `ipv4`, `ipv6` или `all`  
- Генерация отчётов в формате CSV, JSON и YAML  
- Ведение логов выполнения в файл и консоль  

---

## Установка

1. Клонируйте репозиторий:  

`git clone https://github.com/yourusername/bgp-policy-checker.git`  
`cd bgp_policy_check`  

2. Установите зависимости (если есть `requirements.txt`):  

`pip install -r requirements.txt`  

---

## Использование

Запуск скрипта через командную строку:  

`python -m bgp_policy_check.main [OPTIONS]`  

### Аргументы

- `--as-number` — номер AS для запроса политики с RR, по умолчанию `34959`  
- `--routers` — путь к CSV файлу с информацией о маршрутизаторах, по умолчанию `bgp_policy_check/router.csv`  
- `--output-dir` — папка для отчетов и логов, по умолчанию `bgp_policy_check/reports`  
- `--rr-host` — хост Route Server для запроса, по умолчанию `rr.ntt.net`  
- `--json-report` — генерация отчета в JSON формате, по умолчанию `False`  
- `--yaml-report` — генерация отчета в YAML формате, по умолчанию `False`  
- `--afi` — фильтр по адресному семейству: `ipv4`, `ipv6` или `all`, по умолчанию `all`  

### Пример запуска

`python -m bgp_policy_check.main --as-number 12345 --afi ipv4 --json-report`  

---

## Структура проекта

- `bgp_policy_check/`  
  - `main.py` — главный скрипт для запуска проверки  
  - `config.py` — класс конфигурации  
  - `parsers/`  
    - `whois_parser.py` — модуль для получения и парсинга WHOIS данных  
  - `comparators/`  
    - `bgp_comparator.py` — модуль для сравнения политик с настройками маршрутизаторов  
  - `reporters/`  
    - `report_generator.py` — модуль для генерации отчетов  

---

## Логи и отчеты

- Все логи записываются в файл `bgp_policy_check.log` в указанной папке отчётов  
- Отчеты создаются в формате CSV по умолчанию  
- JSON и YAML отчеты генерируются, если указаны соответствующие флаги  

---

## Основные функции

- `setup_logging(output_dir)` — создаёт логгер и пишет логи в консоль и файл  
- `read_routers_csv(path)` — читает CSV-файл с данными о маршрутизаторах и возвращает список словарей  
- `fetch_and_parse_whois(as_number, rr_host, config)` — получает политику с Route Server и парсит её  
- `compare_policies_to_routers(policies, routers, config)` — сравнивает политики с конфигурациями маршрутизаторов, возвращает инциденты и статистику  
- `write_reports(policies, incidents, config, bgp_stats)` — генерирует отчеты в CSV, JSON и YAML форматах  

---

## Лицензия

MIT License
