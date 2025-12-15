## Модуль: parsers/whois_parser.py

Модуль для получения BGP-политик AS с Route Server через WHOIS.  
Извлекает peer AS и IP-адреса, фильтрует приватные ASN и некорректные IP.

### Регулярные выражения

- `RE_IPV4` — извлекает IPv4-адреса  
- `RE_IPV6` — извлекает IPv6-адреса  
- `RE_ASN` — извлекает номера AS  
- `RE_IMPORT_IPV4` — строки `mp-import: afi ipv4.unicast from ASxxxx at <ip>`  
- `RE_IMPORT_IPV6` — строки `mp-import: afi ipv6.unicast from ASxxxx at <ip>`  
- `RE_IMPORT_SHORT` — строки `from ASxxxx at <ip> action ...`  

---

### Функции

#### `fetch_and_parse_whois(as_number: str, rr_host: str, config: Config) -> List[Dict]`

**Описание:**  
Получает политику BGP для указанного AS с указанного RR, парсит её и возвращает список словарей с peer AS и IP.

**Аргументы:**

| Аргумент     | Тип       | Описание |
|-------------|-----------|----------|
| `as_number` | `str`     | Номер AS для запроса |
| `rr_host`   | `str`     | Хост Route Server |
| `config`    | `Config`  | Объект конфигурации с `cache_dir` |

**Возвращаемое значение:** `List[Dict]`  

**Ключи словаря:**

- `asn` — номер AS (int)  
- `peer_ip` — IP-адрес пира (str)  
- `afi` — адресное семейство: `ipv4` или `ipv6`  
- `raw` — исходная строка из WHOIS  
- `issues` — список проблем с адресом, выявленных `check_special_addresses`  

**Пример структуры возвращаемого списка:**

`[
  {"asn": 1234, "peer_ip": "192.0.2.1", "afi": "ipv4", "raw": "...", "issues": []},
  {"asn": 5678, "peer_ip": "2001:db8::1", "afi": "ipv6", "raw": "...", "issues": []}
]`

**Логика работы:**

1. Проверка кэша (`config.cache_dir`). Если файл есть, используется cached версия.  
2. Если кэша нет — выполняется WHOIS-запрос через `subprocess`.  
3. Парсинг данных через регулярные выражения (`RE_IMPORT_IPV4`, `RE_IMPORT_IPV6`, `RE_IMPORT_SHORT`).  
4. Фильтрация: приватные ASN (`is_private_asn`), некорректные IP, broadcast/network (.0/.255 для IPv4).  
5. Проверка специальных адресов с помощью `check_special_addresses`.  
6. Удаление дубликатов.  

---

### Пример использования

`from parsers.whois_parser import fetch_and_parse_whois`  
`from config import Config`  

`cfg = Config(cache_dir="cache")`  
`policies = fetch_and_parse_whois("34959", "rr.ntt.net", cfg)`  

`for p in policies:`  
`    print(p["asn"], p["peer_ip"], p["afi"])`  

---

## Модуль: comparators/bgp_comparator.py

Сравнивает политики AS с конфигурациями маршрутизаторов, выявляет несоответствия и собирает статистику.

**Основная функция:** `compare_policies_to_routers(policies, routers, config) -> (incidents, bgp_stats)`  

| Аргумент   | Тип       | Описание |
|------------|----------|----------|
| `policies` | `list`   | Список политик AS |
| `routers`  | `list`   | Список маршрутизаторов |
| `config`   | `Config` | Объект конфигурации |

**Возвращаемое значение:**  
- `incidents` — список инцидентов  
- `bgp_stats` — словарь с суммарной статистикой BGP  

---

## Модуль: reporters/report_generator.py

Генерация отчётов в CSV, JSON и YAML.  

**Основная функция:** `write_reports(policies, incidents, config, bgp_stats)`  

| Аргумент   | Тип       | Описание |
|------------|----------|----------|
| `policies` | `list`   | Список политик AS |
| `incidents`| `list`   | Список инцидентов |
| `config`   | `Config` | Объект конфигурации |
| `bgp_stats`| `dict`   | Статистика по BGP |

**Возвращаемое значение:** `None`  

---

## utils.py

Утилиты:  
- `is_private_asn(asn)` — проверка приватного AS  
- `check_special_addresses(ip, afi)` — проверка специальных адресов (broadcast, network, reserved)  

---

## Логи

- Все модули используют `logging`  
- Информационные сообщения при использовании кэша и успешном получении данных  
- Ошибки при невозможности выполнить WHOIS-запрос или парсинг  

---

## Кэширование

- Файлы кэша создаются в `config.cache_dir`  
- Формат имени: `whois_AS{as_number}_{rr_host}.txt`  
- Повторные запросы используют кэш для ускорения работы  

---

## Лицензия

MIT License
