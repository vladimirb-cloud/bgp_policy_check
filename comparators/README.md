# BGP Comparator — Документация

Модуль для сравнения BGP-политик AS с реальными BGP-сессиями на маршрутизаторах.  
Выявляет несоответствия, собирает статистику и инциденты.

---

## Функции

### `compare_policies_to_routers(policies: List[Dict], routers_info: List[Dict], config: Config) -> Tuple[List[Dict], Dict]`

**Описание:**  
Сравнивает список политик AS (`policies`) с BGP-сессиями на маршрутизаторах (`routers_info`).  
Возвращает список инцидентов и статистику по состояниям BGP-пиров.

**Аргументы:**

| Аргумент        | Тип                | Описание |
|----------------|------------------|----------|
| `policies`      | `List[Dict]`      | Список политик AS, полученных с Route Server. Каждый словарь должен содержать `asn`, `peer_ip`, `afi` и `raw`. |
| `routers_info`  | `List[Dict]`      | Список маршрутизаторов. Каждый словарь содержит параметры подключения и имя маршрутизатора (`name`). |
| `config`        | `Config`          | Объект конфигурации проекта. Используется `config.afi_filter` для фильтрации по адресному семейству. |

**Возвращаемое значение:** `Tuple[List[Dict], Dict]`

- `incidents` — список инцидентов с полями:  
  - `router` — имя маршрутизатора  
  - `peer` — IP-сессии  
  - `issue` — тип инцидента (`neighbor_not_in_policy`, `asn_mismatch`, `session_not_established`, `policy_peer_not_present_on_router`, `neighbor_no_ip_parsed`, `ssh_failed`)  
  - `remote_as` — номер AS соседа (если есть)  
  - `expected_as` — ожидаемый AS из политики (если есть)  
  - `afi` — адресное семейство (`ipv4`, `ipv6`)  
  - `state` — состояние BGP-сессии (`Established`, `Active`, `Connect`, `Idle`)  
  - `details` — сырой текст из BGP-сессии или политики  

- `bgp_stats` — статистика BGP-сессий:  
```python
{
    "total": int,  # общее количество соседей, учитываемых в статистике
    "afi": {
        "ipv4": {
            "total": int,
            "states": {
                "Established": {"total": int, "with_policy": int, "without_policy": int},
                "Active": {"total": int, "with_policy": int, "without_policy": int},
                "Connect": {"total": int, "with_policy": int, "without_policy": int},
                "Idle": {"total": int, "with_policy": int, "without_policy": int}
            }
        },
        "ipv6": {
            "total": int,
            "states": {
                "Established": {"total": int, "with_policy": int, "without_policy": int},
                "Active": {"total": int, "with_policy": int, "without_policy": int},
                "Connect": {"total": int, "with_policy": int, "without_policy": int},
                "Idle": {"total": int, "with_policy": int, "without_policy": int}
            }
        }
    },
    "other": int  # сессии с неизвестным AFI или состоянием
}
```
---

## Логика работы

1. **Фильтрация политик:**  
   Если `config.afi_filter` установлен (`ipv4` или `ipv6`), используются только соответствующие политики.

2. **Индексирование политик:**  
   Создаётся словарь `policy_index` с ключом `(peer_ip, afi)` и значением `asn` для быстрого поиска.

3. **Сбор BGP-сессий с маршрутизаторов:**  
   - Используется функция `gather_bgp_from_router(router)`.  
   - В случае ошибки SSH соединения добавляется инцидент `ssh_failed`.

4. **Сравнение с политикой:**  
   Для каждого соседа:
   - Пропускаем если AFI не совпадает с фильтром.  
   - Проверяем наличие IP.  
   - Обновляем статистику (`total`, `with_policy`, `without_policy`) по состояниям `Established`, `Active`, `Connect`, `Idle`.  
   - Если сосед отсутствует в политике — инцидент `neighbor_not_in_policy`.  
   - Если ASN отличается — инцидент `asn_mismatch`.  
   - Если сессия не установлена (`state` не `Established`) — инцидент `session_not_established`.

5. **Проверка отсутствующих соседей:**  
   Если политика содержит peer, которого нет на маршрутизаторе, создаётся инцидент `policy_peer_not_present_on_router`.

---

## Пример использования

`from comparators.bgp_comparator import compare_policies_to_routers`  
`from config import Config`  

`cfg = Config(afi_filter="ipv4")`  
`incidents, stats = compare_policies_to_routers(policies, routers_info, cfg)`  

`for inc in incidents:`  
`    print(inc["router"], inc["peer"], inc["issue"])`  

`print(stats["afi"]["ipv4"]["states"]["Established"])`  

---

## Типы инцидентов

| Тип | Описание |
|-----|----------|
| `neighbor_not_in_policy` | Сессия есть на маршрутизаторе, но отсутствует в политике AS |
| `asn_mismatch` | ASN соседа отличается от ожидаемого из политики |
| `session_not_established` | Сессия BGP не установлена |
| `policy_peer_not_present_on_router` | Политика содержит peer, которого нет на маршрутизаторе |
| `neighbor_no_ip_parsed` | Не удалось распарсить IP соседа |
| `ssh_failed` | Не удалось подключиться к маршрутизатору через SSH |

---

## Логи

- Используется модуль `logging`.  
- Ошибки подключения или парсинга соседей логируются через `logger.error`.  
- Информационные сообщения о статистике можно логировать через `logger.info`.

---

## Зависимости

- `re` — регулярные выражения для поиска состояния BGP  
- `typing.List`, `typing.Dict`, `typing.Tuple` — аннотации типов  
- `gather_bgp_from_router` — получение BGP-сессий через SSH  
- `Config` — объект конфигурации проекта  

```yaml
bgp_stats — структура статистики BGP-сессий

total: int  # общее количество соседей, учитываемых в статистике
afi:
  ipv4:
    total: int  # количество IPv4-сессий
    states:
      Established:
        total: int           # общее количество соседей в состоянии Established
        with_policy: int     # количество соседей, соответствующих политике
        without_policy: int  # количество соседей, отсутствующих в политике
      Active:
        total: int
        with_policy: int
        without_policy: int
      Connect:
        total: int
        with_policy: int
        without_policy: int
      Idle:
        total: int
        with_policy: int
        without_policy: int
  ipv6:
    total: int  # количество IPv6-сессий
    states:
      Established:
        total: int
        with_policy: int
        without_policy: int
      Active:
        total: int
        with_policy: int
        without_policy: int
      Connect:
        total: int
        with_policy: int
        without_policy: int
      Idle:
        total: int
        with_policy: int
        without_policy: int
other: int  # сессии с неизвестным AFI или состоянием
```