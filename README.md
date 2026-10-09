# Noranite

Noranite — anticensorship L3-tunnel поверх UDP без узнаваемого wire format.

Протокол реализует философию отсутствия отпечатков протокола на уровне архитектуры. **Все пакеты, с первого и до последнего байта, выглядят как высокоэнтропийный бинарный шум.**

В нём нет открытых magic bytes, версии протокола, типа пакета, session ID, sequence number или узнаваемого handshake header.

Noranite не маскируется под QUIC, DNS, HTTPS или другой разрешённый протокол. Он решает более простую задачу: **не иметь собственной фиксированной сигнатуры**, что делает блокировку протокола связанной с недопустимым коллатеральным уроном.

## Основная идея

Обычный зашифрованный протокол часто выглядит примерно так:

```text
magic
version
packet type
session id
counter
...
encrypted payload
```

Payload может быть идеально зашифрован, но открытый framing уже даёт DPI готовую сигнатуру.

У Noranite такого заголовка нет.

```text
+-------------------+------------------------------+
| opaque route      | opaque / encrypted payload   |
| 16 bytes          |                              |
+-------------------+------------------------------+
```

Первые 16 байт содержат замаскированные данные, необходимые для поиска сессии и проверки sequence number. Сами значения на проводе не присутствуют.

Остальная часть пакета также не содержит открытого типа сообщения или другой постоянной структуры.

DATA, служебные пакеты и handshake различаются только после криптографической обработки.

## Зачем вообще нужен "бинарный шум"

Смысл не в самих случайных байтах, а в том, что они лишают DPI дешёвой и точной сигнатуры. Если протокол как-то себя выдает, его можно блокировать почти без побочного ущерба. Если же packet payload неотличим от обычного encrypted UDP, остаётся либо дорогой behavioral analysis по timing, размерам и структуре flow, либо грубая блокировка широкого класса UDP-трафика вместе с HTTP/3/QUIC, WebRTC, real-time media, играми, VPN и собственными протоколами приложений.

Все, что мы даем стороннему наблюдателю - это картина "какой-то странный трафик". Но под это определение подходит большая часть UDP трафика интернета.
Чем меньше протокол сообщает о себе на wire, тем больше вычислительной работы, false positives и collateral damage требуется цензору для его блокировки.
Поведенческий анализ трафика все равно остается возможным, но Noranite - L3 tunnel, обеспечивающий мультиплексирование и размытие размеров пакетов, что значительно затрудняет даже такой анализ (USENIX Security 2024)

Noranite не делает блокировку невозможной. Он делает её **грязной и очень дорогой**.

## Что говорят исследования

Высокоэнтропийный трафик сам по себе не является нераспознаваемым: encrypted traffic можно классифицировать по размерам пакетов, timing и другим признакам потока.

Наиболее известный исследованный механизм GFW для блокировки fully-encrypted traffic работал с TCP; случайный UDP этим механизмом не блокировался, что подтверждается исследованиями USENIX 2023, 2025.  Более новые работы показывают, что GFW умеет stateful-анализ UDP и QUIC, но об использовании произвольного анализа opaque-UDP в настоящее время не известно.
Для selective blocking цензору приходится опираться на метаданные потока, репутацию IP, статистическую классификацию или более грубую политику фильтрации.

## Установка и управление

Серверный установщик рассчитан на Linux с systemd и `iptables`. Он устанавливает уже собранные бинарники из `./bin`, создаёт ключи и конфигурацию в `/etc/noranite`, настраивает `nrnt0`, forwarding/NAT и запускает сервис.

Для Debian/Ubuntu сервер можно установить одной командой:

```bash
curl -fsSL https://raw.githubusercontent.com/noranite/Noranite-l3/main/quick-install | sudo bash
```

Quick installer скачивает исходники с GitHub во временный каталог, при необходимости использует временный Go toolchain нужной версии, собирает серверные бинарники и запускает штатный installer. При первой установке он автоматически определит Internet-facing interface и попросит выбрать tunnel address, UDP port, MTU (рекомендуется не более 1380) и режим доступа к локальной сети. При повторном запуске существующие `/etc/noranite/server.env`, ключи и peers сохраняются.

Ручной вариант начинается со сборки необходимых бинарников из корня репозитория:

```bash
mkdir -p bin
go build -o bin/opaque-server ./cmd/opaque-server
go build -o bin/noranitectl ./cmd/noranitectl
go build -o bin/noranite-peer ./cmd/noranite-peer
go build -o bin/opaque-keygen ./cmd/opaque-keygen
```

Базовая установка:

```bash
sudo ./install/server/install.sh
```

По умолчанию используется tunnel `10.66.0.1/16`, UDP `0.0.0.0:41675`, MTU `1380`, а Internet-facing interface определяется по default route. При первой установке основные параметры можно задать явно:

```bash
sudo ./install/server/install.sh \
  --egress-interface eth0 \
  --tunnel-address 10.66.0.1/16 \
  --bind 0.0.0.0:41675 \
  --mtu 1380 \
  --local-access deny
```

`--local-access deny` используется по умолчанию: VPN peers получают Internet egress, но не доступ к самому VPN-серверу и локальным сетям. `--local-access allow` снимает эту дополнительную изоляцию; дальнейший доступ определяется routing/firewall самого хоста.

После установки основные файлы находятся в `/etc/noranite`:

```text
server.env       network/runtime parameters
install.state     host state needed for clean uninstall
route.key        shared K_route
server.private   server X25519 private key
server.public    server X25519 public key
server.peers     persistent bootstrap peers
```

Состояние сервиса:

```bash
sudo systemctl status noranite-server
sudo systemctl restart noranite-server
sudo journalctl -u noranite-server -f
```

Полное удаление сервера, включая ключи, persistent peers, systemd units, firewall rules и установленные бинарники:

```bash
sudo ./uninstall
```

`uninstall` просит явное подтверждение перед удалением `/etc/noranite`. Для автоматического запуска используется `sudo ./uninstall --yes`. Пакеты ОС, которые могли существовать до Noranite или использоваться другими программами, uninstall не удаляет.

### Пиры

`/etc/noranite/server.peers` загружается при каждом старте процесса. Формат строки:

```text
<tunnel-ipv4> <client-public-key> [name]
```

Например:

```text
10.66.0.2 BASE64_KEY alice
```

Пиры из файла при старте проходят через тот же runtime Controller, что и динамические операции. Если файл некорректен или содержит конфликтующие IP/ключи, сервер не стартует.

Для управления уже запущенным сервером используется локальный Unix socket `/run/noranite/control.sock` с mode `0600`. Удалённого management API нет; для удалённого администрирования достаточно SSH и `sudo noranitectl`:

```bash
sudo noranitectl peer list
sudo noranitectl peer set --ip 10.66.0.2 --public-key BASE64_KEY
sudo noranitectl peer remove --public-key BASE64_KEY
```

`peer set` идемпотентен. Повтор той же пары ничего не меняет; тот же public key с другим IP заменяет runtime peer и сбрасывает его активные sessions. IP, уже занятый другим public key, использовать нельзя.

Для обычного добавления нового клиента есть provisioning tool: он генерирует client X25519 keypair, выбирает первый свободный адрес в настроенном `/16` и добавляет peer в runtime:

```bash
sudo noranite-peer add \
  --tunnel-address 10.66.0.1/16 \
  --private-key-out ./alice.key \
  --public-key-out ./alice.pub
```

Runtime-команды не изменяют `server.peers`. Поэтому после рестарта сервер снова поднимет набор peers из этого файла; persistence/autosync, если он нужен, остаётся отдельным уровнем над runtime control plane.

## Криптография

Сессия устанавливается через:

```text
Noise_IK_25519_ChaChaPoly_BLAKE2s
```

Noise IK даёт Noranite:

- взаимную аутентификацию клиента и сервера;
- статические X25519 identities;
- forward secrecy через ephemeral X25519;
- свежие независимые ключи для каждого нового соединения.

После handshake трафик защищается ChaCha20-Poly1305.

Ключи передачи данных разделены по направлениям. Новый handshake создаёт новый независимый набор ключей.

Noise используется только для аутентификации и получения ключевого материала. Формат трафика Noranite остаётся отдельным.

## `K_route`

Помимо Noise identities обе стороны используют общий 32-байтный секрет `K_route`.

Это не ключ шифрования трафика и не Noise PSK.

`K_route` нужен для того, чтобы скрыть структуру пакета ещё **до** момента, когда получатель определил нужную сессию и получил возможность использовать её traffic key.

С его помощью маскируются:

- `session_id || sequence` в первых 16 байтах пакета;
- ephemeral X25519 public key внутри Noise handshake.

Mask привязан к конкретному пакету, поэтому одинаковые внутренние значения не дают одинакового представления на проводе.

Сам по себе `K_route` не позволяет расшифровать DATA и не раскрывает Noise private keys. Компрометация `K_route`  не ломает криптографическую защиту туннеля, но делает протокол открытым для DPI. Это осознанно: если цензор знает k_route - он знает IP. В этом случае анализ уже не требуется: намного дешевле блокировать IP.

## Handshake

Обычный Noise IK оставляет ephemeral X25519 public key открытым. Это уже достаточно структурированное значение, чтобы использовать его как часть fingerprint.

Noranite дополнительно маскирует его через keyed BLAKE2s с `K_route`.

Handshake также использует случайный padding и переменный размер пакетов.

В результате на проводе нет характерной структуры Noise IK:

```text
opaque INIT  ->
             <-  opaque RESPONSE
```

Статические identities аутентифицируются внутри Noise.

Сервер не публикует banner, protocol identifier или другую информацию, по которой его можно определить обычным UDP probe.

Случайный UDP datagram не вызывает корректный protocol response.

## DATA

Один DATA packet переносит один IPv4 packet.

В открытом виде на проводе отсутствуют:

- тип DATA;
- session ID;
- sequence number;
- inner source address;
- inner destination address;
- transport protocol внутреннего пакета.

Весь inner IPv4 packet находится внутри ChaCha20-Poly1305 ciphertext.

К пакету добавляется случайный authenticated padding, поэтому одинаковые внутренние пакеты не обязаны иметь одинаковый внешний размер.

DATA и служебный трафик используют один и тот же opaque envelope. Их тип находится внутри зашифрованной части.

## Replay protection

Каждая сессия имеет собственный монотонный sequence number и отдельное replay window.

Sequence участвует в формировании AEAD nonce и никогда не используется повторно внутри одной сессии.

Полученный пакет не может повлиять на состояние туннеля до успешной проверки:

```text
route
  ↓
candidate session
  ↓
AEAD authentication
  ↓
replay protection
  ↓
accepted packet
```

Подделка opaque route сама по себе ничего не даёт: настоящий session ID не является средством аутентификации.

## Почему этому можно доверять

Основная безопасность Noranite не строится на обфускации.

Даже если считать wire masking полностью скомпрометированным, защита трафика остаётся основана на стандартных криптографических примитивах:

- Noise IK для mutual authentication и key agreement;
- X25519 для Diffie-Hellman;
- ChaCha20-Poly1305 для authenticated encryption;
- BLAKE2s внутри Noise и для wire masking;
- независимые ключи для направлений передачи;
- fresh key material для новых сессий;
- monotonic nonces;
- replay protection.

`K_route` отвечает за то, **как протокол выглядит на проводе**.

Noise и ChaCha20-Poly1305 отвечают за то, **можно ли этому трафику доверять и можно ли его расшифровать**.

Это разные задачи и разные криптографические границы.

## Что видит DPI

Без `K_route` содержимое пакета не предоставляет обычному content-based DPI фиксированного byte pattern.

На проводе нет открытых:

- protocol magic;
- version;
- packet type;
- client ID;
- session ID;
- packet counter;
- inner IPv4 header;
- Noise static public key;
- Noise ephemeral public key;
- постоянного handshake header.

Handshake имеет переменный размер и random padding.

DATA имеет per-packet padding.

Служебный трафик использует тот же зашифрованный envelope.

То есть нельзя написать нормальное правило вида:

```text
if udp[offset:n] == known_constant:
    protocol = Noranite
```

Такого `known_constant` у протокола просто нет.


## Active probing

Noranite не имеет unauthenticated discovery protocol.

Произвольный UDP packet не вызывает узнаваемого ответа сервера.

Корректный handshake требует:

- знания `K_route`;
- правильного opaque framing;
- корректного Noise IK exchange;
- авторизованной client identity.

Поэтому модель обнаружения:

```text
send probe
receive VPN banner
block endpoint
```

здесь не работает.

## Scope

Noranite — небольшой point-to-point L3 protocol.

Текущая версия использует:

```text
inner network:    IPv4
outer transport:  IPv4 / UDP
topology:         client <-> server
payload mapping:  one IPv4 packet per UDP datagram
```

Протокол не пытается быть универсальным VPN framework, системой маскировки под другие протоколы или средством полной защиты от traffic analysis.

Он решает одну задачу и делает это прямо:

**Noranite передаёт аутентифицированный и зашифрованный L3-трафик так, чтобы сам wire format не давал пассивному наблюдателю простой способ определить, что перед ним Noranite.**
