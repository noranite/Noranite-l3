# Noranite

[English](README.md) · [Русский](README.ru.md)

[Порядок установки](USAGE.md)

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

Смысл не в самих случайных байтах, а в том, что они лишают DPI дешёвой и точной сигнатуры. Fixed magic, открытый тип пакета или узнаваемый handshake дают content-based DPI готовое правило. У Noranite такого правила нет.

Подход "зашифровать payload с первого байта и не оставлять fixed header" обычно относят к fully encrypted, или "looks like random", transports. Именно такую модель разбирает [*How the Great Firewall of China Detects and Blocks Fully Encrypted Traffic* (USENIX Security 2023)](https://www.usenix.org/conference/usenixsecurity23/presentation/wu-mingshi). Эта же работа хорошо показывает ограничение идеи: high-entropy traffic не становится автоматически нераспознаваемым — исследованный механизм GFW классифицировал fully encrypted TCP с помощью эвристик по первому payload.

При этом в измерениях 2023 года конкретно этот механизм не затрагивал UDP: UDP datagram со случайным payload не вызывал блокировку. Это наблюдение о конкретной реализации GFW, а не гарантия для UDP вообще. [*Exposing and Circumventing SNI-based QUIC Censorship of the Great Firewall of China* (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/zohaib) позднее показала, что GFW умеет stateful-анализ QUIC поверх UDP, включая расшифровку QUIC Initial и protocol-specific filtering.

Без фиксированной content signature цензор всё равно может использовать IP/endpoint information, размеры пакетов, timing, направления, burst structure, объём трафика и statistical classification. Noranite не пытается полностью скрыть эти признаки.

Но Noranite — L3 tunnel: разные внутренние application flows естественным образом мультиплексируются в один внешний UDP flow, а DATA дополнительно получает 0..15 байт случайного authenticated padding. Такое перемешивание нарушает паттерны размеров, timing и direction. [*Fingerprinting Obfuscated Proxy Traffic with Encapsulated TLS Handshakes* (USENIX Security 2024)](https://www.usenix.org/conference/usenixsecurity24/presentation/xue-fingerprinting) показывает, что stream multiplexing действительно может быть эффективной контрмерой против такого анализа, но одновременно подчёркивает, что multiplexing и random padding сами по себе не уничтожают все flow-level fingerprints.

Более общий trade-off разбирается в [*Censorship Evasion with Unidentified Protocol Generation* (USENIX Security 2025)](https://www.usenix.org/conference/usenixsecurity25/presentation/wails): если encrypted protocol нельзя надёжно выделить на уровне протокольной сигнатуры, блокировка всего класса unidentified traffic начинает задевать другие encrypted protocols.

Noranite не делает блокировку невозможной. Он делает её **грязной и очень дорогой**.

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

Помимо Noise identities сервер и его клиенты используют общий 32-байтный секрет `K_route`.

Это не ключ шифрования трафика и не Noise PSK.

`K_route` нужен для того, чтобы скрыть структуру пакета ещё **до** момента, когда получатель определил нужную сессию и получил возможность использовать её traffic key.

С его помощью маскируются:

- `session_id || sequence` в первых 16 байтах пакета;
- ephemeral X25519 public key внутри Noise handshake.

Mask привязан к конкретному пакету, поэтому одинаковые внутренние значения не дают одинакового представления на проводе.

Сам по себе `K_route` не позволяет расшифровать DATA и не раскрывает Noise private keys. Компрометация `K_route` не ломает криптографическую защиту туннеля, но снимает wire-masking для этого deployment. В обычной модели развёртывания `K_route` выдаётся вместе с endpoint сервера, поэтому компрометация клиентской конфигурации обычно раскрывает и то, и другое. В этом случае анализ уже не требуется: намного дешевле блокировать IP.

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
