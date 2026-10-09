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


## Клиент на базе sing-box

Для использования Noranite в качестве endpoint в полноценном TUN/proxy-клиенте можно собрать sing-box с reference-интеграцией Noranite.

Интеграция рассчитана на **sing-box v1.13.15** и поставляется в виде отдельного патча:

```text
integrations/sing-box/sing-box-1.13.15-noranite-integration.patch
```

### Сборка

1. Склонируйте исходники sing-box и перейдите на версию `v1.13.15`:

```bash
git clone https://github.com/SagerNet/sing-box.git
cd sing-box
git checkout v1.13.15
```

2. Примените патч Noranite:

```bash
git apply /path/to/Noranite-l3/integrations/sing-box/sing-box-1.13.15-noranite-integration.patch
```

3. Подключите локальный checkout Noranite-l3:

```bash
go mod edit \
  -require=github.com/noranite/Noranite-l3@v0.0.0 \
  -replace=github.com/noranite/Noranite-l3=/path/to/Noranite-l3

go mod tidy
```

4. Соберите sing-box штатным build-процессом, добавив build tag `with_noranite`.

Для Linux/macOS:

```bash
TAGS="$(cat release/DEFAULT_BUILD_TAGS_OTHERS),with_noranite"
make build TAGS="$TAGS"
```

Для Windows необходимо использовать набор тегов из:

```text
release/DEFAULT_BUILD_TAGS_WINDOWS
```

и также добавить:

```text
with_noranite
```

Интеграция требует `with_gvisor`; этот тег уже входит в стандартные наборы build tags sing-box v1.13.15.

После сборки в конфигурации становится доступен endpoint типа:

```json
{
  "type": "noranite",
  "tag": "noranite",
  "server": "203.0.113.1",
  "server_port": 443,
  "address": "10.0.0.2",
  "mtu": 1380,
  "route_key": "<base64>",
  "private_key": "<base64>",
  "server_public_key": "<base64>"
}
```

Патч является reference-интеграцией Noranite с sing-box и не является отдельным дистрибутивом sing-box.

sing-box распространяется его авторами отдельно и используется здесь как сторонняя платформа. Noranite не аффилирован с SagerNet и разработчиками sing-box.