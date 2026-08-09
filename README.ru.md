# tachyon

> [English](README.md) · **Русский**

![ci](https://github.com/xdearboy/tachyon/actions/workflows/ci.yml/badge.svg)

Статический HTTP/HTTPS-движок на C, построенный вокруг Linux kernel TLS.

Держит **~950 000 HTTPS-запросов/сек** (TLS 1.3) на 28-ядерной машине при латентности около **половины миллисекунды**, а симметричное шифрование считается в ядре, а не в user space.

---

### Почему быстро

Обычный HTTPS-сервер тратит большую часть CPU на перекладывание байтов между user-space буферами и TLS-библиотекой. tachyon эту работу пропускает:

* **Kernel TLS.** OpenSSL делает только рукопожатие TLS 1.3. После установки ключей `AES-128-GCM` отдаётся ядру (`TCP_ULP` / `SOL_TLS`) и шифруется через AES-NI, так что данные ответа вообще не копируются через user space.
* **Заранее собранные батчи.** Статические ответы собираются один раз в непрерывные буферы и пишутся встык.
* **BPF CPU-стиринг.** Фильтр `SO_ATTACH_REUSEPORT_CBPF` прикрепляет соединение к воркеру, уже работающему на этом ядре, и запрос обрабатывается там, где приземлился.
* **Метрики без блокировок.** Счётчики живут в разделяемой памяти (`mmap`) и двигаются обычными атомиками, без мьютексов на горячем пути.

Роуты для отдаваемой директории ищутся через хеш-индекс, поэтому стоимость поиска не растёт с числом файлов.

---

### Бенчмарк

2x Intel Xeon E5-2680 v4 (28 ядер), Linux 7.0 (ядро Proxmox), OpenSSL 3.5, loopback:

```text
$ wrk -t28 -c600 -d15s https://127.0.0.1:8443/

Running 15s test @ https://127.0.0.1:8443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   512.35us  521.99us  29.49ms   90.65%
    Req/Sec    34.29k    14.34k   72.84k    67.25%
  14,409,477 requests in 15.09s, 219.87MB read
Requests/sec: 954,757.69
```

Что kTLS реально включился, проверяется на лету:

```bash
$ curl -k -s https://127.0.0.1:8443/stats
{ "ktls_tx": true, "ktls_rx": true, "cipher": "TLS_AES_128_GCM_SHA256 (TLS 1.3)", ... }
```

---

### Сборка

Нужен GCC или Clang и OpenSSL 3.0+:

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make
```

Self-signed серты для локальных тестов:

```bash
make certs
```

Запуск юнит-тестов:

```bash
make test
```

---

### Запуск

```bash
# TOML-конфиг:
./tachyon -C tachyon.toml

# или просто флаги:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/cert.pem -k /path/to/key.pem

# отдавать статическую директорию:
./tachyon -p 8443 -c cert.pem -k key.pem -d /var/www/html
```

#### Опции CLI
* `-C, --config <file>` — TOML-конфиг
* `-p <port>` — порт (по умолчанию `8443`)
* `-b <addr>` — адрес привязки (по умолчанию `0.0.0.0`)
* `-c <cert.pem>` / `-k <key.pem>` — TLS-серт и ключ
* `-d, --root <dir>` — отдавать статику из директории
* `-w <num>` — число воркеров (по умолчанию: число ядер)
* `-s` — включить BPF CPU-стиринг
* `--status <204|200>` — код ответа для пустого роута (по умолчанию `204`)
* `--stats` / `--no-stats` — переключить эндпоинт `/stats`
* `--stats-path <path>` — свой путь для статы (по умолчанию `/stats`)

---

### Конфигурация (`tachyon.toml`)

```toml
[server]
port = 443
bind = "0.0.0.0"
# workers = 28
status = 204
# root = "/var/www/html"
cpu_steer = true

[tls]
cert = "/etc/letsencrypt/live/example.com/fullchain.pem"
key  = "/etc/letsencrypt/live/example.com/privkey.pem"

[stats]
enabled = true
path = "/stats"
```

---

### Тюнинг ядра

Для максимальной пропускной способности под нагрузкой:

```bash
sudo ./scripts/tune-os.sh
```

### Лицензия

MIT
