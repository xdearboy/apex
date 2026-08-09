# tachyon

Ультрабыстрый статический HTTP/HTTPS движок на C с поддержкой Linux kTLS.

Выжимает **1 000 000+ HTTPS RPS** (TLS 1.3) на обычном 28-ядерном сервере с задержкой **~250 мкс** и минимальным потреблением памяти. На пиковых нагрузках с пайплайнингом держит до ~5 млн RPS.

---

### За счёт чего так быстро

Обычные HTTPS-серверы тратят львиную долю процессора на перекладывание байт между юзерспейс-буферами и криптоконтекстами OpenSSL. В Tachyon это устроено иначе:

1. **Linux Kernel TLS (kTLS):** OpenSSL делает только первоначальный TLS 1.3 хендшейк, после чего симметричное шифрование (`AES-128-GCM`) передаётся в ядро Linux (`SOL_TLS` / `TCP_ULP`). Ядро шифрует трафик напрямую через векторные инструкции процессора (AES-NI) без копирования буферов в юзерспейс.
2. **Zero-Copy Batching:** Статические ответы заранее отрендерены в непрерывные буферы памяти и отправляются пакетами.
3. **BPF CPU Steering:** Программа `SO_ATTACH_REUSEPORT_CBPF` направляет TCP-соединения сразу на тот воркер, который привязан к конкретному ядру CPU.
4. **Lockless метрики:** Метрики `/stats` работают через разделяемую память (`mmap`) и атомарные операции без мьютексов.

---

### Бенчмарк

Тестировалось на 2x Intel Xeon E5-2680 v4 (28 ядер суммарно, Debian Linux 7.0 Proxmox kernel):

```text
$ wrk -t 28 -c 600 -d 10s https://127.0.0.1:443/

Running 10s test @ https://127.0.0.1:443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   251.62us  205.78us  10.74ms   95.16%
    Req/Sec    37.19k     5.51k   52.48k    71.49%
  10,365,042 requests in 10.10s, 148.28MB read
Requests/sec: 1,026,241.78
Transfer/sec:     14.68MB
```

---

### Сборка

Требуется GCC или Clang и OpenSSL 3.0+:

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make
```

Сгенерировать самоподписанные сертификаты для локального теста:
```bash
make certs
```

---

### Запуск

```bash
# Запуск через TOML-конфиг:
./tachyon -C tachyon.toml

# Или через флаги:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/cert.pem -k /path/to/key.pem

# Раздача статики из папки:
./tachyon -p 8443 -c cert.pem -k key.pem -d /var/www/html
```

#### Флаги
* `-C, --config <file>` — путь к TOML-конфигу
* `-p <port>` — порт (дефолт: `8443`)
* `-b <addr>` — адрес привязки (дефолт: `0.0.0.0`)
* `-c <cert.pem>` / `-k <key.pem>` — пути к сертификату и ключу
* `-d, --root <dir>` — раздача статики из директории (HTML, CSS, JS и т.д.)
* `-w <num>` — число воркеров (по умолчанию равно числу ядер)
* `-s` — включить BPF CPU steering
* `--status <204|200>` — код ответа (дефолт: `204`)
* `--stats` / `--no-stats` — включить или выключить эндпоинт `/stats`
* `--stats-path <path>` — кастомный путь для метрик (дефолт: `/stats`)

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

### Тюнинг ядра Linux

Для максимального RPS под экстремальной нагрузкой:

```bash
sudo ./scripts/tune-os.sh
```

### Лицензия

MIT
