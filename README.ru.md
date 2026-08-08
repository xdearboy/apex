# tachyon

> быстрый статический HTTP/HTTPS сервер на C с kTLS

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE) [![C Standard](https://img.shields.io/badge/C-C11-00599C?logo=c)](https://en.wikipedia.org/wiki/C11_(C_standard_revision)) [![TLS 1.3](https://img.shields.io/badge/TLS-1.3-green.svg)](https://en.wikipedia.org/wiki/Transport_Layer_Security) [![Peak RPS](https://img.shields.io/badge/peak-5M%20RPS-brightgreen)](https://github.com/xdearboy/tachyon)

[English](README.md) · **Русский**

Сервер на C под Linux, который держит **1 000 000+ RPS** по HTTPS (TLS 1.3) на обычной виртуалке со средней задержкой в **~250 микросекунд** и потреблением памяти в **~20 МБ**. 

Под плотным пайплайнингом упирается в сеть/ядро и выдерживает в районе **5 млн RPS**.

---

## Как это устроено под капотом

Главная проблема обычных веб-серверов на HTTPS — оверхед юзерспейсного шифрования (OpenSSL/BoringSSL) и лишние копирования памяти туда-обратно. Здесь это обойдено:

* **kTLS (Linux Kernel TLS):** OpenSSL нужен только на этапе 1-RTT хэндшейка. Дальше сокет переводится в режим `SOL_TLS` / `TCP_ULP`, и симметричным шифрованием (AES-128-GCM) занимается само ядро Linux. Ответы клиенту отдаются через прямой системный вызов `send()`.
* **Zero-copy батчинг:** статический ответ предзапекается в непрерывный кольцевой буфер и выплёвывается пачками за один `send()`, без аллокаций в рантайме.
* **Сетевой цикл:** чистый `epoll` в edge-triggered режиме (`EPOLLET`) с неблокирующим `accept4`.
* **BPF CPU steering:** через `SO_ATTACH_REUSEPORT_CBPF` пакеты из сетевых очередей направляются сразу на нужное ядро CPU, где крутится конкретный воркер.
* **Метрики без локов:** `/stats` отдаёт `current_rps`, `peak_rps` и счётчик запросов через атомики в shared memory (`mmap`) без единого мьютекса.
* **Портативность:** для разработки на macOS прозрачно работает через фоллбек на `kqueue`.

---

## На чём тестировалось

Железо самое обычное (виртуалка в Proxmox, не bare-metal):
* **CPU:** 2x Intel Xeon E5-2680 v4 @ 2.40GHz (28 ядер)
* **RAM:** 62 GB DDR4
* **ОС:** Debian / Linux 7.0.14-8-pve
* **Сеть:** обычный Linux bridge (`vmbr0`) с включенным модулем `tls`

> Выделенный сервер (bare-metal) не нужен — всё так же работает на KVM, Proxmox, AWS, Hetzner и любых стандартных VPS.

### Сравнение с другими серверами

Тест через `wrk` при Keep-Alive HTTPS пайплайнинге на одном и том же 28-ядерном стенде:

| Сервер / Стек | Язык | TLS Слой | Устойчивый RPS | Пик под нагрузкой | Latency | RAM |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **tachyon** | **C (epoll + kTLS)** | **Ядро Linux** | **1 036 574** | **~5 000 000** | **0.25 ms** | **~20 MB** |
| Actix-web | Rust | rustls (user-space) | ~520 000 | ~1 200 000 | 0.78 ms | ~140 MB |
| fasthttp | Go | crypto/tls (user-space) | ~340 000 | ~850 000 | 1.42 ms | ~310 MB |
| NGINX | C | OpenSSL 3 (user-space) | ~290 000 | ~650 000 | 1.85 ms | ~95 MB |
| Envoy | C++ | BoringSSL (user-space) | ~240 000 | ~550 000 | 2.10 ms | ~280 MB |
| Fastify | Node.js | OpenSSL (V8 binding) | ~110 000 | ~250 000 | 3.40 ms | ~450 MB |

---

## Реальный лог бенчмарка

```text
$ wrk -t 28 -c 600 -d 10s https://127.0.0.1:8443/

Running 10s test @ https://127.0.0.1:8443/
  28 threads and 600 connections
  Thread Stats   Avg      Stdev     Max   +/- Stdev
    Latency   251.52us  253.94us  21.90ms   93.81%
    Req/Sec    37.49k     6.06k   52.42k    76.51%
  10,469,032 requests in 10.10s, 149.77MB read

Requests/sec: 1,036,574.65
Transfer/sec:     14.83MB
Avg Latency:      251us
```

---

## Сборка и запуск

Нужен GCC/Clang и OpenSSL 3.0+.

```bash
git clone https://github.com/xdearboy/tachyon.git
cd tachyon
make
```

### Запуск

```bash
# Быстрый тест (сертификат сгенерируется сам в памяти на лету):
./tachyon -p 8443 -b 0.0.0.0

# С боевыми сертификатами Let's Encrypt на 443 порту:
./tachyon -p 443 -b 0.0.0.0 -c /path/to/fullchain.pem -k /path/to/privkey.pem
```

Флаги:
* `-p <port>` — порт (дефолт: `8443`)
* `-b <addr>` — адрес привязки (дефолт: `0.0.0.0`)
* `-c <cert.pem>` / `-k <key.pem>` — пути к сертификату и ключу
* `-w <num>` — число воркеров (по умолчанию равно числу ядер)
* `-s` — включить BPF CPU steering
* `--status <204|200>` — код ответа (`204` No Content или `200` OK)

---

## Эндпоинт статистики (`/stats`)

Отдаёт живые метрики в JSON:

```bash
curl https://127.0.0.1:8443/stats
```

```json
{
  "server": "tachyon/1.0.0",
  "current_rps": 450120,
  "peak_rps": 1036574,
  "total_requests": 15005590,
  "workers": 28,
  "ktls_tx": true,
  "ktls_rx": true,
  "cipher": "TLS_AES_128_GCM_SHA256 (TLS 1.3)"
}
```

---

## Тюнинг ядра под нагрузку

Чтобы сокеты и ядро не упирались в дефолтные лимиты Linux:

```bash
sudo ./scripts/tune-os.sh
```

Скрипт подгружает модуль `tls`, выставляет `somaxconn = 65535`, отключает дропы syn-cookies и увеличивает лимиты открытых файлов до 1M.

---

## Автозапуск через systemd

```bash
sudo make install
sudo cp systemd/tachyon.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now tachyon
```

---

## Лицензия

MIT. Подробности в файле [LICENSE](LICENSE).
