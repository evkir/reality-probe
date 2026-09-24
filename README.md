<h1 align="center">🐼 Reality Probe v4</h1>

<p align="center">
  <b>Подбор SNI/target для VLESS Reality под политики ТСПУ 2026</b><br/>
  <sub>SNI↔IP/ASN · соседи по подсети VPS · X25519MLKEM768 · тест заморозки 15–20 КБ · Xray / sing-box / Mihomo</sub>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/version-4.0-00cfee?style=flat-square" />
  <img src="https://img.shields.io/badge/python-3.9+-00d47e?style=flat-square&logo=python&logoColor=white" />
  <img src="https://img.shields.io/badge/license-MIT-e8a800?style=flat-square" />
</p>

---

## Что изменилось в ТСПУ и как на это ответил v4

| Поведение ТСПУ (2026) | Что делает v4 |
|---|---|
| Заморозка TCP после ~15–20 КБ / ~25 пакетов на зарубежные IP из DC-ASN (Hetzner, DO, Vultr, OVH…) | **Тест заморозки**: качает страницу донора через IP VPS и показывает, на каком байте встал поток. Предупреждает, если ASN сервера в группе риска |
| Сверка SNI с владельцем IP: SNI Apple/Microsoft/Google на IP хостера = аномалия | **Топология**: ASN/префикс донора vs сервера (RIPEstat). +25 за ту же подсеть, +20 за тот же ASN, −15 за SNI крупного бренда на чужом ASN, −15 за донора за Cloudflare |
| «Затёртые» SNI (microsoft.com, apple.com, lovelive-anime.jp…) — в первых строках эвристик | Штраф −15, убраны из встроенного списка |
| Лучший донор — сайт рядом с сервером | **Соседи по подсети** (как RealiTLScanner): TLS без SNI ко всем хостам /24 (/23, /22), имена из сертификатов → полный пробинг |
| Браузеры шлют X25519MLKEM768; target без него выдаёт себя при active probing | Сырой TLS 1.3 ClientHello: выбранная группа + поддержка MLKEM (колонка `KEX`, метка `PQ`) |
| Fingerprint `chrome` под подозрением, частая смена fp → бан узла ~10 мин | По умолчанию `firefox`, порядок перебора в подсказке, без автосмены |
| Режим белых списков (мобильные сети): TLS проходит только с SNI из списка | Профиль **«Белые списки РФ»**: встроенные кандидаты, штраф для остальных |
| Vision не спасает от поведенческого анализа | Конфиг **XHTTP** (mode auto, padding 100–1000) как запасной inbound |

Без IP сервера максимум ~70 баллов (EXCELLENT): главный риск — несовпадение SNI↔IP — нельзя оценить, и инструмент это показывает.

---

## Быстрый старт

```bash
git clone https://github.com/evkir/reality-probe.git
cd reality-probe
pip install -r requirements.txt
python reality_probe.py            # или: python -m realityprobe --port 7890 --no-browser
```

Откройте **http://localhost:7890**.

### Рабочий порядок

1. Впишите **IP сервера (VPS)** → нажмите **🧭 Соседи по подсети**. Это главный режим.
2. Если в /24 пусто — /23 или /22, затем обычный скан списка с тем же IP.
3. Отфильтруйте **🧭 Подсеть/ASN** или **🟢 Низкий риск** → **USE**.
4. **Из сети РФ** введите донора в Quick Probe и нажмите **❄ Тест заморозки** (IP сервера заполнен).
   `FROZEN` → меняйте IP/ASN, а не SNI. Контроль: тот же тест с пустым IP сервера (напрямую к донору).
5. Конфиг: транспорт `TCP + Vision` (основной) и `XHTTP` (запасной), fingerprint `firefox`.

---

## Скоринг

| Фактор | Баллы |
|---|---|
| TLS 1.3 | +25 (без него — непригоден) |
| h2 в ALPN | +15 |
| X25519MLKEM768 | +10 |
| X25519/MLKEM выбран | +5 |
| Сертификат покрывает SNI | +5 / −10 |
| HTTP 2xx на `/` | +5; офсайт-редирект −25 (непригоден) |
| RTT | до +5 |
| **Донор в подсети VPS** | **+25** |
| **Донор в ASN VPS** | **+20** |
| SNI крупного бренда на чужом ASN | −15 |
| Донор за Cloudflare (ASN неизвестен) | −15 |
| Затёртый SNI | −15 |
| Профиль «белые списки»: SNI в списке | +15 (иначе непригоден) |

Статус: **IDEAL** ≥80 · **EXCELLENT** ≥65 · **GOOD** ≥50 · **POOR** <50.
Риск ТСПУ: `НИЗКИЙ` / `СРЕДНИЙ` / `ВЫСОКИЙ` — наведите на значение, чтобы увидеть причины.

---

## Конфиги

Xray (server/client), sing-box, Mihomo, NekoBox/Throne, `vless://`:

- `target` вместо устаревшего `dest`, `serverNames` = хост target;
- без пустого shortId, `fingerprint` только на клиенте;
- `mux` выключен (несовместим с Vision);
- XHTTP: `flow` не используется; sing-box/Mihomo/NekoBox его не поддерживают — клиент на Xray-core (v2rayN, v2rayNG, Happ, Streisand).

---

## Архитектура

```
realityprobe/
  policy.py     модель политик ТСПУ: списки, ASN, диапазоны Cloudflare, белый список
  netinfo.py    ASN/префикс через RIPEstat (кеш по префиксу, офлайн-режим)
  tlshello.py   сырой ClientHello (X25519MLKEM768) и разбор ServerHello
  certs.py      разбор DER-сертификата, RFC 6125, MITM-издатели
  prober.py     DNS → TLS/ALPN/серт → KEX → HTTP-статус → ASN → скоринг
  scoring.py    чистая функция оценки и риска
  subnet.py     соседи по подсети VPS
  freeze.py     тест заморозки 15–20 КБ
  configgen.py  Xray / sing-box / Mihomo / NekoBox / vless://
  runner.py     фоновые сканы, история
  app.py        Flask API, web/index.html — UI
```

API: `POST /api/probe`, `POST /api/subnet`, `POST /api/freeze`, `POST /api/genconfig`,
`GET /api/status`, `GET /api/export/{csv,json,zip}`.

---

## Docker

```bash
docker build -t reality-probe .
docker run -p 127.0.0.1:7890:7890 reality-probe
```

API без авторизации — не публикуйте порт наружу.

## Тесты

```bash
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

Тесты не ходят в интернет: локальный TLS 1.3 сервер с самоподписанным сертификатом, фейковый RIPEstat.

---

## Ограничения

- Модель ТСПУ — реконструкция по публичным наблюдениям (май–июнь 2026), не официальные данные; эвристики меняются.
- Тест заморозки осмыслен только из сети РФ; из-за рубежа он покажет `CLEAN`.
- Белый список РФ неофициальный и отличается по регионам.
- Сканирование подсети — только IPv4.

## Связанные проекты

- [XTLS/Xray-core](https://github.com/XTLS/Xray-core) · [XTLS/RealiTLScanner](https://github.com/XTLS/RealiTLScanner) · [SagerNet/sing-box](https://github.com/SagerNet/sing-box)

## License

MIT — see [LICENSE](LICENSE)
