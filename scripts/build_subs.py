#!/usr/bin/env python3
"""
Скачивает несколько подписок и раскладывает их по секретным путям:
    site/<path>/sub.txt

Вход (переменные окружения, приходят из GitHub Secrets):
    SUBS_JSON  - JSON-массив: [{"name": "...", "url": "...", "hwid": "...", "path": "..."}]
    PAGES_BASE - адрес сайта Pages (для отката на предыдущую версию)
    SUB_UA     - User-Agent для запросов к провайдеру (по умолчанию v2rayN)

Важно: репозиторий публичный, логи Actions видны всем. Поэтому скрипт НИКОГДА
не печатает url / hwid / path / содержимое подписок — только name, размер и тип.
"""
import base64
import json
import os
import sys
import urllib.error
import urllib.request
from pathlib import Path

SITE = Path("site")
PAGES_BASE = os.environ.get("PAGES_BASE", "").rstrip("/")
UA = os.environ.get("SUB_UA", "v2rayN")
MIN_PATH_LEN = 24  # короткий путь = угадываемая ссылка


def detect_kind(data: bytes) -> str | None:
    """Возвращает тип подписки или None, если это не похоже на подписку."""
    stripped = data.strip()
    if not stripped:
        return None
    first = stripped[:1]
    if first == b"<":
        return None  # HTML-заглушка / страница провайдера
    if first == b"{":
        return "JSON (sing-box?)"
    text = stripped.decode("utf-8", "ignore")
    if "[Interface]" in text and "[Peer]" in text:
        return "WireGuard/AmneziaWG .conf"
    if "proxies:" in text:
        return "Clash YAML"
    if "://" in text:
        return "plain-список"
    try:
        padded = stripped + b"=" * (-len(stripped) % 4)
        if b"://" in base64.b64decode(padded):
            return "base64-список"
    except Exception:
        pass
    return None


def fetch(url: str, hwid: str) -> bytes:
    headers = {"User-Agent": UA}
    if hwid:
        headers["x-hwid"] = hwid
    # Если провайдер требует ещё заголовки (x-device-os, x-ver-os, x-device-model),
    # добавь их сюда в headers.
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def fetch_previous(path: str) -> bytes | None:
    """Последняя опубликованная версия с Pages - запасной вариант при сбое."""
    if not PAGES_BASE:
        return None
    try:
        with urllib.request.urlopen(f"{PAGES_BASE}/{path}/sub.txt", timeout=30) as resp:
            return resp.read()
    except Exception:
        return None


def main() -> int:
    # Источник конфигурации: файл из приватного репо (SUBS_FILE)
    # или переменная окружения с секретом (SUBS_JSON)
    try:
        if os.environ.get("SUBS_FILE"):
            # utf-8-sig: терпимо к BOM, который Windows-редакторы любят добавлять
            raw = Path(os.environ["SUBS_FILE"]).read_text(encoding="utf-8-sig")
        else:
            raw = os.environ["SUBS_JSON"]
        subs = json.loads(raw)
    except (KeyError, OSError, json.JSONDecodeError):
        print("::error::конфиг подписок не найден или это невалидный JSON")
        return 1

    # Маскируем значения в логах (GitHub маскирует только секрет целиком)
    for s in subs:
        for key in ("url", "hwid", "path"):
            if s.get(key):
                print(f"::add-mask::{s[key]}")

    paths = [s.get("path", "") for s in subs]
    if len(set(paths)) != len(paths) or any(len(p) < MIN_PATH_LEN for p in paths):
        print(f"::error::path должен быть уникальным и не короче {MIN_PATH_LEN} символов")
        return 1

    SITE.mkdir(exist_ok=True)
    (SITE / "index.html").write_text("")  # пустой корень сайта
    failed = []

    for s in subs:
        name = s.get("name", "?")
        data, source = None, "fresh"
        try:
            data = fetch(s["url"], s.get("hwid", ""))
            if detect_kind(data) is None:
                print(f"[{name}] ответ не похож на подписку (заглушка?)")
                data = None
        except urllib.error.HTTPError as e:
            print(f"[{name}] HTTP {e.code}")
        except Exception as e:  # сеть, таймаут и т.п. - без деталей URL
            print(f"[{name}] ошибка запроса: {type(e).__name__}")

        if data is None:
            prev = fetch_previous(s["path"])
            if prev is not None and detect_kind(prev) is not None:
                data, source = prev, "STALE (прошлая версия)"
                print(f"::warning::[{name}] не удалось обновить, оставлена прошлая версия")
            else:
                failed.append(name)
                continue

        out = SITE / s["path"]
        out.mkdir(parents=True, exist_ok=True)
        (out / "sub.txt").write_bytes(data)
        print(f"[{name}] {source}: {len(data)} bytes, {detect_kind(data)}")

    if failed:
        print(f"::error::нет ни свежей, ни прошлой версии для: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
