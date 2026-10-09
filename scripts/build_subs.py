#!/usr/bin/env python3
"""
Раскладывает подписки по секретным путям:
    site/<path>/sub.txt          - запись с "url": подписка скачивается у провайдера
    site/<path>/<имя файла>      - запись с "file": файл берётся из приватного репозитория
                                   (например AmneziaWG 2.0 .conf), публикуется под своим именем

Вход (переменные окружения):
    SUBS_FILE  - путь к JSON-файлу конфига (либо SUBS_JSON - сам JSON)
    PAGES_BASE - адрес сайта Pages (для отката на предыдущую версию)
    SUB_UA     - User-Agent по умолчанию для запросов к провайдеру (v2rayN)

Формат записи (ровно одно из url / file):
    {"name": "...", "url": "...", "hwid": "...", "path": "...", "ua": "..."}   # ua необязателен
    {"name": "...", "file": "configs/mama.conf", "path": "..."}

Пути "file" считаются от каталога, где лежит SUBS_FILE.

Важно: репозиторий публичный, логи Actions видны всем. Поэтому скрипт НИКОГДА
не печатает url / hwid / path / содержимое — только name, размер и тип.
"""
import base64
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

SITE = Path("site")
PAGES_BASE = os.environ.get("PAGES_BASE", "").rstrip("/")
UA = os.environ.get("SUB_UA", "v2rayN")
MIN_PATH_LEN = 24  # короткий путь = угадываемая ссылка
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")


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


def fetch(url: str, hwid: str, ua: str = "") -> bytes:
    headers = {"User-Agent": ua or UA}
    if hwid:
        headers["x-hwid"] = hwid
    # Если провайдер требует ещё заголовки (x-device-os, x-ver-os, x-device-model),
    # добавь их сюда в headers.
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.read()


def read_local(rel: str, base_dir: Path) -> bytes:
    """Читает файл из каталога конфига; выйти за его пределы нельзя."""
    root = base_dir.resolve()
    p = (root / rel).resolve()
    if root not in p.parents:
        raise ValueError("file вне каталога конфига")
    data = p.read_bytes()
    if not data.strip():
        raise ValueError("файл пуст")
    return data


def fetch_previous(path: str, filename: str) -> bytes | None:
    """Последняя опубликованная версия с Pages - запасной вариант при сбое."""
    if not PAGES_BASE:
        return None
    try:
        with urllib.request.urlopen(f"{PAGES_BASE}/{path}/{filename}", timeout=30) as resp:
            return resp.read()
    except Exception:
        return None


def main() -> int:
    base_dir = Path(".")
    try:
        if os.environ.get("SUBS_FILE"):
            base_dir = Path(os.environ["SUBS_FILE"]).parent
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

    for s in subs:
        if bool(s.get("url")) == bool(s.get("file")):
            print(f"::error::[{s.get('name', '?')}] нужно указать ровно одно из: url или file")
            return 1
        if s.get("file") and not SAFE_NAME.fullmatch(Path(s["file"]).name):
            print(f"::error::[{s.get('name', '?')}] имя файла: только латиница, цифры, . _ -")
            return 1

    SITE.mkdir(exist_ok=True)
    (SITE / "index.html").write_text("")  # пустой корень сайта
    failed = []

    for s in subs:
        name = s.get("name", "?")
        is_file = bool(s.get("file"))
        fname = Path(s["file"]).name if is_file else "sub.txt"
        data, source = None, "fresh"

        try:
            if is_file:
                data = read_local(s["file"], base_dir)
                source = "из файла"
            else:
                data = fetch(s["url"], s.get("hwid", ""), s.get("ua", ""))
                if detect_kind(data) is None:
                    print(f"[{name}] ответ не похож на подписку (заглушка?)")
                    data = None
        except urllib.error.HTTPError as e:
            print(f"[{name}] HTTP {e.code}")
        except Exception as e:  # сеть, таймаут, нет файла - без деталей
            print(f"[{name}] ошибка: {type(e).__name__}")

        if data is None:
            prev = fetch_previous(s["path"], fname)
            # Для файловой записи достаточно непустого не-HTML ответа
            prev_ok = bool(prev) and (
                detect_kind(prev) is not None
                or (is_file and prev.strip()[:1] != b"<" and bool(prev.strip()))
            )
            if prev_ok:
                data, source = prev, "STALE (прошлая версия)"
                print(f"::warning::[{name}] не удалось обновить, оставлена прошлая версия")
            else:
                failed.append(name)
                continue

        out = SITE / s["path"]
        out.mkdir(parents=True, exist_ok=True)
        (out / fname).write_bytes(data)
        print(f"[{name}] {source}: {len(data)} bytes, {detect_kind(data) or 'файл'}")

    if failed:
        print(f"::error::нет ни свежей, ни прошлой версии для: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
