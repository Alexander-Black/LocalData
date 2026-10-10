#!/usr/bin/env python3
"""
Раскладывает подписки по секретным адресам.

Новая схема адресов (у записи в subs.json НЕТ поля "path"):
    site/subs/<GUID>       - запись с "url":  подписка скачивается у провайдера (VLESS и т.п.)
    site/configs/<GUID>    - запись с "file": файл из приватного репозитория (AmneziaWG .conf и т.п.)
GUID - это поле "id" записи; он и есть секрет адреса.

Старая схема (у записи есть "path"):  site/<path>/<id | имя файла | sub.txt>.
Продолжает работать без изменений, пока запись не переведена на новую схему.

Вход (переменные окружения):
    SUBS_FILE  - путь к JSON-файлу конфига (либо SUBS_JSON - сам JSON)
    PAGES_BASE - адрес сайта Pages (для отката на предыдущую версию)
    SUB_UA     - User-Agent по умолчанию для запросов к провайдеру (v2rayN)

Формат записи (ровно одно из url / file):
    {"name": "...", "url": "...",  "hwid": "...", "id": "<GUID>", "ua": "..."}   # ua необязателен
    {"name": "...", "file": "configs/mama.conf",  "id": "<GUID>"}

Пути "file" считаются от каталога, где лежит SUBS_FILE.

Важно: репозиторий публичный, логи Actions видны всем. Поэтому скрипт НИКОГДА
не печатает url / hwid / path / id / содержимое - только name, размер и тип.
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
MIN_PATH_LEN = 24  # старая схема: короткий path = угадываемая ссылка
SAFE_NAME = re.compile(r"[A-Za-z0-9._-]+")
ID_RE = re.compile(r"[A-Za-z0-9-]{16,64}")  # id в старой схеме
GUID_RE = re.compile(r"[0-9a-fA-F]{8}(-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}")  # id в новой схеме


def rel_path(s: dict) -> Path:
    """Куда класть файл относительно site/ (он же адрес на Pages)."""
    if s.get("path"):  # старая схема
        name = s.get("id") or (Path(s["file"]).name if s.get("file") else "sub.txt")
        return Path(s["path"]) / name
    return Path("configs" if s.get("file") else "subs") / s["id"]


def validate(subs: list) -> str | None:
    """Возвращает текст ошибки или None. Значения секретов в сообщения не попадают."""
    seen = set()
    for s in subs:
        name = s.get("name", "?")
        if bool(s.get("url")) == bool(s.get("file")):
            return f"[{name}] нужно указать ровно одно из: url или file"
        if s.get("path"):  # старая схема
            if len(s["path"]) < MIN_PATH_LEN:
                return f"[{name}] path короче {MIN_PATH_LEN} символов"
            if s.get("id") and not ID_RE.fullmatch(s["id"]):
                return f"[{name}] id: латиница, цифры и дефис, 16-64 символа"
            if s.get("file") and not s.get("id") and not SAFE_NAME.fullmatch(Path(s["file"]).name):
                return f"[{name}] имя файла: только латиница, цифры, . _ -"
        elif not s.get("id") or not GUID_RE.fullmatch(s["id"]):
            return f"[{name}] нужен id в формате GUID (или path для старой схемы)"
        key = rel_path(s).as_posix().lower()
        if key in seen:
            return f"[{name}] адрес не уникален (повторяется id или path)"
        seen.add(key)
    return None


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


def fetch_previous(rel: str) -> bytes | None:
    """Последняя опубликованная версия с Pages - запасной вариант при сбое."""
    if not PAGES_BASE:
        return None
    try:
        with urllib.request.urlopen(f"{PAGES_BASE}/{rel}", timeout=30) as resp:
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
        for key in ("url", "hwid", "path", "id"):
            if s.get(key):
                print(f"::add-mask::{s[key]}")

    error = validate(subs)
    if error:
        print(f"::error::{error}")
        return 1

    SITE.mkdir(exist_ok=True)
    (SITE / "index.html").write_text("")  # пустой корень сайта
    failed = []

    for s in subs:
        name = s.get("name", "?")
        is_file = bool(s.get("file"))
        rel = rel_path(s)
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
            prev = fetch_previous(rel.as_posix())
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

        out = SITE / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(data)
        print(f"[{name}] {source}: {len(data)} bytes, {detect_kind(data) or 'файл'}")

    if failed:
        print(f"::error::нет ни свежей, ни прошлой версии для: {', '.join(failed)}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
