from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import logging
import math
import os
import platform
import random
import re
import signal
import sys
import time
from ctypes import c_int32
from dataclasses import dataclass, field
from getpass import getpass
from hashlib import md5, sha1
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urljoin

try:
    import requests
    from requests import Session
    from requests.exceptions import RequestException
except ImportError as exc:  # pragma: no cover
    requests = None
    Session = Any  # type: ignore[assignment]
    RequestException = Exception  # type: ignore[assignment]
    REQUESTS_IMPORT_ERROR = exc
else:
    REQUESTS_IMPORT_ERROR = None
    try:
        import urllib3

        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except Exception:
        pass

SCRIPT_DIR = Path(__file__).resolve().parent
DEFAULT_CONFIG_PATH = SCRIPT_DIR / "connection.local.json"
DEFAULT_SAMPLE_CONFIG_PATH = SCRIPT_DIR / "connection.sample.json"
DEFAULT_AUTH_SETTING_PATH = SCRIPT_DIR / ".auth-setting"
DEFAULT_GATEWAY_URLS = [
    "https://gw.buaa.edu.cn/",
    "http://gw.buaa.edu.cn:801/",
    "http://10.111.3.3/",
]
DEFAULT_PROBE_URLS = [
    {"url": "http://connectivitycheck.gstatic.com/generate_204", "expect_status": 204},
    {
        "url": "http://www.msftconnecttest.com/connecttest.txt",
        "expect_status": 200,
        "expect_text": "Microsoft Connect Test",
    },
]
DEFAULT_CHECK_INTERVAL_SECONDS = 60
DEFAULT_AUTH_TIMEOUT_SECONDS = 8
DEFAULT_HTTP_AUTH_RETRY_COUNT = 2
DEFAULT_HEADLESS_FALLBACK_AFTER_FAILURES = 3
DEFAULT_HEADLESS_TIMEOUT_SECONDS = 45
DEFAULT_LOG_MAX_BYTES = 1_048_576
DEFAULT_LOG_BACKUP_COUNT = 3
DEFAULT_INITIAL_BACKOFF_SECONDS = 5
DEFAULT_MAX_BACKOFF_SECONDS = 600
POST_AUTH_SETTLE_SECONDS = 2
ENCRYPTED_CREDENTIALS_ENV_VAR = "BUAA_CONNECTION_SECRET"
DEFAULT_CREDENTIAL_FILE_NAME = "connection.credentials.enc"
DEFAULT_CREDENTIAL_KEY_FILE_NAME = "connection.credentials.key"
CREDENTIAL_FILE_VERSION = 1
PBKDF2_ITERATIONS = 200_000
SRUN_BASE64_ALPHABET = "LVoJPiCN2R8G90yg+hmFHuacZ1OWMnrsSTXkYpUq/3dlbfKwv6xztjI7DeBE45QA"
USERNAME_SELECTORS = [
    "input[name='username']",
    "input[id='username']",
    "input[name*='user']",
    "input[id*='user']",
    "input[placeholder*='用户名']",
    "input[placeholder*='账号']",
    "input[type='text']",
]
PASSWORD_SELECTORS = [
    "input[name='password']",
    "input[id='password']",
    "input[name*='pass']",
    "input[id*='pass']",
    "input[placeholder*='密码']",
    "input[type='password']",
]
SUBMIT_SELECTORS = [
    "button[type='submit']",
    "input[type='submit']",
    "button[id*='login']",
    "button[class*='login']",
    "button:has-text('登录')",
    "button:has-text('Login')",
    "input[value*='登录']",
    "input[value*='Login']",
]


class ConfigError(RuntimeError):
    pass


class DependencyError(RuntimeError):
    pass


@dataclass(slots=True)
class ProbeTarget:
    url: str
    expect_status: int | None = None
    expect_text: str | None = None

    @classmethod
    def from_raw(cls, raw: str | dict[str, Any]) -> "ProbeTarget":
        if isinstance(raw, str):
            return cls(url=raw)
        if not isinstance(raw, dict) or "url" not in raw:
            raise ConfigError(f"Invalid probe target: {raw!r}")
        return cls(
            url=str(raw["url"]),
            expect_status=int(raw["expect_status"]) if raw.get("expect_status") is not None else None,
            expect_text=str(raw["expect_text"]) if raw.get("expect_text") is not None else None,
        )


@dataclass(slots=True)
class Config:
    username: str
    password: str
    gateway_urls: list[str]
    ac_id: str
    check_interval_seconds: int = DEFAULT_CHECK_INTERVAL_SECONDS
    probe_urls: list[ProbeTarget] = field(default_factory=list)
    auth_timeout_seconds: int = DEFAULT_AUTH_TIMEOUT_SECONDS
    http_auth_retry_count: int = DEFAULT_HTTP_AUTH_RETRY_COUNT
    headless_fallback_enabled: bool = True
    headless_fallback_after_failures: int = DEFAULT_HEADLESS_FALLBACK_AFTER_FAILURES
    headless_timeout_seconds: int = DEFAULT_HEADLESS_TIMEOUT_SECONDS
    log_file: str = "connection.log"
    log_max_bytes: int = DEFAULT_LOG_MAX_BYTES
    log_backup_count: int = DEFAULT_LOG_BACKUP_COUNT
    config_path: Path = DEFAULT_CONFIG_PATH
    credential_file: Path | None = None
    credential_key_file: Path | None = None


@dataclass(slots=True)
class AuthResult:
    success: bool
    method: str
    message: str
    gateway_url: str | None = None
    response_data: dict[str, Any] | None = None


@dataclass(slots=True)
class StatusReport:
    state: str
    online: bool
    gateway_url: str | None
    dependency_issue: str | None = None
    config_warning: str | None = None


def require_requests() -> None:
    if requests is None:
        raise DependencyError(
            "requests is not installed. Install it with: pip install requests"
        ) from REQUESTS_IMPORT_ERROR


def import_playwright_sync():
    try:
        from playwright.sync_api import Error as PlaywrightError
        from playwright.sync_api import TimeoutError as PlaywrightTimeoutError
        from playwright.sync_api import sync_playwright
    except ImportError as exc:
        raise DependencyError(
            "Playwright is not installed. Install it with: pip install playwright && playwright install chromium"
        ) from exc
    return sync_playwright, PlaywrightError, PlaywrightTimeoutError


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="BUAA campus network auto-auth helper")
    parser.add_argument("--config", default=str(DEFAULT_CONFIG_PATH), help="Path to connection.local.json")
    parser.add_argument(
        "--secret-passphrase",
        default=None,
        help=f"Passphrase for encrypted credentials. Can also be provided via {ENCRYPTED_CREDENTIALS_ENV_VAR}.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("run", help="Run the monitoring loop")
    subparsers.add_parser("status", help="Check status once")
    subparsers.add_parser("auth", help="Attempt one HTTP authentication now")
    subparsers.add_parser("doctor", help="Check config, gateway access and Playwright runtime")
    seal_parser = subparsers.add_parser("seal", help="Create encrypted credential file")
    seal_parser.add_argument("--from-config", action="store_true", help="Read plaintext username/password from the current config")
    seal_parser.add_argument("--output", default=None, help=f"Output path for encrypted credentials (default: {DEFAULT_CREDENTIAL_FILE_NAME})")
    seal_parser.add_argument(
        "--key-file",
        nargs="?",
        const="",
        default=None,
        help=f"Use key-file mode and write the generated key to this path (default: {DEFAULT_CREDENTIAL_KEY_FILE_NAME})",
    )
    return parser.parse_args(argv)


def read_auth_setting(path: Path) -> dict[str, str]:
    settings: dict[str, str] = {}
    if not path.exists():
        return settings
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        settings[key.strip()] = value.strip().strip('"')
    return settings


def _as_bool(value: Any, field_name: str) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        lowered = value.strip().lower()
        if lowered in {"1", "true", "yes", "on"}:
            return True
        if lowered in {"0", "false", "no", "off"}:
            return False
    raise ConfigError(f"{field_name} must be a boolean, got {value!r}")


def _as_int(value: Any, field_name: str) -> int:
    try:
        return int(value)
    except (TypeError, ValueError) as exc:
        raise ConfigError(f"{field_name} must be an integer, got {value!r}") from exc


def normalize_gateway_url(url: str) -> str:
    stripped = url.strip()
    if not stripped:
        raise ConfigError("Gateway URL cannot be empty")
    if not re.match(r"^https?://", stripped, re.IGNORECASE):
        stripped = f"http://{stripped}"
    return stripped.rstrip("/") + "/"


def dedupe_preserve_order(values: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for value in values:
        if value not in seen:
            seen.add(value)
            result.append(value)
    return result


def resolve_path_from_config(config_path: Path, value: Any, default_name: str | None = None) -> Path | None:
    raw = str(value or "").strip()
    if not raw:
        if default_name is None:
            return None
        raw = default_name
    path = Path(raw)
    if not path.is_absolute():
        path = config_path.parent / path
    return path.resolve()


def load_raw_config(config_path: Path) -> dict[str, Any]:
    if not config_path.exists():
        raise ConfigError(
            f"Config file not found: {config_path}. Copy {DEFAULT_SAMPLE_CONFIG_PATH.name} to {config_path.name} and fill in your credentials."
        )
    try:
        raw_config = json.loads(config_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Config file is not valid JSON: {config_path}") from exc
    if not isinstance(raw_config, dict):
        raise ConfigError("Config root must be a JSON object")
    return raw_config


def load_plain_credentials(raw_config: dict[str, Any]) -> tuple[str, str]:
    username = str(raw_config.get("username", "")).strip()
    password = str(raw_config.get("password", "")).strip()
    if not username or not password:
        raise ConfigError("Config must provide non-empty username and password")
    return username, password


def resolve_secret_passphrase(cli_passphrase: str | None) -> str | None:
    value = cli_passphrase if cli_passphrase is not None else os.environ.get(ENCRYPTED_CREDENTIALS_ENV_VAR)
    return value.strip() if isinstance(value, str) and value.strip() else None


def import_aesgcm():
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise DependencyError("cryptography is not installed. Install it with: pip install cryptography") from exc
    return AESGCM


def derive_passphrase_key(passphrase: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", passphrase.encode("utf-8"), salt, PBKDF2_ITERATIONS, dklen=32)


def _b64decode(value: Any, field_name: str) -> bytes:
    text = str(value or "").strip()
    if not text:
        return b""
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except Exception as exc:
        raise ConfigError(f"Invalid base64 data for {field_name}") from exc


def write_private_text(path: Path, text: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    if os.name != "nt":
        try:
            path.chmod(0o600)
        except OSError:
            pass


def read_key_file(path: Path) -> bytes:
    if not path.exists():
        raise ConfigError(f"Credential key file not found: {path}")
    key = _b64decode(path.read_text(encoding="utf-8"), "credential key")
    if len(key) != 32:
        raise ConfigError(f"Credential key file must decode to 32 bytes: {path}")
    return key


def encrypt_credentials(username: str, password: str, passphrase: str | None = None, key_file_path: Path | None = None) -> dict[str, Any]:
    AESGCM = import_aesgcm()
    if key_file_path is not None:
        key = os.urandom(32)
        scheme = "aesgcm-keyfile"
        salt = b""
        write_private_text(key_file_path, base64.b64encode(key).decode("ascii") + "\n")
    else:
        if not passphrase:
            raise ConfigError("A non-empty passphrase is required when --key-file is not used")
        key = derive_passphrase_key(passphrase, salt := os.urandom(16))
        scheme = "aesgcm-pbkdf2-sha256"
    nonce = os.urandom(12)
    payload = json.dumps({"username": username, "password": password}, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    ciphertext = AESGCM(key).encrypt(nonce, payload, None)
    return {
        "version": CREDENTIAL_FILE_VERSION,
        "scheme": scheme,
        "salt": base64.b64encode(salt).decode("ascii"),
        "nonce": base64.b64encode(nonce).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
    }


def decrypt_credentials(credential_file: Path, cli_passphrase: str | None = None, credential_key_file: Path | None = None) -> tuple[str, str]:
    if not credential_file.exists():
        raise ConfigError(f"Encrypted credential file not found: {credential_file}")
    try:
        payload = json.loads(credential_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        raise ConfigError(f"Encrypted credential file is not valid JSON: {credential_file}") from exc
    if not isinstance(payload, dict):
        raise ConfigError("Encrypted credential file root must be a JSON object")
    version = payload.get("version")
    if version != CREDENTIAL_FILE_VERSION:
        raise ConfigError(f"Unsupported credential file version: {version!r}")
    scheme = str(payload.get("scheme", "")).strip()
    salt = _b64decode(payload.get("salt"), "salt")
    nonce = _b64decode(payload.get("nonce"), "nonce")
    ciphertext = _b64decode(payload.get("ciphertext"), "ciphertext")
    if len(nonce) != 12:
        raise ConfigError("Encrypted credential file nonce must decode to 12 bytes")
    if not ciphertext:
        raise ConfigError("Encrypted credential file ciphertext cannot be empty")
    if scheme == "aesgcm-pbkdf2-sha256":
        passphrase = resolve_secret_passphrase(cli_passphrase)
        if not passphrase:
            raise ConfigError(
                f"Encrypted credentials require a passphrase. Provide --secret-passphrase or set {ENCRYPTED_CREDENTIALS_ENV_VAR}."
            )
        if len(salt) != 16:
            raise ConfigError("Encrypted credential file salt must decode to 16 bytes")
        key = derive_passphrase_key(passphrase, salt)
    elif scheme == "aesgcm-keyfile":
        if credential_key_file is None:
            raise ConfigError("Encrypted credentials require credential_key_file in the config")
        key = read_key_file(credential_key_file)
    else:
        raise ConfigError(f"Unsupported credential encryption scheme: {scheme!r}")
    AESGCM = import_aesgcm()
    try:
        plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
    except Exception as exc:
        raise ConfigError("Failed to decrypt encrypted credentials. Check the passphrase or key file.") from exc
    try:
        data = json.loads(plaintext.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ConfigError("Decrypted credential payload is invalid") from exc
    if not isinstance(data, dict):
        raise ConfigError("Decrypted credential payload must be a JSON object")
    return load_plain_credentials(data)


def load_credentials(
    raw_config: dict[str, Any],
    config_path: Path,
    secret_passphrase: str | None = None,
) -> tuple[str, str, Path | None, Path | None]:
    credential_file = resolve_path_from_config(config_path, raw_config.get("credential_file"))
    credential_key_file = resolve_path_from_config(config_path, raw_config.get("credential_key_file"))
    if credential_file is not None:
        username, password = decrypt_credentials(credential_file, secret_passphrase, credential_key_file)
        return username, password, credential_file, credential_key_file
    username, password = load_plain_credentials(raw_config)
    return username, password, None, credential_key_file


def load_config(
    config_path: Path | None = None,
    auth_setting_path: Path | None = None,
    secret_passphrase: str | None = None,
) -> Config:
    config_path = (config_path or DEFAULT_CONFIG_PATH).resolve()
    auth_setting_path = (auth_setting_path or DEFAULT_AUTH_SETTING_PATH).resolve()
    raw_config = load_raw_config(config_path)
    auth_settings = read_auth_setting(auth_setting_path)
    username, password, credential_file, credential_key_file = load_credentials(raw_config, config_path, secret_passphrase)
    raw_gateway_urls = raw_config.get("gateway_urls") or DEFAULT_GATEWAY_URLS
    if not isinstance(raw_gateway_urls, list) or not raw_gateway_urls:
        raise ConfigError("gateway_urls must be a non-empty list")
    merged_gateways = [normalize_gateway_url(str(item)) for item in raw_gateway_urls]
    if auth_settings.get("campus_url"):
        merged_gateways.insert(0, normalize_gateway_url(auth_settings["campus_url"]))
    if auth_settings.get("host"):
        merged_gateways.append(normalize_gateway_url(auth_settings["host"]))
    ac_id = str(raw_config.get("ac_id") or auth_settings.get("acid") or "").strip()
    if not ac_id:
        raise ConfigError("ac_id is missing in both connection.local.json and .auth-setting")
    raw_probe_urls = raw_config.get("probe_urls") or DEFAULT_PROBE_URLS
    if not isinstance(raw_probe_urls, list) or not raw_probe_urls:
        raise ConfigError("probe_urls must be a non-empty list")
    return Config(
        username=username,
        password=password,
        gateway_urls=dedupe_preserve_order(merged_gateways),
        ac_id=ac_id,
        check_interval_seconds=max(5, _as_int(raw_config.get("check_interval_seconds", DEFAULT_CHECK_INTERVAL_SECONDS), "check_interval_seconds")),
        probe_urls=[ProbeTarget.from_raw(item) for item in raw_probe_urls],
        auth_timeout_seconds=max(2, _as_int(raw_config.get("auth_timeout_seconds", DEFAULT_AUTH_TIMEOUT_SECONDS), "auth_timeout_seconds")),
        http_auth_retry_count=max(1, _as_int(raw_config.get("http_auth_retry_count", DEFAULT_HTTP_AUTH_RETRY_COUNT), "http_auth_retry_count")),
        headless_fallback_enabled=_as_bool(raw_config.get("headless_fallback_enabled", True), "headless_fallback_enabled"),
        headless_fallback_after_failures=max(1, _as_int(raw_config.get("headless_fallback_after_failures", DEFAULT_HEADLESS_FALLBACK_AFTER_FAILURES), "headless_fallback_after_failures")),
        headless_timeout_seconds=max(10, _as_int(raw_config.get("headless_timeout_seconds", DEFAULT_HEADLESS_TIMEOUT_SECONDS), "headless_timeout_seconds")),
        log_file=str(raw_config.get("log_file", "connection.log")),
        log_max_bytes=max(1024, _as_int(raw_config.get("log_max_bytes", DEFAULT_LOG_MAX_BYTES), "log_max_bytes")),
        log_backup_count=max(1, _as_int(raw_config.get("log_backup_count", DEFAULT_LOG_BACKUP_COUNT), "log_backup_count")),
        config_path=config_path,
        credential_file=credential_file,
        credential_key_file=credential_key_file,
    )


def setup_logger(config: Config) -> logging.Logger:
    logger = logging.getLogger("buaa_connection")
    logger.setLevel(logging.INFO)
    logger.handlers.clear()
    logger.propagate = False
    formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    logger.addHandler(stream_handler)
    log_path = Path(config.log_file)
    if not log_path.is_absolute():
        log_path = SCRIPT_DIR / log_path
    log_path.parent.mkdir(parents=True, exist_ok=True)
    file_handler = RotatingFileHandler(log_path, maxBytes=config.log_max_bytes, backupCount=config.log_backup_count, encoding="utf-8")
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    return logger


def create_session() -> Session:
    require_requests()
    session = requests.Session()
    session.headers.update(
        {
            "User-Agent": (
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36"
            )
        }
    )
    return session


def build_callback() -> str:
    return f"jQuery{random.randint(10**9, 10**10 - 1)}_{int(time.time() * 1000)}"


def parse_jsonp(payload: str) -> dict[str, Any]:
    text = payload.strip()
    if not text:
        raise ValueError("Empty response body")
    if text.startswith("{") and text.endswith("}"):
        return json.loads(text)
    match = re.match(r"^[^(]+\((.*)\)\s*;?\s*$", text, re.DOTALL)
    if not match:
        raise ValueError(f"Unsupported JSONP payload: {payload[:80]!r}")
    return json.loads(match.group(1))


def unsigned_right_shift(value: int, bits: int) -> int:
    return (value & 0xFFFFFFFF) >> bits


def int32(value: int) -> int:
    return c_int32(value).value


def to_uint32_list(data: bytes, include_length: bool) -> list[int]:
    result: list[int] = []
    for index in range(0, len(data), 4):
        chunk = data[index : index + 4]
        value = 0
        for offset, byte in enumerate(chunk):
            value |= byte << (offset * 8)
        result.append(int32(value))
    if include_length:
        result.append(len(data))
    return result


def from_uint32_list(values: list[int], include_length: bool) -> bytes:
    output = bytearray()
    for value in values:
        unsigned = value & 0xFFFFFFFF
        output.extend((unsigned & 0xFF, (unsigned >> 8) & 0xFF, (unsigned >> 16) & 0xFF, (unsigned >> 24) & 0xFF))
    if include_length:
        data_length = values[-1]
        if data_length < 0 or data_length > len(output):
            raise ValueError("Invalid encoded length")
        return bytes(output[:data_length])
    return bytes(output)


def xencode(message: str, key: str) -> bytes:
    if not message:
        return b""
    v = to_uint32_list(message.encode("utf-8"), True)
    k = to_uint32_list(key.encode("utf-8"), False)
    while len(k) < 4:
        k.append(0)
    n = len(v) - 1
    z = v[n]
    c = -1640531527
    q = math.floor(6 + 52 / (n + 1))
    d = 0
    while q > 0:
        d = int32(d + c)
        e = unsigned_right_shift(d, 2) & 3
        for p in range(n):
            y = v[p + 1]
            mix = unsigned_right_shift(z, 5) ^ (y << 2)
            mix = int32(mix + ((unsigned_right_shift(y, 3) ^ (z << 4)) ^ (d ^ y)))
            mix = int32(mix + (k[(p & 3) ^ e] ^ z))
            v[p] = int32(v[p] + mix)
            z = v[p]
        y = v[0]
        mix = unsigned_right_shift(z, 5) ^ (y << 2)
        mix = int32(mix + ((unsigned_right_shift(y, 3) ^ (z << 4)) ^ (d ^ y)))
        mix = int32(mix + (k[(n & 3) ^ e] ^ z))
        v[n] = int32(v[n] + mix)
        z = v[n]
        q -= 1
    return from_uint32_list(v, False)


def custom_base64_encode(data: bytes) -> str:
    if not data:
        return ""
    import base64

    standard_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
    return base64.b64encode(data).decode("ascii").translate(str.maketrans(standard_alphabet, SRUN_BASE64_ALPHABET))


def hmac_md5_hex(password: str, token: str) -> str:
    return hmac.new(token.encode("utf-8"), password.encode("utf-8"), md5).hexdigest()


def encode_info(username: str, password: str, ip_address: str, ac_id: str, token: str) -> str:
    info_json = json.dumps({"username": username, "password": password, "ip": ip_address, "acid": ac_id, "enc_ver": "srun_bx1"}, separators=(",", ":"), ensure_ascii=False)
    return "{SRBX1}" + custom_base64_encode(xencode(info_json, token))


def build_chksum(token: str, username: str, hmd5: str, ac_id: str, ip_address: str, info: str, n: str = "200", auth_type: str = "1") -> str:
    raw = token + username + token + hmd5 + token + ac_id + token + ip_address + token + n + token + auth_type + token + info
    return sha1(raw.encode("utf-8")).hexdigest()


def join_gateway_url(base_url: str, endpoint: str) -> str:
    return urljoin(base_url.rstrip("/") + "/", endpoint.lstrip("/"))


def response_indicates_success(data: dict[str, Any]) -> bool:
    values = " ".join(str(data.get(key) or "").strip().lower() for key in ("res", "error", "suc_msg", "error_msg"))
    return any(token in values for token in ("ok", "login_ok", "login is successful", "already online", "ip_already_online_error"))


def detect_config_permission_warning(config_path: Path) -> str | None:
    if os.name == "nt":
        return "Windows: keep config and credential files under a user-only directory."
    mode = config_path.stat().st_mode & 0o777
    if mode & 0o077:
        return f"Linux permissions are too open for {config_path.name}: {oct(mode)}. Recommended: chmod 600 {config_path.name}"
    return None


def next_backoff_seconds(previous_backoff_seconds: int, minimum_seconds: int = DEFAULT_CHECK_INTERVAL_SECONDS) -> int:
    if previous_backoff_seconds <= 0:
        return max(minimum_seconds, DEFAULT_INITIAL_BACKOFF_SECONDS)
    return min(max(previous_backoff_seconds * 2, minimum_seconds), DEFAULT_MAX_BACKOFF_SECONDS)


def prompt_non_empty(prompt_text: str, secret: bool = False) -> str:
    while True:
        value = (getpass(prompt_text) if secret else input(prompt_text)).strip()
        if value:
            return value
        print("error=Input cannot be empty.", file=sys.stderr)


def prompt_passphrase() -> str:
    while True:
        passphrase = getpass("Secret passphrase: ").strip()
        if not passphrase:
            print("error=Passphrase cannot be empty.", file=sys.stderr)
            continue
        confirm = getpass("Confirm passphrase: ").strip()
        if passphrase != confirm:
            print("error=Passphrases did not match.", file=sys.stderr)
            continue
        return passphrase


def write_encrypted_credentials_file(
    output_path: Path,
    username: str,
    password: str,
    passphrase: str | None = None,
    key_file_path: Path | None = None,
) -> None:
    if output_path.exists():
        raise ConfigError(f"Refusing to overwrite existing credential file: {output_path}")
    if key_file_path is not None and key_file_path.exists():
        raise ConfigError(f"Refusing to overwrite existing credential key file: {key_file_path}")
    payload = encrypt_credentials(username, password, passphrase, key_file_path)
    write_private_text(output_path, json.dumps(payload, indent=2, ensure_ascii=False) + "\n")


def seal_credentials(args: argparse.Namespace) -> int:
    config_path = Path(args.config).resolve()
    output_path = resolve_path_from_config(config_path, args.output, DEFAULT_CREDENTIAL_FILE_NAME)
    if output_path is None:
        raise ConfigError("Failed to resolve the encrypted credential output path")
    key_file_path = resolve_path_from_config(config_path, args.key_file, DEFAULT_CREDENTIAL_KEY_FILE_NAME) if args.key_file else None
    if args.from_config:
        raw_config = load_raw_config(config_path)
        username, password = load_plain_credentials(raw_config)
    else:
        username = prompt_non_empty("Username: ")
        password = prompt_non_empty("Password: ", secret=True)
    if key_file_path is not None:
        write_encrypted_credentials_file(output_path, username, password, key_file_path=key_file_path)
        print(f"credential_file={output_path}")
        print(f"credential_key_file={key_file_path}")
    else:
        write_encrypted_credentials_file(output_path, username, password, passphrase=prompt_passphrase())
        print(f"credential_file={output_path}")
        print(f"secret_env_var={ENCRYPTED_CREDENTIALS_ENV_VAR}")
    print("message=Add credential_file to your config and remove plaintext username/password after verifying.")
    return 0


class CampusAuthService:
    def __init__(self, config: Config, session: Session | None = None, logger: logging.Logger | None = None, sleep_func=time.sleep) -> None:
        self.config = config
        self.session = session or create_session()
        self.logger = logger or setup_logger(config)
        self.sleep_func = sleep_func
        self.cached_gateway_url: str | None = None
        self.stop_requested = False

    def request_stop(self, *_args: object) -> None:
        self.stop_requested = True
        self.logger.info("Stop requested, exiting after current cycle.")

    def probe_internet(self) -> bool:
        for target in self.config.probe_urls:
            try:
                response = self.session.get(target.url, timeout=min(5, self.config.auth_timeout_seconds), allow_redirects=False)
            except RequestException:
                continue
            if target.expect_status is not None and response.status_code != target.expect_status:
                continue
            if target.expect_text is not None and target.expect_text not in response.text:
                continue
            return True
        return False

    def probe_gateway_url(self, gateway_url: str) -> bool:
        try:
            response = self.session.get(gateway_url, timeout=self.config.auth_timeout_seconds, allow_redirects=False, verify=False)
        except RequestException:
            return False
        return response.status_code < 500

    def resolve_gateway_url(self) -> str | None:
        candidates = self.config.gateway_urls
        if self.cached_gateway_url:
            candidates = [self.cached_gateway_url] + [url for url in candidates if url != self.cached_gateway_url]
        for gateway_url in candidates:
            if self.probe_gateway_url(gateway_url):
                self.cached_gateway_url = gateway_url
                return gateway_url
        return None

    def get_challenge(self, gateway_url: str) -> tuple[str, str]:
        response = self.session.get(
            join_gateway_url(gateway_url, "cgi-bin/get_challenge"),
            params={
                "callback": build_callback(),
                "username": self.config.username,
                "ip": "",
                "_": int(time.time() * 1000),
            },
            timeout=self.config.auth_timeout_seconds,
            verify=False,
        )
        response.raise_for_status()
        payload = parse_jsonp(response.text)
        token = str(payload.get("challenge", "")).strip()
        ip_address = str(payload.get("client_ip") or payload.get("online_ip") or "").strip()
        if not token:
            raise RuntimeError(f"Challenge token missing in response: {payload}")
        return token, ip_address

    def authenticate_via_http(self, gateway_url: str) -> AuthResult:
        os_name = platform.system() or "Unknown"
        for attempt in range(1, self.config.http_auth_retry_count + 1):
            try:
                token, ip_address = self.get_challenge(gateway_url)
                hmd5 = hmac_md5_hex(self.config.password, token)
                info = encode_info(self.config.username, self.config.password, ip_address, self.config.ac_id, token)
                chksum = build_chksum(token, self.config.username, hmd5, self.config.ac_id, ip_address, info)
                response = self.session.get(
                    join_gateway_url(gateway_url, "cgi-bin/srun_portal"),
                    params={
                        "callback": build_callback(),
                        "action": "login",
                        "username": self.config.username,
                        "password": "{MD5}" + hmd5,
                        "ac_id": self.config.ac_id,
                        "ip": ip_address,
                        "chksum": chksum,
                        "info": info,
                        "n": "200",
                        "type": "1",
                        "os": os_name,
                        "name": os_name,
                        "double_stack": "0",
                        "_": int(time.time() * 1000),
                    },
                    timeout=self.config.auth_timeout_seconds,
                    verify=False,
                )
                response.raise_for_status()
                payload = parse_jsonp(response.text)
                if not response_indicates_success(payload):
                    message = str(payload.get("error_msg") or payload.get("suc_msg") or payload.get("error") or payload.get("res") or "Authentication rejected by gateway")
                    self.logger.warning("HTTP auth rejected on attempt %s: %s", attempt, message)
                    continue
                self.sleep_func(POST_AUTH_SETTLE_SECONDS)
                if self.probe_internet():
                    return AuthResult(True, "http", str(payload.get("suc_msg") or "HTTP authentication succeeded"), gateway_url, payload)
                self.logger.warning("Gateway accepted HTTP auth on attempt %s but internet probe still failed.", attempt)
            except (RequestException, ValueError, RuntimeError) as exc:
                self.logger.warning("HTTP auth attempt %s failed: %s", attempt, exc)
        return AuthResult(False, "http", "HTTP authentication failed after retries", gateway_url)

    def _fill_first_visible(self, page, selectors: list[str], value: str):
        for selector in selectors:
            locator = page.locator(selector)
            count = min(locator.count(), 3)
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if candidate.is_visible():
                        candidate.fill(value)
                        return candidate
                except Exception:
                    continue
        raise RuntimeError(f"No visible input matched selectors: {selectors}")

    def _click_first_visible(self, page, selectors: list[str]) -> bool:
        for selector in selectors:
            locator = page.locator(selector)
            count = min(locator.count(), 3)
            for index in range(count):
                candidate = locator.nth(index)
                try:
                    if candidate.is_visible():
                        candidate.click()
                        return True
                except Exception:
                    continue
        return False

    def authenticate_via_headless(self, gateway_url: str) -> AuthResult:
        sync_playwright, _, PlaywrightTimeoutError = import_playwright_sync()
        timeout_ms = self.config.headless_timeout_seconds * 1000
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                context = browser.new_context(ignore_https_errors=True)
                page = context.new_page()
                page.goto(gateway_url, wait_until="domcontentloaded", timeout=timeout_ms)
                username_field = self._fill_first_visible(page, USERNAME_SELECTORS, self.config.username)
                self._fill_first_visible(page, PASSWORD_SELECTORS, self.config.password)
                if not self._click_first_visible(page, SUBMIT_SELECTORS):
                    username_field.press("Tab")
                    page.keyboard.press("Enter")
                page.wait_for_load_state("networkidle", timeout=timeout_ms)
                page.wait_for_timeout(POST_AUTH_SETTLE_SECONDS * 1000)
                browser.close()
        except DependencyError:
            raise
        except PlaywrightTimeoutError as exc:
            return AuthResult(False, "headless", f"Headless browser timeout: {exc}", gateway_url)
        except Exception as exc:
            return AuthResult(False, "headless", f"Headless browser auth failed: {exc}", gateway_url)
        if self.probe_internet():
            return AuthResult(True, "headless", "Headless browser authentication succeeded", gateway_url)
        return AuthResult(False, "headless", "Headless browser submitted the form but internet probe still failed", gateway_url)

    def check_headless_runtime(self) -> str | None:
        if not self.config.headless_fallback_enabled:
            return None
        sync_playwright, _, _ = import_playwright_sync()
        try:
            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                browser.close()
        except Exception as exc:
            return "Playwright is installed but Chromium could not be started. Run 'playwright install chromium'. Details: " + str(exc)
        return None

    def get_status(self) -> StatusReport:
        dependency_issue = None
        if self.config.headless_fallback_enabled:
            try:
                dependency_issue = self.check_headless_runtime()
            except DependencyError as exc:
                dependency_issue = str(exc)
        warning = detect_config_permission_warning(self.config.config_path)
        if dependency_issue:
            return StatusReport("dependency_missing", False, None, dependency_issue, warning)
        if self.probe_internet():
            return StatusReport("online", True, self.cached_gateway_url, None, warning)
        gateway_url = self.resolve_gateway_url()
        if gateway_url:
            return StatusReport("needs_auth", False, gateway_url, None, warning)
        return StatusReport("gateway_unreachable", False, None, None, warning)

    def run_once(self) -> int:
        status = self.get_status()
        print(f"state={status.state}")
        if status.gateway_url:
            print(f"gateway_url={status.gateway_url}")
        if status.dependency_issue:
            print(f"dependency_issue={status.dependency_issue}")
        if status.config_warning:
            print(f"config_warning={status.config_warning}")
        return 0 if status.state == "online" else 1

    def doctor(self) -> int:
        print(f"config_path={self.config.config_path}")
        warning = detect_config_permission_warning(self.config.config_path)
        if warning:
            print(f"config_warning={warning}")
        online = self.probe_internet()
        gateway_url = self.resolve_gateway_url()
        print(f"internet_online={online}")
        print(f"gateway_reachable={bool(gateway_url)}")
        if gateway_url:
            print(f"gateway_url={gateway_url}")
        if self.config.headless_fallback_enabled:
            try:
                issue = self.check_headless_runtime()
            except DependencyError as exc:
                issue = str(exc)
            if issue:
                print("playwright=unavailable")
                print(f"playwright_issue={issue}")
                return 1
            print("playwright=ok")
        else:
            print("playwright=disabled")
        return 0 if gateway_url else 1

    def authenticate_now(self) -> int:
        gateway_url = self.resolve_gateway_url()
        if not gateway_url:
            self.logger.error("No reachable BUAA gateway found. Refusing to authenticate blindly.")
            return 1
        result = self.authenticate_via_http(gateway_url)
        print(f"method={result.method}")
        print(f"message={result.message}")
        if result.success:
            self.logger.info(result.message)
            return 0
        self.logger.error(result.message)
        return 1

    def run_forever(self) -> int:
        if self.config.headless_fallback_enabled:
            issue = self.check_headless_runtime()
            if issue:
                raise DependencyError(issue)
        signal.signal(signal.SIGINT, signal.default_int_handler)
        try:
            signal.signal(signal.SIGTERM, self.request_stop)
        except AttributeError:  # pragma: no cover
            pass
        consecutive_auth_failures = 0
        backoff_seconds = 0
        self.logger.info("Starting monitoring loop. interval=%ss", self.config.check_interval_seconds)
        while not self.stop_requested:
            if self.probe_internet():
                if consecutive_auth_failures:
                    self.logger.info("Connectivity restored, clearing failure counters.")
                consecutive_auth_failures = 0
                backoff_seconds = 0
                self.sleep_func(self.config.check_interval_seconds)
                continue
            gateway_url = self.resolve_gateway_url()
            if not gateway_url:
                self.logger.warning("Internet is down and BUAA gateway is unreachable. Waiting for next check.")
                self.sleep_func(self.config.check_interval_seconds)
                continue
            use_headless = self.config.headless_fallback_enabled and consecutive_auth_failures >= self.config.headless_fallback_after_failures
            result = self.authenticate_via_headless(gateway_url) if use_headless else self.authenticate_via_http(gateway_url)
            if result.success:
                self.logger.info("%s auth succeeded via %s.", gateway_url, result.method)
                consecutive_auth_failures = 0
                backoff_seconds = 0
                self.sleep_func(self.config.check_interval_seconds)
                continue
            consecutive_auth_failures += 1
            backoff_seconds = next_backoff_seconds(backoff_seconds, self.config.check_interval_seconds)
            self.logger.warning(
                "%s auth failed via %s. consecutive_failures=%s next_retry_in=%ss",
                gateway_url,
                result.method,
                consecutive_auth_failures,
                backoff_seconds,
            )
            self.sleep_func(backoff_seconds)
        return 0


def build_service(config_path: Path, secret_passphrase: str | None = None) -> CampusAuthService:
    config = load_config(config_path=config_path, secret_passphrase=secret_passphrase)
    return CampusAuthService(config=config, logger=setup_logger(config))


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    try:
        if args.command == "seal":
            return seal_credentials(args)
        service = build_service(Path(args.config), secret_passphrase=args.secret_passphrase)
        if args.command == "run":
            return service.run_forever()
        if args.command == "status":
            return service.run_once()
        if args.command == "auth":
            return service.authenticate_now()
        if args.command == "doctor":
            return service.doctor()
        raise RuntimeError(f"Unsupported command: {args.command}")
    except (ConfigError, DependencyError) as exc:
        print(f"error={exc}", file=sys.stderr)
        return 2
    except KeyboardInterrupt:
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
