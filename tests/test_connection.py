import json
import tempfile
import unittest
from hashlib import md5
import hmac
from pathlib import Path
from unittest.mock import Mock, patch

import connection


class FakeResponse:
    def __init__(self, text="", status_code=200):
        self.text = text
        self.status_code = status_code

    def raise_for_status(self):
        if self.status_code >= 400:
            raise connection.RequestException(f"HTTP {self.status_code}")


class CampusConnectionTests(unittest.TestCase):
    @staticmethod
    def reference_xencode(msg: str, key: str) -> bytes:
        def sencode(text: str, include_length: bool):
            values = []
            for index in range(0, len(text), 4):
                values.append(
                    ord(text[index])
                    | (ord(text[index + 1]) << 8 if index + 1 < len(text) else 0)
                    | (ord(text[index + 2]) << 16 if index + 2 < len(text) else 0)
                    | (ord(text[index + 3]) << 24 if index + 3 < len(text) else 0)
                )
            if include_length:
                values.append(len(text))
            return values

        def lencode(values):
            chars = []
            for value in values:
                chars.append(chr(value & 0xFF))
                chars.append(chr((value >> 8) & 0xFF))
                chars.append(chr((value >> 16) & 0xFF))
                chars.append(chr((value >> 24) & 0xFF))
            return "".join(chars)

        pwd = sencode(msg, True)
        pwdk = sencode(key, False)
        if len(pwdk) < 4:
            pwdk += [0] * (4 - len(pwdk))
        n = len(pwd) - 1
        z = pwd[n]
        y = pwd[0]
        c = 0x86014019 | 0x183639A0
        q = int(6 + 52 / (n + 1))
        d = 0
        while q > 0:
            d = d + c & (0x8CE0D9BF | 0x731F2640)
            e = d >> 2 & 3
            p = 0
            while p < n:
                y = pwd[p + 1]
                m = z >> 5 ^ y << 2
                m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
                m = m + (pwdk[(p & 3) ^ e] ^ z)
                pwd[p] = pwd[p] + m & (0xEFB8D130 | 0x10472ECF)
                z = pwd[p]
                p += 1
            y = pwd[0]
            m = z >> 5 ^ y << 2
            m = m + ((y >> 3 ^ z << 4) ^ (d ^ y))
            m = m + (pwdk[(p & 3) ^ e] ^ z)
            pwd[n] = pwd[n] + m & (0xBB390742 | 0x44C6F8BD)
            z = pwd[n]
            q -= 1
        return lencode(pwd).encode("latin1")

    def test_load_config_merges_auth_setting(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            temp_path = Path(temp_dir)
            config_path = temp_path / "connection.local.json"
            auth_setting_path = temp_path / ".auth-setting"
            config_path.write_text(
                json.dumps(
                    {
                        "username": "by1234567",
                        "password": "secret",
                        "gateway_urls": ["https://gw.buaa.edu.cn/"],
                        "probe_urls": ["http://example.com/ping"],
                        "headless_fallback_enabled": False,
                    }
                ),
                encoding="utf-8",
            )
            auth_setting_path.write_text('host="10.111.3.3"\nacid="67"\n', encoding="utf-8")

            loaded = connection.load_config(config_path=config_path, auth_setting_path=auth_setting_path)

            self.assertEqual(loaded.ac_id, "67")
            self.assertEqual(loaded.gateway_urls[-1], "http://10.111.3.3/")
            self.assertEqual(loaded.probe_urls[0].url, "http://example.com/ping")

    def test_parse_jsonp(self):
        payload = 'jQuery123_456({"res":"ok","client_ip":"10.0.0.2"})'
        parsed = connection.parse_jsonp(payload)
        self.assertEqual(parsed["res"], "ok")
        self.assertEqual(parsed["client_ip"], "10.0.0.2")

    def test_hmac_md5_known_value(self):
        self.assertEqual(
            connection.hmac_md5_hex("password", "token"),
            hmac.new(b"token", b"password", md5).hexdigest(),
        )

    def test_xencode_matches_reference_implementation(self):
        payload = '{"username":"by1234567","password":"secret","ip":"10.0.0.8","acid":"67","enc_ver":"srun_bx1"}'
        token = "token123"
        self.assertEqual(
            connection.xencode(payload, token),
            self.reference_xencode(payload, token),
        )

    def test_next_backoff_seconds_caps_at_maximum(self):
        value = 0
        for _ in range(10):
            value = connection.next_backoff_seconds(value)
        self.assertEqual(value, connection.DEFAULT_MAX_BACKOFF_SECONDS)

    def test_authenticate_via_http_success(self):
        config = connection.Config(
            username="by1234567",
            password="secret",
            gateway_urls=["http://10.111.3.3/"],
            ac_id="67",
            probe_urls=[connection.ProbeTarget(url="http://example.com/ping", expect_status=204)],
            headless_fallback_enabled=False,
        )
        session = Mock()
        session.get.side_effect = [
            FakeResponse('jQuery1({"challenge":"token123","client_ip":"10.0.0.8","res":"ok"})'),
            FakeResponse('jQuery2({"res":"ok","error":"ok","suc_msg":"Login is successful"})'),
        ]
        service = connection.CampusAuthService(config=config, session=session, logger=Mock(), sleep_func=lambda _seconds: None)
        service.probe_internet = Mock(return_value=True)

        result = service.authenticate_via_http("http://10.111.3.3/")

        self.assertTrue(result.success)
        self.assertEqual(result.method, "http")
        self.assertIn("successful", result.message.lower())

    def test_status_reports_dependency_missing(self):
        config = connection.Config(
            username="by1234567",
            password="secret",
            gateway_urls=["http://10.111.3.3/"],
            ac_id="67",
            probe_urls=[connection.ProbeTarget(url="http://example.com/ping", expect_status=204)],
        )
        service = connection.CampusAuthService(config=config, session=Mock(), logger=Mock(), sleep_func=lambda _seconds: None)
        with patch.object(service, "check_headless_runtime", return_value="missing playwright"):
            status = service.get_status()
        self.assertEqual(status.state, "dependency_missing")
        self.assertIn("missing", status.dependency_issue)


if __name__ == "__main__":
    unittest.main()
