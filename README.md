# BUAA 校园网自动认证脚本

适用于 Windows / Linux 的简单脚本，用来定时检查联网状态，并在北航校园网环境下自动完成 `gw.buaa.edu.cn` 认证。目标应用场景为工位有网线情况下的远程连接。

功能：
1. 检查外网是否已经正常可用。
2. 如果外网不可用，再检查北航网关是否可达。
只有在“外网不通，但北航网关可达”时，脚本才会尝试认证。

认证分两层：
- 第一层是直接调用校园网网关接口，发送 Srun/深澜认证请求，资源占用最低。
- 如果连续多次失败，并启用兜底功能，脚本会尝试使用无头浏览器自动打开认证页并提交账号密码（未测试）。

## 依赖

- Python 3.10+
- `requests`
- `cryptography`（启用加密凭据时需要）
- 可选：`playwright` 与 Chromium

安装示例：

```bash
pip install requests
pip install cryptography
pip install playwright
playwright install chromium
```

如果不需要无头浏览器兜底，可以在配置里把 `headless_fallback_enabled` 设为 `false`，这样就不需要 `playwright`。

## 配置

先复制样例配置：

```bash
copy connection.sample.json connection.local.json
```

Linux / macOS 可用：

```bash
cp connection.sample.json connection.local.json
```

明文方式下，编辑 `connection.local.json`，至少填写：

```json
{
  "username": "学号",
  "password": "密码"
}
```

如果希望避免把账号密码明文保存在 JSON 中，可以改用加密凭据文件：

```json
{
  "credential_file": "connection.credentials.enc"
}
```

如果使用密钥文件自动解密，再额外加上：

```json
{
  "credential_file": "connection.credentials.enc",
  "credential_key_file": "connection.credentials.key"
}
```

常用配置项：

- `username`：校园网账号
- `password`：校园网密码
- `credential_file`：加密后的账号密码文件路径，配置后优先于明文 `username/password`
- `credential_key_file`：密钥文件路径，仅在密钥文件自动解密模式下使用
- `gateway_urls`：候选网关地址
- `ac_id`：认证区域 ID，默认可用 `67`
- `check_interval_seconds`：检查间隔，默认 `60`
- `http_auth_retry_count`：每轮 HTTP 认证重试次数
- `headless_fallback_enabled`：是否启用无头浏览器兜底
- `headless_fallback_after_failures`：连续失败多少次后启用兜底
- `headless_timeout_seconds`：无头浏览器超时时间

## 加密凭据

首次录入账号密码时，推荐使用交互式命令生成密文文件：

```bash
python connection.py seal
```

命令会：

1. 提示输入用户名
2. 提示输入密码（不回显）
3. 提示输入解密口令并生成 `connection.credentials.enc`

如果已经在 `connection.local.json` 中写了明文账号密码，也可以直接迁移：

```bash
python connection.py seal --from-config
```

如果希望使用独立密钥文件实现无人值守自动解密，可以这样生成：

```bash
python connection.py seal --from-config --key-file
```

生成后建议把 `connection.local.json` 改成只保留非敏感配置，例如：

```json
{
  "credential_file": "connection.credentials.enc",
  "gateway_urls": [
    "https://gw.buaa.edu.cn/",
    "http://gw.buaa.edu.cn:801/",
    "http://10.111.3.3/"
  ],
  "ac_id": "67",
  "check_interval_seconds": 60,
  "headless_fallback_enabled": true
}
```

如果使用“口令解密”模式，运行时提供口令：

```bash
python connection.py --secret-passphrase "你的解密口令" run
```

或者通过环境变量提供：

```bash
set BUAA_CONNECTION_SECRET=你的解密口令
python connection.py run
```

Linux / macOS 可用：

```bash
export BUAA_CONNECTION_SECRET='你的解密口令'
python connection.py run
```

如果使用“密钥文件自动解密”模式，并且配置里已经写了 `credential_key_file`，则无需再额外传入口令。

## 用法

检查当前状态：

```bash
python connection.py status
```

检查配置、网关和 Playwright 运行环境：

```bash
python connection.py doctor
```

立即尝试一次 HTTP 认证：

```bash
python connection.py auth
```

启动常驻监控：

```bash
python connection.py run
```

如果配置文件不在默认位置，可以显式指定：

```bash
python connection.py --config /path/to/connection.local.json run
```

查看加密凭据命令帮助：

```bash
python connection.py seal --help
```

## 日志

脚本会把运行日志写到 `connection.log`，默认开启轮转，不会无限增长。

常见日志含义：

- `state=online`：当前已经联网
- `state=needs_auth`：检测到需要校园网认证
- `ip_already_online_error`：当前 IP 实际已经在线，通常不算故障
- `auth_info_error`：认证参数构造错误，通常是协议实现问题，不是账号密码错误
