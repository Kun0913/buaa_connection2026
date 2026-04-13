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
- 可选：`playwright` 与 Chromium

安装示例：

```bash
pip install requests
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

然后编辑 `connection.local.json`，至少填写：

```json
{
  "username": "学号",
  "password": "密码"
}
```

常用配置项：

- `username`：校园网账号
- `password`：校园网密码
- `gateway_urls`：候选网关地址
- `ac_id`：认证区域 ID，默认可用 `67`
- `check_interval_seconds`：检查间隔，默认 `60`
- `http_auth_retry_count`：每轮 HTTP 认证重试次数
- `headless_fallback_enabled`：是否启用无头浏览器兜底
- `headless_fallback_after_failures`：连续失败多少次后启用兜底
- `headless_timeout_seconds`：无头浏览器超时时间

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

## 日志

脚本会把运行日志写到 `connection.log`，默认开启轮转，不会无限增长。

常见日志含义：

- `state=online`：当前已经联网
- `state=needs_auth`：检测到需要校园网认证
- `ip_already_online_error`：当前 IP 实际已经在线，通常不算故障
- `auth_info_error`：认证参数构造错误，通常是协议实现问题，不是账号密码错误
