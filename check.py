#!/usr/bin/env python3
"""wenshucha 全站健康检查 — 每 15 分钟 cron / launchd 跑
- 检查 HTTP 200、关键词、SSL 到期、响应时间
- 状态变化 / 连续失败时发微信告警
- 历史日志写 logs/check-YYYY-MM-DD.jsonl
"""
import json
import os
import ssl
import socket
import subprocess
import sys
import time
import urllib.request
import urllib.error
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

try:
    import yaml
except ImportError:
    print("ERROR: pyyaml not installed. Run: pip3 install pyyaml")
    sys.exit(2)

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.yml"
LOGS_DIR = ROOT / "logs"
STATE_PATH = ROOT / "state.json"  # 记录每个站点上次状态 + 连续失败计数
LOGS_DIR.mkdir(exist_ok=True)

# iMessage 是主告警通道(微信 iLink 限流不稳);双通道都试,任一成功即可
NOTIFY_IMESSAGE = Path.home() / ".claude/bin/notify-imessage.sh"
NOTIFY_WECHAT = Path.home() / ".claude/bin/notify-wechat.py"


def now_iso() -> str:
    return datetime.now(timezone.utc).astimezone().strftime("%Y-%m-%d %H:%M:%S %z")


def load_state() -> dict:
    if STATE_PATH.exists():
        try:
            return json.loads(STATE_PATH.read_text())
        except Exception:
            return {}
    return {}


def save_state(state: dict) -> None:
    STATE_PATH.write_text(json.dumps(state, indent=2, ensure_ascii=False))


def notify(msg: str) -> None:
    """告警通知 — 优先 iMessage(主通道,osascript),失败回退微信(hermes)"""
    sent = False

    # 主通道:iMessage(osascript → Messages.app → +8615627388666)
    if NOTIFY_IMESSAGE.exists() and os.access(NOTIFY_IMESSAGE, os.X_OK):
        try:
            r = subprocess.run(
                [str(NOTIFY_IMESSAGE), msg],
                timeout=20,
                check=False,
                capture_output=True,
                text=True,
            )
            if r.returncode == 0:
                sent = True
                print(f"[notify-imessage OK]")
            else:
                print(f"[notify-imessage fail rc={r.returncode}] {r.stderr[:200]}")
        except Exception as e:
            print(f"[notify-imessage error] {e}")

    # 回退通道:微信(iLink 可能限流但聊胜于无)
    if not sent and NOTIFY_WECHAT.exists() and os.access(NOTIFY_WECHAT, os.X_OK):
        try:
            r = subprocess.run(
                [str(NOTIFY_WECHAT), msg],
                timeout=20,
                check=False,
                capture_output=True,
                text=True,
            )
            if r.returncode == 0 and "rate limited" not in (r.stderr or ""):
                sent = True
                print(f"[notify-wechat OK]")
            else:
                print(f"[notify-wechat fail] {(r.stderr or '')[:200]}")
        except Exception as e:
            print(f"[notify-wechat error] {e}")

    if not sent:
        print(f"[notify ALL FAILED] {msg[:200]}")


def get_ssl_days_left(hostname: str, port: int = 443, timeout: int = 10) -> Optional[int]:
    """返回 SSL 证书剩余天数,失败返回 None"""
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                exp = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z")
                return (exp - datetime.utcnow()).days
    except Exception:
        return None


def check_site(site: dict, cfg_global: dict) -> dict:
    """跑单站检查,返回 {ok, status, reason, response_ms, ssl_days}"""
    url = site["url"]
    timeout = cfg_global.get("timeout_sec", 15)
    user_agent = cfg_global.get("user_agent", "wenshucha-monitor/1.0")
    expected_status = site.get("expected_status", [200])
    must_contain = site.get("must_contain", [])
    must_not_contain = site.get("must_not_contain", [])
    must_contain_after_redirect = site.get("must_contain_after_redirect", [])
    max_ms = site.get("max_response_ms", 10000)
    check_ssl = site.get("check_ssl", url.startswith("https://"))

    result = {
        "name": site["name"],
        "url": url,
        "ok": False,
        "status": None,
        "reason": None,
        "response_ms": None,
        "ssl_days": None,
        "final_url": None,
    }

    # HTTP 检查 (跟随 redirect)
    req = urllib.request.Request(url, headers={"User-Agent": user_agent})
    # 支持单站跳过 SSL 验证(hostname mismatch / 自签证书的旧站)
    if site.get("verify_ssl", True) is False:
        ssl_ctx = ssl.create_default_context()
        ssl_ctx.check_hostname = False
        ssl_ctx.verify_mode = ssl.CERT_NONE
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl_ctx))
    else:
        opener = urllib.request.build_opener()
    start = time.time()
    try:
        with opener.open(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            result["response_ms"] = int((time.time() - start) * 1000)
            result["status"] = resp.status
            result["final_url"] = resp.url
    except urllib.error.HTTPError as e:
        result["response_ms"] = int((time.time() - start) * 1000)
        result["status"] = e.code
        if e.code in expected_status:
            # 4xx / 3xx 在 expected 内,算 OK,但不读 body
            result["ok"] = True
            result["reason"] = f"HTTP {e.code}(在 expected_status 内)"
            return result
        result["reason"] = f"HTTP {e.code}"
        return result
    except (urllib.error.URLError, socket.timeout, TimeoutError) as e:
        result["response_ms"] = int((time.time() - start) * 1000)
        result["reason"] = f"网络错误: {e}"
        return result
    except Exception as e:
        result["reason"] = f"未知错误: {type(e).__name__}: {e}"
        return result

    # 状态码检查
    if result["status"] not in expected_status:
        result["reason"] = f"HTTP {result['status']} (期望 {expected_status})"
        return result

    # 响应时间
    if result["response_ms"] > max_ms:
        result["reason"] = f"响应慢 {result['response_ms']}ms > {max_ms}ms"
        return result

    # 关键词检查
    missing = [kw for kw in must_contain if kw not in body]
    if missing:
        result["reason"] = f"缺关键词: {missing}"
        return result

    forbidden = [kw for kw in must_not_contain if kw in body]
    if forbidden:
        result["reason"] = f"包含禁忌内容: {forbidden}"
        return result

    redirect_missing = [kw for kw in must_contain_after_redirect if kw not in result["final_url"]]
    if redirect_missing:
        result["reason"] = f"redirect URL 缺: {redirect_missing} (final={result['final_url']})"
        return result

    # SSL 检查
    if check_ssl:
        hostname = urlparse(url).hostname
        if hostname:
            days = get_ssl_days_left(hostname)
            result["ssl_days"] = days
            ssl_warn = cfg_global.get("ssl_warn_days", 14)
            if days is None:
                result["reason"] = "SSL 证书读取失败"
                return result
            if days < ssl_warn:
                result["reason"] = f"SSL 证书 {days} 天后到期 (阈值 {ssl_warn})"
                return result

    result["ok"] = True
    return result


def main() -> int:
    if not CONFIG_PATH.exists():
        print(f"ERROR: config missing: {CONFIG_PATH}")
        return 2

    cfg = yaml.safe_load(CONFIG_PATH.read_text())
    state = load_state()
    # 只有故障持续超过 alert_after_hours 小时才告警(默认 24h)。
    # 期间自动恢复 = 完全静默不打扰。Jack 2026-06-10 要求(15min 抖动告警太频繁)。
    alert_after_hours = cfg.get("global", {}).get("alert_after_hours", 24)
    now_t = time.time()

    results = []
    now = now_iso()
    new_alerts = []
    recoveries = []

    for site in cfg.get("sites", []):
        r = check_site(site, cfg.get("global", {}))
        r["checked_at"] = now
        results.append(r)

        name = site["name"]
        prev = state.get(name, {})

        if r["ok"]:
            # 只有「曾经告警过的长故障」恢复时才通知一次;短暂抖动(没到 24h 没告警)= 静默恢复
            if prev.get("alerted") and prev.get("down_since"):
                r["_down_hours"] = (now_t - prev["down_since"]) / 3600
                recoveries.append(r)
            state[name] = {"last_ok": True, "down_since": None, "alerted": False, "last_checked": now}
        else:
            down_since = prev.get("down_since") or now_t   # 本轮故障起点(首次失败时记下)
            alerted = prev.get("alerted", False)
            last_alert = prev.get("last_alert", 0)
            dur_h = (now_t - down_since) / 3600
            r["_down_hours"] = dur_h
            r["_down_since_str"] = datetime.fromtimestamp(down_since).strftime("%Y-%m-%d %H:%M")
            # 关键:只有持续 ≥ alert_after_hours 才告警;之后仍未恢复每隔同样时长最多再提醒一次
            if dur_h >= alert_after_hours:
                if not alerted:
                    new_alerts.append(r)
                    alerted = True
                    last_alert = now_t
                elif (now_t - last_alert) / 3600 >= alert_after_hours:
                    new_alerts.append(r)  # 还没好,再提醒一次(避免遗忘,但不频繁)
                    last_alert = now_t
            # dur_h < 阈值 → 什么都不发,只默默记着 down_since,等它自愈或熬够时长
            state[name] = {
                "last_ok": False,
                "down_since": down_since,
                "alerted": alerted,
                "last_alert": last_alert,
                "last_reason": r["reason"],
                "last_checked": now,
            }

    # 写日志(每天一份 JSONL)
    log_file = LOGS_DIR / f"check-{datetime.now().strftime('%Y-%m-%d')}.jsonl"
    with log_file.open("a") as f:
        for r in results:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")

    save_state(state)

    # 控制台输出 + 微信通知
    ok_count = sum(1 for r in results if r["ok"])
    print(f"[{now}] {ok_count}/{len(results)} OK")
    for r in results:
        flag = "✓" if r["ok"] else "✗"
        ssl_str = f"SSL {r['ssl_days']}d" if r.get("ssl_days") else ""
        ms = f"{r['response_ms']}ms" if r["response_ms"] else ""
        reason = f" — {r['reason']}" if r.get("reason") else ""
        print(f"  {flag} {r['name']:30} {ms:>8} {ssl_str:>9}{reason}")

    if new_alerts:
        msg = f"【wenshucha 监控告警 · 故障已持续超 {alert_after_hours} 小时】\n"
        for r in new_alerts:
            hrs = r.get("_down_hours", 0)
            msg += (f"\n• {r['name']}: {r['reason']}"
                    f"\n  自 {r.get('_down_since_str','?')} 起已 down {hrs:.0f} 小时\n  {r['url']}")
        notify(msg)

    if recoveries:
        msg = "【wenshucha 已恢复】\n"
        for r in recoveries:
            hrs = r.get("_down_hours", 0)
            msg += f"\n• {r['name']} 在 down {hrs:.0f} 小时后恢复正常"
        notify(msg)

    # exit 非 0 让 cron 能感知
    return 0 if ok_count == len(results) else 1


if __name__ == "__main__":
    sys.exit(main())
