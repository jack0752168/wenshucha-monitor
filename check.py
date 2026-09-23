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


# 本机告警钩子:同目录下的 notify-local.sh(不在 git 里,每台机器自己放)。
# 为什么要有这个:这份 check.py 同时跑在 Jack 的 Mac 和生产机 .235 上,而下面两个
# 通道(iMessage 的 osascript、微信的 hermes)**只有 Mac 上存在**。
# 2026-09-16 查到:.235 上 /root/.claude/bin/ 根本没有这两个脚本,所以这个监控在
# 生产机上跑了几个月,每一次告警都静默地走到 "notify ALL FAILED" —— 监控在跑,
# 但没有任何人收得到。而 .235 恰恰是唯一 24 小时在线、不依赖 Jack 家里的机器。
NOTIFY_LOCAL = ROOT / "notify-local.sh"
ALERT_LOG = ROOT / "alerts.log"


def notify(msg: str) -> None:
    """告警通知 — 本机钩子 → iMessage → 微信;并且无论如何都落一份到 alerts.log"""
    sent = False

    # 落盘优先:通道全挂时至少有据可查,也给别的机器拉取转发用
    try:
        with ALERT_LOG.open("a", encoding="utf-8") as f:
            f.write(f"{now_iso()} {msg}\n")
    except Exception as e:
        print(f"[alert-log error] {e}")

    # 通道 0:本机钩子(生产机 .235 用这个;Mac 上没有这个文件就跳过)
    if NOTIFY_LOCAL.exists() and os.access(NOTIFY_LOCAL, os.X_OK):
        try:
            r = subprocess.run([str(NOTIFY_LOCAL), msg], timeout=25,
                               check=False, capture_output=True, text=True)
            if r.returncode == 0:
                sent = True
                print("[notify-local OK]")
            else:
                print(f"[notify-local fail rc={r.returncode}] {(r.stderr or '')[:200]}")
        except Exception as e:
            print(f"[notify-local error] {e}")

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
    # 单站可覆写 UA。钱路(OKX/Binance 返佣链)用真浏览器 UA,测的才是真实用户
    # 拿到的那条响应——交易所会按 UA 分流。(2026-09-23 订正:加这个能力的起因
    # 是一次误诊,那次连红 14.7h 的真因是 VPN 出口楔死,不是 UA。)
    user_agent = site.get("user_agent") or cfg_global.get("user_agent", "wenshucha-monitor/1.0")
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
        "warn": None,          # 非故障级提醒(如证书临近到期):不影响 ok,走独立告警通道
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
    # ⚠️ 本监控跑在走 EPN 海外 VPN 的 Mac 上(全局 TUN,出口 202.68.183.224)。
    # 访问**直连腾讯广州**的国内站(wenshucha.com 主站/旧页、datahouseful)时,流量要绕海外出口
    # 再回国 → 响应时间凭空 +3~9s、且随 VPN 抖动,与真实用户(国内直连 ~0.3s)完全脱节,
    # 只会周期性误报「响应慢」(2026-07-22 起 wenshucha.com 连报 169h 即此)。Vercel 全球 CDN 的站
    # (tob/mcp/sinoverdict/peilema)不受影响,故保留响应时间告警。对被污染的站置 check_response_ms:false,
    # 只靠状态码 + 关键词 + 15s 超时兜可用性(真挂了会超时/内容缺失,照样告警)。
    if site.get("check_response_ms", True) and result["response_ms"] > max_ms:
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
            # 证书「即将到期」是警告,不是故障:站还在正常服务 200。
            # 2026-08-12 修:原本这里 return(ok=False)把健康站标成 down,
            # 而证书还有 13 天 ⇒ 会连续 13 天判定为故障,并在 24h 后发出
            # 「wenshucha-main 已 down 24 小时」这种与事实不符的告警。
            # 改为走独立的 warn 通道(措辞是到期日,不是 down 时长)。
            if days < ssl_warn:
                result["warn"] = f"SSL 证书 {days} 天后到期 (阈值 {ssl_warn})"

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
    new_warns = []
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
            # 警告(证书临近到期)独立节流:同一目标最多每 alert_after_hours 提醒一次
            last_warn = prev.get("last_warn_alert", 0)
            if r.get("warn") and (now_t - last_warn) / 3600 >= alert_after_hours:
                new_warns.append(r)
                last_warn = now_t
            state[name] = {"last_ok": True, "down_since": None, "alerted": False,
                           "last_warn_alert": last_warn, "last_checked": now}
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
                "last_warn_alert": prev.get("last_warn_alert", 0),
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
    warn_count = sum(1 for r in results if r.get("warn"))
    print(f"[{now}] {ok_count}/{len(results)} OK" + (f" ({warn_count} 警告)" if warn_count else ""))
    for r in results:
        flag = "⚠" if (r["ok"] and r.get("warn")) else ("✓" if r["ok"] else "✗")
        ssl_str = f"SSL {r['ssl_days']}d" if r.get("ssl_days") else ""
        ms = f"{r['response_ms']}ms" if r["response_ms"] else ""
        note = r.get("reason") or r.get("warn")
        reason = f" — {note}" if note else ""
        print(f"  {flag} {r['name']:30} {ms:>8} {ssl_str:>9}{reason}")

    if new_alerts:
        msg = f"【wenshucha 监控告警 · 故障已持续超 {alert_after_hours} 小时】\n"
        for r in new_alerts:
            hrs = r.get("_down_hours", 0)
            msg += (f"\n• {r['name']}: {r['reason']}"
                    f"\n  自 {r.get('_down_since_str','?')} 起已 down {hrs:.0f} 小时\n  {r['url']}")
        notify(msg)

    # 警告(站正常服务,但有需要提前处理的事,如证书临近到期)。
    # 措辞刻意不含「down / 故障」,免得把「还有 N 天到期」讲成「已经掛了」。
    if new_warns:
        msg = "【wenshucha 监控警告 · 站点正常,但需提前处理】\n"
        for r in new_warns:
            msg += f"\n• {r['name']}: {r['warn']}\n  {r['url']}"
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
