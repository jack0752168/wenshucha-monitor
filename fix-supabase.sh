#!/bin/bash
# Supabase 连接自动诊断+修复脚本
# Usage(技术那边一行复制粘贴):
#   curl -sSL https://raw.githubusercontent.com/jack0752168/wenshucha-monitor/main/fix-supabase.sh | sudo bash
#
# 作用:
# 1. 清本地 DNS 缓存(macOS / Linux 各种 resolver)
# 2. 测 Supabase 是否能解析+连通
# 3. 如果 DNS 还不通,自动加 hosts hardcode 绕过 DNS
# 4. 二次验证,通了打 ✓ ALL OK

set +e  # 不要单点失败退出 — 容错执行所有步骤

SUPABASE_HOST="cylkkyojwyjzheztznqm.supabase.co"
SUPABASE_IPS="172.64.149.246 104.18.38.10"
FALLBACK_IP="172.64.149.246"

echo "==========================================="
echo " Supabase 连接修复脚本 v1"
echo " Target: $SUPABASE_HOST"
echo " 时间: $(date '+%Y-%m-%d %H:%M:%S')"
echo "==========================================="
echo ""

# ============================================
# Step 1: 检测系统 + 清 DNS 缓存
# ============================================
echo "[1/4] 清本地 DNS 缓存..."

OS=$(uname -s)
if [ "$OS" = "Darwin" ]; then
    echo "  系统: macOS"
    /usr/bin/dscacheutil -flushcache 2>&1 | head -1
    /usr/bin/killall -HUP mDNSResponder 2>&1 | head -1
    echo "  ✓ macOS DNS 缓存已清"
elif [ "$OS" = "Linux" ]; then
    echo "  系统: Linux"
    if command -v systemd-resolve >/dev/null 2>&1; then
        systemd-resolve --flush-caches 2>&1
        echo "  ✓ systemd-resolved 缓存已清"
    elif command -v resolvectl >/dev/null 2>&1; then
        resolvectl flush-caches 2>&1
        echo "  ✓ resolvectl 缓存已清"
    fi
    systemctl restart nscd 2>/dev/null && echo "  ✓ nscd 重启"
    systemctl restart dnsmasq 2>/dev/null && echo "  ✓ dnsmasq 重启"
    # 至少有一个成功
    echo "  ✓ Linux DNS 缓存已尝试清理"
else
    echo "  系统: $OS (跳过 DNS 缓存清理)"
fi
echo ""

# ============================================
# Step 2: 测 DNS 解析 + HTTP 连接
# ============================================
echo "[2/4] 验证 DNS 解析..."

DIG_RESULT=""
if command -v dig >/dev/null 2>&1; then
    DIG_RESULT=$(dig +short +time=5 +tries=1 $SUPABASE_HOST @1.1.1.1 2>/dev/null | head -1)
elif command -v nslookup >/dev/null 2>&1; then
    DIG_RESULT=$(nslookup $SUPABASE_HOST 1.1.1.1 2>/dev/null | grep -A1 "Name:" | grep "Address" | head -1 | awk '{print $NF}')
fi

if [ -n "$DIG_RESULT" ]; then
    echo "  ✓ DNS 解析正常: $SUPABASE_HOST → $DIG_RESULT"
else
    echo "  ✗ DNS 解析仍失败,准备 hosts 兜底"
fi
echo ""

# ============================================
# Step 3: 测 HTTPS 连接
# ============================================
echo "[3/4] 验证 HTTPS 连接..."

HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "https://$SUPABASE_HOST/rest/v1/" 2>&1)
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ HTTPS 连接成功 (HTTP $HTTP_CODE = Supabase 正常响应)"
    echo ""
    echo "==========================================="
    echo " ✓ ALL OK — Supabase 已连通,无需 hosts 兜底"
    echo "==========================================="
    exit 0
else
    echo "  ✗ HTTPS 连接失败 (HTTP $HTTP_CODE)"
fi
echo ""

# ============================================
# Step 4: hosts 兜底(强制走硬编码 IP)
# ============================================
echo "[4/4] hosts 兜底硬编码..."

HOSTS_FILE="/etc/hosts"
if [ "$OS" = "MINGW"* ] || [ "$OS" = "CYGWIN"* ]; then
    HOSTS_FILE="/c/Windows/System32/drivers/etc/hosts"
fi

if [ ! -w "$HOSTS_FILE" ]; then
    echo "  ✗ 没有 hosts 写权限 — 请用 sudo 重新跑这个脚本"
    echo "    sudo bash fix-supabase.sh"
    exit 1
fi

# 移除旧的 supabase hosts 行(避免重复)
sed -i.bak "/$SUPABASE_HOST/d" "$HOSTS_FILE" 2>/dev/null || true
# 添加新行
echo "$FALLBACK_IP $SUPABASE_HOST  # wenshucha-monitor fix-supabase $(date +%Y-%m-%d)" >> "$HOSTS_FILE"
echo "  ✓ 已加 hosts: $FALLBACK_IP $SUPABASE_HOST"
echo ""

# 再测一次
echo "  二次验证..."
HTTP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" --max-time 10 "https://$SUPABASE_HOST/rest/v1/" 2>&1)
if [ "$HTTP_CODE" = "401" ] || [ "$HTTP_CODE" = "200" ]; then
    echo "  ✓ HTTPS 连接成功 (HTTP $HTTP_CODE)"
    echo ""
    echo "==========================================="
    echo " ✓ ALL OK — Supabase 已通(走 hosts 硬编码)"
    echo " 注意:Supabase 换 IP 时会失效,建议 7 天内删 hosts 那行"
    echo "==========================================="
    exit 0
else
    echo "  ✗ 仍然失败 (HTTP $HTTP_CODE)"
    echo ""
    echo "==========================================="
    echo " ✗ 自动修复失败 — 可能是防火墙/VPN/HTTPS 拦截"
    echo " 把下面输出截图发回去人工查:"
    echo "==========================================="
    echo "  系统: $OS"
    echo "  DNS 解析: ${DIG_RESULT:-NONE}"
    echo "  HTTP code: $HTTP_CODE"
    echo "  hosts:"
    grep -i supabase "$HOSTS_FILE" 2>/dev/null
    exit 1
fi
