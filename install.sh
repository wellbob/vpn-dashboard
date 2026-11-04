#!/usr/bin/env bash
# vpn-dashboard: дашборд VPN-сервера на Amnezia (веб + Telegram-бот) и защита от РКН (rkn-shield).
#
#   bash install.sh                 установить или обновить всё (запускать из папки с файлами)
#   bash install.sh --no-rkn        то же, но без защиты от РКН
#   bash install.sh check           проверить, что всё работает
#   bash install.sh reset-password  сбросить вход в дашборд на admin / admin
#   bash install.sh uninstall       удалить дашборд (защита от РКН остаётся)
#   bash install.sh uninstall --all удалить и дашборд, и защиту от РКН
set -euo pipefail

APP=/opt/vpn-dashboard
CONF=/etc/vpn-dashboard
DATA=/var/lib/vpn-dashboard
PORT=8080
VPN_IF=amn0          # мост Docker-сети Amnezia: через него клиенты VPN видят сервер
SRC=$(cd "$(dirname "$0")" && pwd)

ok()   { printf '  \033[32m✓\033[0m %s\n' "$*"; }
warn() { printf '  \033[33m!\033[0m %s\n' "$*"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$*"; }
die()  { printf '\033[31mОшибка: %s\033[0m\n' "$*" >&2; exit 1; }
as_user() { runuser -u vpndash -- "$@"; }
vpn_ip() { ip -4 -o addr show "$VPN_IF" 2>/dev/null | awk '{print $4}' | cut -d/ -f1 | head -1; }

[ "$(id -u)" -eq 0 ] || die "запусти от root"

cmd_uninstall() {
    if [ "$ALL" = 1 ] && [ -x /usr/local/sbin/rkn-shield ]; then /usr/local/sbin/rkn-shield uninstall; fi
    systemctl disable --now vpn-dashboard vpn-dashboard-collector 2>/dev/null || true
    rm -f /etc/systemd/system/vpn-dashboard.service /etc/systemd/system/vpn-dashboard-collector.service
    systemctl daemon-reload
    if command -v ufw >/dev/null; then ufw delete allow in on $VPN_IF to any port $PORT proto tcp >/dev/null 2>&1 || true; fi
    rm -rf "$APP" "$CONF" "$DATA" /etc/update-motd.d/99-vpn-dashboard
    userdel vpndash 2>/dev/null || true
    echo "vpn-dashboard удалён."
}

cmd_check() {
    echo "Проверка vpn-dashboard:"
    local bad=0 ip age
    for s in vpn-dashboard-collector vpn-dashboard; do
        if systemctl is-active --quiet $s; then ok "служба $s работает"; else fail "служба $s не работает: journalctl -u $s -n 30"; bad=1; fi
    done
    if [ -f "$DATA/stats.json" ]; then
        age=$(( $(date +%s) - $(stat -c %Y "$DATA/stats.json") ))
        if [ $age -lt 60 ]; then ok "статистика свежая ($age с назад)"; else fail "статистика не обновлялась $age с"; bad=1; fi
    else fail "нет файла статистики"; bad=1; fi
    if curl -s -o /dev/null -m 5 "http://127.0.0.1:$PORT/login"; then ok "дашборд отвечает на 127.0.0.1:$PORT"; else fail "дашборд не отвечает"; bad=1; fi
    ip=$(vpn_ip)
    if [ -n "$ip" ]; then
        if curl -s -o /dev/null -m 5 "http://$ip:$PORT/login"; then ok "открывается из VPN: http://$ip:$PORT"; else fail "не отвечает на $ip:$PORT"; bad=1; fi
    else warn "сети Amnezia ($VPN_IF) нет — открывай через SSH-туннель: ssh -L $PORT:127.0.0.1:$PORT root@сервер"; fi
    if command -v docker >/dev/null; then
        local n; n=$(docker ps --format '{{.Names}}' | grep -cE '^amnezia-(awg[0-9]*|awg-legacy|wireguard)(-[0-9]+)?$' || true)
        if [ "$n" -gt 0 ]; then ok "найдено VPN-контейнеров Amnezia: $n"; else warn "запущенных AmneziaWG/WireGuard контейнеров нет — клиентов не будет видно"; fi
    else warn "Docker не установлен — будут видны только сервер и защита от РКН"; fi
    if [ -x /usr/local/sbin/rkn-shield ]; then
        if [ "$(cat /etc/rkn-shield/state 2>/dev/null)" = on ]; then ok "защита от РКН включена"; else warn "защита от РКН установлена, но выключена"; fi
    elif [ -x /usr/local/sbin/rkn-extra-block ]; then ok "защита от РКН: плагин панели PRVTPRO"
    else warn "защита от РКН не установлена: bash $APP/rkn-shield.sh install"; fi
    return $bad
}

install_rkn() {
    if [ -x /usr/local/sbin/rkn-extra-block ]; then
        warn "найден плагин РКН из панели PRVTPRO — rkn-shield не ставлю, чтобы защита не дублировалась"
        return
    fi
    local prev; prev=$(cat /etc/rkn-shield/state 2>/dev/null || true)
    if bash "$APP/rkn-shield.sh" install >/tmp/rkn-shield-install.log 2>&1; then
        # переустановка не должна включать защиту, если её выключили намеренно
        [ "$prev" = off ] && /usr/local/sbin/rkn-shield off >/dev/null
        ok "защита от РКН (rkn-shield) $([ -n "$prev" ] && echo обновлена || echo установлена)"
    else
        warn "rkn-shield не установился, подробности: /tmp/rkn-shield-install.log"
    fi
}

CMD=install; NO_RKN=0; ALL=0
for a in "$@"; do
    case "$a" in
        install|check|reset-password|uninstall) CMD=$a ;;
        --no-rkn) NO_RKN=1 ;;
        --all) ALL=1 ;;
        *) die "неизвестный параметр: $a (install | check | reset-password | uninstall | --no-rkn | --all)" ;;
    esac
done

case "$CMD" in
    uninstall) cmd_uninstall; exit 0 ;;
    check) cmd_check; exit $? ;;
    reset-password)
        as_user python3 "$APP/dashboard.py" --reset-password
        systemctl restart vpn-dashboard
        exit 0 ;;
esac

echo "Устанавливаю vpn-dashboard..."
command -v systemctl >/dev/null || die "нужен systemd"
for f in collector.py dashboard.py rkn-shield.sh web/index.html web/login.html; do
    [ -f "$SRC/$f" ] || die "нет файла $f — запускай install.sh из папки vpn-dashboard целиком"
done
if ! command -v python3 >/dev/null; then
    command -v apt-get >/dev/null || die "нужен python3"
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq python3 >/dev/null
fi
python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' || die "нужен Python 3.8 или новее"
for c in curl ip ping; do command -v $c >/dev/null || warn "нет команды $c — часть данных будет пустой"; done
command -v docker >/dev/null || warn "Docker не найден — клиенты VPN не будут видны, только сервер"

id vpndash >/dev/null 2>&1 || useradd --system --no-create-home --shell /usr/sbin/nologin vpndash
install -d -m 755 "$APP" "$APP/web" "$CONF" "$DATA"
install -d -m 700 -o vpndash -g vpndash "$DATA/web"
if [ "$SRC" != "$APP" ]; then
    install -m 755 "$SRC/collector.py" "$SRC/dashboard.py" "$SRC/install.sh" "$SRC/rkn-shield.sh" "$APP/"
    install -m 644 "$SRC/web/index.html" "$SRC/web/login.html" "$APP/web/"
fi

[ -f "$CONF/config.json" ] || cat > "$CONF/config.json" <<EOF
{
  "bind": ["127.0.0.1", "$VPN_IF"],
  "port": $PORT,
  "ping_targets": ["1.1.1.1", "8.8.8.8"]
}
EOF
# старая версия хранила имя контейнера — теперь контейнеры находятся сами
sed -i '/"container"\|"iface"/d' "$CONF/config.json"

as_user python3 "$APP/dashboard.py" --init

cat > /etc/systemd/system/vpn-dashboard-collector.service <<EOF
[Unit]
Description=vpn-dashboard: stats collector
After=docker.service network-online.target

[Service]
ExecStart=/usr/bin/env python3 $APP/collector.py
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/vpn-dashboard.service <<EOF
[Unit]
Description=vpn-dashboard: web panel + Telegram bot
After=network-online.target vpn-dashboard-collector.service
Wants=network-online.target

[Service]
User=vpndash
Group=vpndash
ExecStart=/usr/bin/env python3 $APP/dashboard.py
Restart=always
RestartSec=5
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=yes
PrivateTmp=yes
ReadWritePaths=$DATA/web

[Install]
WantedBy=multi-user.target
EOF

# подсказка при входе на сервер по SSH
cat > /etc/update-motd.d/99-vpn-dashboard <<EOF
#!/bin/sh
S=$DATA/web/settings.json
[ -f "\$S" ] || exit 0
IP=\$(ip -4 -o addr show $VPN_IF 2>/dev/null | awk '{print \$4}' | cut -d/ -f1 | head -1)
echo ""
echo "  VPN Dashboard:"
if [ -n "\$IP" ]; then
  echo "    включи VPN и открой в браузере  http://\$IP:$PORT"
else
  echo "    ssh -L $PORT:127.0.0.1:$PORT root@<сервер>, затем http://127.0.0.1:$PORT"
fi
if grep -q '"default_password": true' "\$S"; then
  echo "    вход: admin / admin  — смени пароль в Настройках!"
else
  echo "    логин: \$(sed -n 's/.*"username": "\\([^"]*\\)".*/\\1/p' "\$S")   (забыл пароль: bash $APP/install.sh reset-password)"
fi
EOF
chmod 755 /etc/update-motd.d/99-vpn-dashboard

if command -v ufw >/dev/null && ufw status | grep -q 'Status: active'; then
    ufw allow in on $VPN_IF to any port $PORT proto tcp comment 'vpn-dashboard (only from VPN)' >/dev/null
fi

[ "$NO_RKN" = 1 ] || install_rkn

systemctl daemon-reload
systemctl enable vpn-dashboard-collector vpn-dashboard >/dev/null 2>&1
systemctl restart vpn-dashboard-collector vpn-dashboard
sleep 20

echo
cmd_check || true
echo
IP=$(vpn_ip)
echo "Готово!"
if [ -n "$IP" ]; then echo "  Открой через VPN:  http://$IP:$PORT"
else echo "  Открой через SSH-туннель:  ssh -L $PORT:127.0.0.1:$PORT root@<сервер>, затем http://127.0.0.1:$PORT"; fi
grep -q '"default_password": true' "$DATA/web/settings.json" && echo "  Вход: admin / admin — смени пароль в Настройках."
exit 0
