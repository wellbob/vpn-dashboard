#!/usr/bin/env bash
# ru-filter — фильтр российских сайтов для клиентов VPN Amnezia через sing-box.
#
# Весь трафик клиентов (контейнеры в сети Amnezia, мост amn0) идёт через sing-box.
# Российские домены (.ru/.su/.рф + база geosite-category-ru) и российские IP (geoip-ru)
# отклоняются, остальное уходит в интернет как обычно. Если sing-box упал — клиенты без
# интернета (аварийный стоп), а не мимо фильтра. Сам сервер и SSH фильтр не трогает.
#
#   ru-filter install       поставить последний sing-box и всё настроить
#   ru-filter on | off      включить / выключить фильтр (off — клиенты ходят напрямую)
#   ru-filter update        обновить sing-box до последней версии
#   ru-filter check-update  проверить, есть ли новая версия
#   ru-filter test          проверить работу изнутри VPN-сети
#   ru-filter status [--json]
#   ru-filter uninstall     убрать фильтр (пакет sing-box остаётся)

set -u
VERSION="1.0.0"
# apt не должен сам перезапускать службы (иначе может прервать дашборд, который нас вызвал)
export NEEDRESTART_SUSPEND=1 NEEDRESTART_MODE=l DEBIAN_FRONTEND=noninteractive

BIN=/usr/local/sbin/ru-filter
CONF_DIR=/etc/ru-filter
CONFIG=$CONF_DIR/config.json
STATE_FILE=$CONF_DIR/state
DATA_DIR=/var/lib/ru-filter
UPDATE_FILE=$DATA_DIR/update.json
TEST_FILE=$DATA_DIR/test.json
LOCK_FILE=/run/ru-filter.lock

BRIDGE=amn0          # мост Docker-сети Amnezia (amnezia-dns-net)
TUN=rftun
TABLE=2022
MARK=0x2023
APT_SOURCE=/etc/apt/sources.list.d/sagernet.sources

LISTS="https://raw.githubusercontent.com/runetfreedom/russia-v2ray-rules-dat/release/sing-box"

c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
die()    { printf '\033[31mОшибка: %s\033[0m\n' "$*" >&2; exit 1; }
need_root() { [ "$(id -u)" -eq 0 ] || die "запусти от root"; }
lock() { exec 9>"$LOCK_FILE" || die "нет доступа к $LOCK_FILE"; flock -w 120 9 || die "ru-filter уже выполняется"; }
get_state() { cat "$STATE_FILE" 2>/dev/null || echo off; }
installed() { [ -f "$CONFIG" ] && [ -f /etc/systemd/system/ru-filter.service ]; }
singbox_version() { sing-box version 2>/dev/null | awk 'NR==1{print $3}'; }

# ------------------------------------------------------------------ маршрутизация
route_up() {
    # ответы на входящие соединения (сам туннель VPN к клиентам) идут как обычно
    iptables -w -t mangle -C PREROUTING -i $BRIDGE -m conntrack --ctdir REPLY -j MARK --set-mark $MARK 2>/dev/null \
        || iptables -w -t mangle -A PREROUTING -i $BRIDGE -m conntrack --ctdir REPLY -j MARK --set-mark $MARK
    ip rule del priority 9000 2>/dev/null; ip rule add priority 9000 iif $BRIDGE fwmark $MARK lookup main
    ip rule del priority 9001 2>/dev/null; ip rule add priority 9001 iif $BRIDGE to 172.16.0.0/12 lookup main
    ip rule del priority 9002 2>/dev/null; ip rule add priority 9002 iif $BRIDGE lookup $TABLE
    # аварийный стоп: пока sing-box не поднял туннель, клиентам некуда идти
    ip route replace unreachable default metric 4000 table $TABLE
    ip link show $TUN >/dev/null 2>&1 && ip route replace default dev $TUN table $TABLE
    return 0
}

route_down() {
    ip rule del priority 9002 2>/dev/null
    ip rule del priority 9001 2>/dev/null
    ip rule del priority 9000 2>/dev/null
    ip route flush table $TABLE 2>/dev/null
    while iptables -w -t mangle -D PREROUTING -i $BRIDGE -m conntrack --ctdir REPLY -j MARK --set-mark $MARK 2>/dev/null; do :; done
    return 0
}

route_tun() {   # вызывается после старта sing-box
    for _ in $(seq 1 30); do ip link show $TUN >/dev/null 2>&1 && break; sleep 1; done
    ip route replace default dev $TUN table $TABLE
}

rules_present() { ip rule | grep -q "lookup $TABLE"; }

# ------------------------------------------------------------------ установка
write_config() {
    mkdir -p "$CONF_DIR"
    cat > "$CONFIG" <<EOF
{
  "log": { "level": "warn", "timestamp": false },
  "dns": { "servers": [ { "type": "local", "tag": "local" } ] },
  "http_clients": [ { "tag": "lists" } ],
  "inbounds": [
    { "type": "tun", "tag": "tun-in", "interface_name": "$TUN", "address": ["172.19.0.1/30"],
      "mtu": 1500, "auto_route": false, "stack": "gvisor" }
  ],
  "outbounds": [ { "type": "direct", "tag": "direct" } ],
  "route": {
    "default_domain_resolver": "local",
    "rule_set": [
      { "type": "remote", "tag": "geosite-ru", "format": "binary", "update_interval": "1d",
        "url": "$LISTS/rule-set-geosite/geosite-category-ru.srs" },
      { "type": "remote", "tag": "geoip-ru", "format": "binary", "update_interval": "1d",
        "url": "$LISTS/rule-set-geoip/geoip-ru.srs" }
    ],
    "rules": [
      { "inbound": "tun-in", "action": "sniff" },
      { "domain_suffix": ["ru", "su", "xn--p1ai"], "action": "reject" },
      { "rule_set": "geosite-ru", "action": "reject" },
      { "rule_set": "geoip-ru", "action": "reject" }
    ],
    "final": "direct"
  },
  "experimental": { "cache_file": { "enabled": true } }
}
EOF
    chmod 644 "$CONFIG"
}

write_units() {
    local user_lines=""
    if id sing-box >/dev/null 2>&1; then
        user_lines="User=sing-box
StateDirectory=ru-filter
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW CAP_NET_BIND_SERVICE"
    fi
    cat > /etc/systemd/system/ru-filter.service <<EOF
[Unit]
Description=ru-filter: sing-box for VPN clients
After=network-online.target ru-filter-route.service
Wants=network-online.target

[Service]
$user_lines
ExecStart=/usr/bin/sing-box run -c $CONFIG -D $DATA_DIR
ExecStartPost=+$BIN route-tun
Restart=always
RestartSec=3
LimitNOFILE=infinity

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/ru-filter-route.service <<EOF
[Unit]
Description=ru-filter: route VPN clients through sing-box
After=network-online.target docker.service
Before=ru-filter.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN route-up
ExecStop=$BIN route-down

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/ru-filter-check.service <<EOF
[Unit]
Description=ru-filter: check sing-box updates

[Service]
Type=oneshot
ExecStart=$BIN check-update
EOF
    cat > /etc/systemd/system/ru-filter-check.timer <<'EOF'
[Unit]
Description=ru-filter: daily sing-box update check

[Timer]
OnCalendar=daily
RandomizedDelaySec=2h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
}

add_repo() {
    [ -f "$APT_SOURCE" ] && [ -f /etc/apt/keyrings/sagernet.asc ] && return 0
    mkdir -p /etc/apt/keyrings
    curl -fsSL https://sing-box.app/gpg.key -o /etc/apt/keyrings/sagernet.asc || die "не скачался ключ репозитория sing-box"
    chmod a+r /etc/apt/keyrings/sagernet.asc
    cat > "$APT_SOURCE" <<'EOF'
Types: deb
URIs: https://deb.sagernet.org/
Suites: *
Components: *
Enabled: yes
Signed-By: /etc/apt/keyrings/sagernet.asc
EOF
}

apt_refresh_singbox() {   # обновить списки только репозитория sing-box, остальные не трогать
    local d; d=$(mktemp -d)
    cp "$APT_SOURCE" "$d/"
    apt-get update -qq -o Dir::Etc::SourceList=/dev/null -o "Dir::Etc::SourceParts=$d" \
        -o APT::Get::List-Cleanup=0 >/dev/null 2>&1 || apt-get update -qq >/dev/null 2>&1
    rm -rf "$d"
}

migrate_old() {
    # ручная установка из первой версии: sing-box.service + awg-singbox-route
    [ -f /etc/systemd/system/awg-singbox-route.service ] || return 0
    echo "Нашёл старую ручную настройку — переношу на ru-filter..."
    systemctl disable --now awg-singbox-route >/dev/null 2>&1
    rm -f /etc/systemd/system/awg-singbox-route.service /usr/local/sbin/awg-singbox-route
    rm -rf /etc/systemd/system/sing-box.service.d
    systemctl disable --now sing-box >/dev/null 2>&1
    [ -f /etc/sing-box/config.json.orig ] && mv -f /etc/sing-box/config.json.orig /etc/sing-box/config.json
    systemctl daemon-reload
    ip link del sbtun 2>/dev/null
    route_down
}

cmd_install() {
    need_root; lock
    command -v apt-get >/dev/null || die "нужен Debian/Ubuntu (apt)"
    command -v docker >/dev/null || c_warn "Docker не найден — фильтр заработает, когда появится VPN Amnezia"
    ip link show $BRIDGE >/dev/null 2>&1 || c_warn "сети Amnezia ($BRIDGE) пока нет — фильтр подключится, когда она появится"
    local self; self=$(readlink -f "$0")
    head -5 "$self" | grep -q 'ru-filter' || die "запускай скачанный файл: bash ru-filter.sh install"
    [ "$self" = "$BIN" ] || install -m 755 "$self" "$BIN"

    echo "Ставлю последний sing-box из официального репозитория..."
    command -v curl >/dev/null || { DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl >/dev/null; }
    add_repo
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >/dev/null 2>&1
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq -o DPkg::Lock::Timeout=120 sing-box >/dev/null 2>&1 \
        || die "не удалось установить sing-box (apt)"
    echo "sing-box $(singbox_version) установлен."

    migrate_old
    mkdir -p "$DATA_DIR"
    write_config
    sing-box check -c "$CONFIG" >/dev/null 2>&1 || die "sing-box не принял конфиг: $(sing-box check -c "$CONFIG" 2>&1 | tail -1)"
    write_units   # свой ru-filter.service со своим конфигом: чужой sing-box.service, если есть, не трогаем
    systemctl enable --now ru-filter-check.timer >/dev/null 2>&1
    cmd_on_nolock
    check_update_quiet >/dev/null
    sleep 3
    cmd_test || true
    echo
    c_ok "Готово! Клиенты VPN идут через фильтр, российские сайты закрыты."
}

cmd_on_nolock() {
    echo on > "$STATE_FILE"
    systemctl enable ru-filter-route ru-filter >/dev/null 2>&1
    systemctl restart ru-filter-route
    systemctl restart ru-filter
    for _ in $(seq 1 20); do ip link show $TUN >/dev/null 2>&1 && break; sleep 1; done
    systemctl is-active --quiet ru-filter || die "sing-box не запустился: journalctl -u ru-filter -n 30"
}

cmd_on() { need_root; installed || die "фильтр не установлен: ru-filter install"; lock; cmd_on_nolock; c_ok "Фильтр включён."; }

cmd_off() {
    need_root; installed || die "фильтр не установлен"; lock
    echo off > "$STATE_FILE"
    systemctl disable --now ru-filter ru-filter-route >/dev/null 2>&1
    route_down
    c_warn "Фильтр выключен — клиенты ходят в интернет напрямую."
}

check_update_quiet() {
    mkdir -p "$DATA_DIR"
    apt_refresh_singbox
    local inst cand
    inst=$(dpkg-query -W -f='${Version}' sing-box 2>/dev/null)
    cand=$(apt-cache policy sing-box 2>/dev/null | awk '/Candidate:/{print $2}')
    printf '{"installed":"%s","candidate":"%s","checked":%s}\n' "$inst" "$cand" "$(date +%s)" > "$UPDATE_FILE"
    chmod 644 "$UPDATE_FILE"
    echo "$inst $cand"
}

cmd_check_update() {
    need_root; lock
    read -r inst cand <<< "$(check_update_quiet)"
    if [ -n "$cand" ] && [ "$cand" != "$inst" ]; then c_warn "Доступна новая версия sing-box: $cand (сейчас $inst)"
    else c_ok "Установлена последняя версия sing-box: ${inst:-нет}"; fi
}

cmd_update() {
    need_root; installed || die "фильтр не установлен"; lock
    local before after; before=$(singbox_version)
    apt_refresh_singbox
    DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --only-upgrade -o DPkg::Lock::Timeout=120 sing-box >/dev/null 2>&1 \
        || die "обновление не удалось (apt)"
    after=$(singbox_version)
    sing-box check -c "$CONFIG" >/dev/null 2>&1 || c_warn "новая версия ругается на конфиг: $(sing-box check -c "$CONFIG" 2>&1 | tail -1)"
    [ "$(get_state)" = on ] && systemctl restart ru-filter
    check_update_quiet >/dev/null
    if [ "$before" = "$after" ]; then c_ok "Уже последняя версия sing-box: $after"; else c_ok "sing-box обновлён: $before → $after"; fi
}

vpn_container() {   # контейнер в сети Amnezia, из которого можно проверить выход в интернет
    docker ps --filter "network=amnezia-dns-net" --format '{{.Names}}' 2>/dev/null \
        | grep -E '^amnezia-(awg|wireguard|openvpn|xray)' | head -1
}

cmd_test() {
    command -v docker >/dev/null || { echo "Проверка: Docker не найден"; return 1; }
    local c; c=$(vpn_container)
    [ -n "$c" ] || { echo "Проверка: нет VPN-контейнера в сети Amnezia"; return 1; }
    local g y
    g=$(docker exec "$c" sh -c 'wget -q -T 8 -O /dev/null https://www.google.com && echo ok || echo fail' 2>/dev/null)
    y=$(docker exec "$c" sh -c 'wget -q -T 8 -O /dev/null https://ya.ru && echo ok || echo fail' 2>/dev/null)
    mkdir -p "$DATA_DIR"
    printf '{"ts":%s,"google":"%s","ru":"%s"}\n' "$(date +%s)" "$g" "$y" > "$TEST_FILE"; chmod 644 "$TEST_FILE"
    local gs ys; gs=$([ "$g" = ok ] && echo "открывается" || echo "НЕ открывается")
    ys=$([ "$y" = ok ] && echo "открывается" || echo "заблокирован")
    if [ "$g" = ok ] && [ "$y" != ok ]; then c_ok "Проверка пройдена: google.com $gs, ya.ru $ys"; return 0; fi
    c_warn "Проверка: google.com $gs, ya.ru $ys"; return 1
}

cmd_status() {
    local inst=false active=false rules=false
    installed && inst=true
    systemctl is-active --quiet ru-filter 2>/dev/null && active=true
    rules_present && rules=true
    if [ "${1:-}" = --json ]; then
        printf '{"installed":%s,"state":"%s","active":%s,"rules":%s,"version":"%s","update":%s,"test":%s}\n' \
            "$inst" "$(get_state)" "$active" "$rules" "$(singbox_version)" \
            "$(cat "$UPDATE_FILE" 2>/dev/null || echo null)" "$(cat "$TEST_FILE" 2>/dev/null || echo null)"
        return
    fi
    echo "ru-filter $VERSION"
    if ! $inst; then c_warn "Не установлен (ru-filter install)"; return; fi
    if [ "$(get_state)" = on ] && $active && $rules; then c_ok "Состояние: ВКЛЮЧЁН"; else c_warn "Состояние: выключен"; fi
    echo "sing-box: $(singbox_version)"
}

cmd_uninstall() {
    need_root; lock
    systemctl disable --now ru-filter ru-filter-route ru-filter-check.timer >/dev/null 2>&1
    route_down
    rm -f /etc/systemd/system/ru-filter.service /etc/systemd/system/ru-filter-route.service \
          /etc/systemd/system/ru-filter-check.service /etc/systemd/system/ru-filter-check.timer
    systemctl daemon-reload
    rm -rf "$CONF_DIR" "$DATA_DIR"
    rm -f "$BIN"
    c_ok "ru-filter удалён, клиенты ходят напрямую. Пакет sing-box оставлен (apt remove sing-box — если не нужен)."
}

case "${1:-help}" in
    install)      cmd_install ;;
    on)           cmd_on ;;
    off)          cmd_off ;;
    update)       cmd_update ;;
    check-update) cmd_check_update ;;
    test)         cmd_test ;;
    status)       cmd_status "${2:-}" ;;
    uninstall)    cmd_uninstall ;;
    route-up)     route_up ;;
    route-down)   route_down ;;
    route-tun)    route_tun ;;
    *) sed -n '2,17p' "$0" | sed 's/^# \{0,1\}//' ;;
esac
