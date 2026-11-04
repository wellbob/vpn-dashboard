#!/usr/bin/env bash
# rkn-shield — закрывает сервер от сетей РКН и госструктур.
#
#   Входящие: подключения из сетей РКН/госструктур отбрасываются на ВСЕХ портах сразу,
#             включая сервисы в Docker и порты, которые откроются позже.
#   Исходящие: (по желанию) сервер и его клиенты не ходят в сети VK / OK / Max.
#
# Списки сетей: https://github.com/C24Be/AS_Network_List (BSD-2-Clause), обновляются раз в сутки.
# Лицензия скрипта: MIT.

set -u
VERSION="1.0.0"

CONF_DIR=/etc/rkn-shield
CONF_FILE=$CONF_DIR/config
ALLOW_FILE=$CONF_DIR/allow.list
STATE_FILE=$CONF_DIR/state
CACHE_DIR=/var/lib/rkn-shield
BIN=/usr/local/sbin/rkn-shield
LOCK_FILE=/run/rkn-shield.lock

IN_CHAIN=RKN_SHIELD_IN     # таблица mangle: видит всё входящее до разделения на порты и Docker
OUT_CHAIN=RKN_SHIELD_OUT   # таблица filter

# Настройки по умолчанию (переопределяются в /etc/rkn-shield/config)
BLOCK_IN=yes
BLOCK_OUT=yes
LIST_BASE="https://raw.githubusercontent.com/C24Be/AS_Network_List/main/blacklists_iptables"

[ -f "$CONF_FILE" ] && . "$CONF_FILE"

# список: имя набора ipset | файл C24Be | семейство | минимум сетей (защита от пустой загрузки)
LISTS="in4:blacklist-v4:inet:300 in6:blacklist-v6:inet6:5 out4:blacklist-vk-v4:inet:50 out6:blacklist-vk-v6:inet6:1"

# ---------------------------------------------------------------- вспомогательное
c_ok()   { printf '\033[32m%s\033[0m\n' "$*"; }
c_warn() { printf '\033[33m%s\033[0m\n' "$*"; }
die()    { printf '\033[31mОшибка: %s\033[0m\n' "$*" >&2; exit 1; }

need_root() { [ "$(id -u)" -eq 0 ] || die "запусти от root (sudo rkn-shield ...)"; }

lock() {
    exec 9>"$LOCK_FILE" || die "не удалось открыть $LOCK_FILE"
    flock -w 60 9 || die "rkn-shield уже выполняется в другом окне"
}

ipt() { # ipt 4|6 аргументы...
    if [ "$1" = 4 ]; then shift; iptables -w "$@"; else shift; ip6tables -w "$@"; fi
}

set_name() { echo "rkns_$1"; }   # in4 -> rkns_in4

get_state() { cat "$STATE_FILE" 2>/dev/null || echo off; }

# ---------------------------------------------------------------- наборы адресов
ensure_set() { # ensure_set имя семейство
    ipset list -n "$1" >/dev/null 2>&1 || ipset create "$1" hash:net family "$2" maxelem 65536
}

ensure_sets() {
    local item key fam
    for item in $LISTS; do
        key=${item%%:*}; fam=$(echo "$item" | cut -d: -f3)
        ensure_set "$(set_name "$key")" "$fam"
    done
    ensure_set rkns_allow4 inet
    ensure_set rkns_allow6 inet6
}

load_set() { # load_set имя семейство файл — атомарная замена содержимого
    local name=$1 fam=$2 file=$3 tmp="${1}_tmp"
    ensure_set "$name" "$fam"
    ipset destroy "$tmp" 2>/dev/null
    ipset create "$tmp" hash:net family "$fam" maxelem 65536 || return 1
    sed "s|^|add $tmp |" "$file" | ipset restore -exist || { ipset destroy "$tmp"; return 1; }
    ipset swap "$tmp" "$name" && ipset destroy "$tmp"
}

load_allow() {
    local f4 f6
    f4=$(mktemp); f6=$(mktemp)
    if [ -f "$ALLOW_FILE" ]; then
        grep -vE '^\s*(#|$)' "$ALLOW_FILE" | awk '{print $1}' | grep -v ':' > "$f4"
        grep -vE '^\s*(#|$)' "$ALLOW_FILE" | awk '{print $1}' | grep ':'    > "$f6"
    fi
    load_set rkns_allow4 inet "$f4"
    load_set rkns_allow6 inet6 "$f6"
    rm -f "$f4" "$f6"
}

load_from_cache() {
    local item key fam
    for item in $LISTS; do
        key=${item%%:*}; fam=$(echo "$item" | cut -d: -f3)
        [ -s "$CACHE_DIR/$key.txt" ] && load_set "$(set_name "$key")" "$fam" "$CACHE_DIR/$key.txt"
    done
    load_allow
}

# ---------------------------------------------------------------- загрузка списков
fetch_lists() {
    local item key src fam min tmp n failed=0
    mkdir -p "$CACHE_DIR"
    for item in $LISTS; do
        IFS=: read -r key src fam min <<< "$item"
        tmp=$(mktemp)
        if curl -fsSL --max-time 60 --retry 2 "$LIST_BASE/$src.ipset" -o "$tmp.raw"; then
            # строки вида "add <набор> <сеть>" -> оставляем только сеть
            awk '$1=="add"{print $3}' "$tmp.raw" > "$tmp"
            if [ "$fam" = inet ]; then
                grep -E '^[0-9]{1,3}(\.[0-9]{1,3}){3}(/[0-9]{1,2})?$' "$tmp" > "$tmp.ok"
            else
                grep -E '^[0-9a-fA-F:]+(/[0-9]{1,3})?$' "$tmp" | grep ':' > "$tmp.ok"
            fi
            n=$(wc -l < "$tmp.ok")
            if [ "$n" -ge "$min" ]; then
                mv "$tmp.ok" "$CACHE_DIR/$key.txt"
            else
                c_warn "  $src: пришло всего $n сетей (меньше $min) — оставляю прежний список"
                failed=1
            fi
        else
            c_warn "  $src: не удалось скачать — оставляю прежний список"
            failed=1
        fi
        rm -f "$tmp" "$tmp.raw" "$tmp.ok"
    done
    date '+%Y-%m-%d %H:%M' > "$CACHE_DIR/last_update"
    return $failed
}

# ---------------------------------------------------------------- правила
rules_off() {
    local v
    for v in 4 6; do
        while ipt $v -t mangle -D PREROUTING -j $IN_CHAIN 2>/dev/null; do :; done
        ipt $v -t mangle -F $IN_CHAIN 2>/dev/null; ipt $v -t mangle -X $IN_CHAIN 2>/dev/null
        for c in OUTPUT FORWARD DOCKER-USER; do
            while ipt $v -D $c -j $OUT_CHAIN 2>/dev/null; do :; done
        done
        ipt $v -F $OUT_CHAIN 2>/dev/null; ipt $v -X $OUT_CHAIN 2>/dev/null
    done
}

rules_on() {
    local v c
    rules_off
    for v in 4 6; do
        if [ "$BLOCK_IN" = yes ]; then
            ipt $v -t mangle -N $IN_CHAIN
            ipt $v -t mangle -A $IN_CHAIN -m set --match-set rkns_allow$v src -j RETURN
            ipt $v -t mangle -A $IN_CHAIN -m set --match-set rkns_in$v src -m conntrack --ctstate NEW -j DROP
            ipt $v -t mangle -I PREROUTING 1 -j $IN_CHAIN
        fi
        if [ "$BLOCK_OUT" = yes ]; then
            ipt $v -N $OUT_CHAIN
            ipt $v -A $OUT_CHAIN -p tcp -m set --match-set rkns_out$v dst -j REJECT --reject-with tcp-reset
            ipt $v -A $OUT_CHAIN -m set --match-set rkns_out$v dst -j REJECT
            ipt $v -I OUTPUT 1 -j $OUT_CHAIN
            ipt $v -I FORWARD 1 -j $OUT_CHAIN
            # Docker сам переставляет свои правила в FORWARD; DOCKER-USER он не трогает
            ipt $v -S DOCKER-USER >/dev/null 2>&1 && ipt $v -I DOCKER-USER 1 -j $OUT_CHAIN
        fi
    done
}

rules_present() { iptables -w -t mangle -C PREROUTING -j $IN_CHAIN 2>/dev/null || iptables -w -C OUTPUT -j $OUT_CHAIN 2>/dev/null; }

# ---------------------------------------------------------------- команды
cmd_install() {
    need_root
    echo "Устанавливаю rkn-shield $VERSION..."
    if ! command -v ipset >/dev/null || ! command -v iptables >/dev/null || ! command -v curl >/dev/null; then
        command -v apt-get >/dev/null || die "нужны ipset, iptables и curl — поставь их вручную"
        DEBIAN_FRONTEND=noninteractive apt-get update -qq
        DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ipset iptables curl >/dev/null || die "не удалось установить ipset/iptables/curl"
    fi
    command -v flock >/dev/null || die "нет утилиты flock (пакет util-linux)"

    local self; self=$(readlink -f "$0")
    head -5 "$self" 2>/dev/null | grep -q 'rkn-shield' || die "сначала скачай скрипт в файл (см. инструкцию), потом запусти: rkn-shield install"
    [ "$self" = "$BIN" ] || install -m 755 "$self" "$BIN"

    mkdir -p "$CONF_DIR" "$CACHE_DIR"
    [ -f "$CONF_FILE" ] || cat > "$CONF_FILE" <<'EOF'
# Настройки rkn-shield. После изменения: rkn-shield on
# Блокировать входящие подключения из сетей РКН и госструктур (yes/no)
BLOCK_IN=yes
# Не пускать сервер и его клиентов в сети VK / OK / Max (yes/no)
BLOCK_OUT=yes
EOF
    [ -f "$ALLOW_FILE" ] || cat > "$ALLOW_FILE" <<'EOF'
# Адреса, которые нельзя блокировать никогда (по одному на строку, можно с маской: 1.2.3.0/24)
# Добавлять удобнее командой: rkn-shield allow 1.2.3.4
EOF

    cat > /etc/systemd/system/rkn-shield.service <<EOF
[Unit]
Description=rkn-shield: block RKN/government networks
After=network-online.target docker.service
Wants=network-online.target

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$BIN boot

[Install]
WantedBy=multi-user.target
EOF
    cat > /etc/systemd/system/rkn-shield-update.service <<EOF
[Unit]
Description=rkn-shield: update network lists
After=network-online.target

[Service]
Type=oneshot
ExecStart=$BIN update
EOF
    cat > /etc/systemd/system/rkn-shield-update.timer <<'EOF'
[Unit]
Description=rkn-shield: daily list update

[Timer]
OnCalendar=daily
RandomizedDelaySec=1h
Persistent=true

[Install]
WantedBy=timers.target
EOF
    systemctl daemon-reload
    systemctl enable rkn-shield.service rkn-shield-update.timer >/dev/null 2>&1
    systemctl start rkn-shield-update.timer

    lock
    echo "Скачиваю списки сетей..."
    fetch_lists
    [ -s "$CACHE_DIR/in4.txt" ] || die "списки не скачались, проверь интернет на сервере и запусти: rkn-shield install"
    ensure_sets
    load_from_cache
    rules_on
    echo on > "$STATE_FILE"
    echo
    c_ok "Готово! Сервер закрыт от сетей РКН."
    echo
    cmd_status
}

cmd_uninstall() {
    need_root; lock
    rules_off
    for s in rkns_in4 rkns_in6 rkns_out4 rkns_out6 rkns_allow4 rkns_allow6; do ipset destroy "$s" 2>/dev/null; done
    systemctl disable --now rkn-shield-update.timer rkn-shield.service >/dev/null 2>&1
    rm -f /etc/systemd/system/rkn-shield.service /etc/systemd/system/rkn-shield-update.service /etc/systemd/system/rkn-shield-update.timer
    systemctl daemon-reload
    rm -rf "$CONF_DIR" "$CACHE_DIR"
    rm -f "$BIN"
    c_ok "rkn-shield удалён, все его правила сняты."
}

cmd_on() {
    need_root; lock
    [ -s "$CACHE_DIR/in4.txt" ] || fetch_lists
    ensure_sets; load_from_cache; rules_on
    echo on > "$STATE_FILE"
    c_ok "Защита включена."
}

cmd_off() {
    need_root; lock
    rules_off
    echo off > "$STATE_FILE"
    c_warn "Защита выключена (списки сохранены, включить: rkn-shield on)."
}

cmd_update() {
    need_root; lock
    echo "Обновляю списки..."
    fetch_lists; local rc=$?
    ensure_sets; load_from_cache
    if [ "$(get_state)" = on ] && ! rules_present; then rules_on; fi
    [ $rc -eq 0 ] && c_ok "Списки обновлены." || c_warn "Часть списков не обновилась, работают прежние."
}

cmd_boot() {
    lock
    ensure_sets
    if [ -s "$CACHE_DIR/in4.txt" ]; then load_from_cache; else fetch_lists; load_from_cache; fi
    if [ "$(get_state)" = on ]; then rules_on; fi
}

count() { ipset list -t "$1" 2>/dev/null | awk -F': ' '/Number of entries/{print $2}'; }
hits()  { # сколько пакетов отбросило правило с указанным действием в цепочке
    ipt "$1" -t "$2" -L "$3" -vnx 2>/dev/null | awk -v t="$4" '$3==t{s+=$1} END{print s+0}'
}

cmd_status() {
    local st; st=$(get_state)
    echo "rkn-shield $VERSION"
    if [ "$st" = on ] && rules_present; then c_ok "Состояние:  ВКЛЮЧЕНА"; else c_warn "Состояние:  выключена"; fi
    printf 'Входящие от РКН/госструктур:  %s  (сетей: %s IPv4, %s IPv6)\n' \
        "$([ "$BLOCK_IN" = yes ] && echo блокируются || echo не блокируются)" "$(count rkns_in4)" "$(count rkns_in6)"
    printf 'Исходящие в VK/OK/Max:        %s  (сетей: %s IPv4, %s IPv6)\n' \
        "$([ "$BLOCK_OUT" = yes ] && echo блокируются || echo не блокируются)" "$(count rkns_out4)" "$(count rkns_out6)"
    printf 'Исключения (allow):           %s\n' "$(( $(count rkns_allow4) + $(count rkns_allow6) ))"
    printf 'Отбито попыток подключения:   %s  (с последнего включения)\n' "$(( $(hits 4 mangle $IN_CHAIN DROP) + $(hits 6 mangle $IN_CHAIN DROP) ))"
    printf 'Списки обновлены:             %s\n' "$(cat "$CACHE_DIR/last_update" 2>/dev/null || echo никогда)"
}

cmd_check() {
    local ip=${1:-}
    [ -n "$ip" ] || die "укажи адрес: rkn-shield check 1.2.3.4"
    local v=4; case "$ip" in *:*) v=6 ;; esac
    if ipset test rkns_allow$v "$ip" 2>/dev/null; then c_ok "$ip — в исключениях, не блокируется"; return; fi
    if ipset test rkns_in$v "$ip" 2>/dev/null; then c_warn "$ip — сеть РКН/госструктур: входящие подключения с него блокируются"
    else c_ok "$ip — не в списке РКН, подключается свободно"; fi
    if ipset test rkns_out$v "$ip" 2>/dev/null; then c_warn "$ip — сеть VK/OK/Max: исходящие к нему блокируются"; fi
}

cmd_allow() {
    need_root
    local ip=${1:-}; [ -n "$ip" ] || die "укажи адрес: rkn-shield allow 1.2.3.4"
    grep -qxF "$ip" "$ALLOW_FILE" 2>/dev/null || echo "$ip" >> "$ALLOW_FILE"
    lock; load_allow
    c_ok "$ip добавлен в исключения."
}

cmd_unallow() {
    need_root
    local ip=${1:-}; [ -n "$ip" ] || die "укажи адрес: rkn-shield unallow 1.2.3.4"
    [ -f "$ALLOW_FILE" ] && sed -i "\|^$ip\$|d" "$ALLOW_FILE"
    lock; load_allow
    c_ok "$ip убран из исключений."
}

cmd_help() {
    cat <<EOF
rkn-shield $VERSION — защита сервера от сетей РКН и госструктур

  rkn-shield status          что включено, сколько сетей, сколько попыток отбито
  rkn-shield on | off        включить / выключить защиту
  rkn-shield update          обновить списки сейчас (само делается раз в сутки)
  rkn-shield check IP        проверить, попадает ли адрес под блокировку
  rkn-shield allow IP        никогда не блокировать этот адрес
  rkn-shield unallow IP      убрать адрес из исключений
  rkn-shield install         установить (или переустановить)
  rkn-shield uninstall       удалить полностью

Настройки: $CONF_FILE
EOF
}

case "${1:-help}" in
    install)   cmd_install ;;
    uninstall) cmd_uninstall ;;
    on)        cmd_on ;;
    off)       cmd_off ;;
    update)    cmd_update ;;
    boot)      cmd_boot ;;
    status)    cmd_status ;;
    check)     cmd_check "${2:-}" ;;
    allow)     cmd_allow "${2:-}" ;;
    unallow)   cmd_unallow "${2:-}" ;;
    version)   echo "$VERSION" ;;
    *)         cmd_help ;;
esac
