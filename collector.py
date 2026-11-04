#!/usr/bin/env python3
"""Сборщик статистики для vpn-dashboard.

Работает от root и в основном только ЧИТАЕТ: `awg/wg show dump` во всех контейнерах
Amnezia, список клиентов, состояние модулей и служб, защиту от РКН и фильтр RU.
По просьбе дашборда умеет только одно — выполнить команду rkn-shield или ru-filter
строго из белого списка (см. ACTIONS), в фоне, по одной за раз.

Результат: /var/lib/vpn-dashboard/stats.json (читает дашборд).
"""
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import threading
import time

CONFIG_FILE = '/etc/vpn-dashboard/config.json'
DATA_DIR = '/var/lib/vpn-dashboard'
STATS_FILE = f'{DATA_DIR}/stats.json'
STATE_FILE = f'{DATA_DIR}/state.json'
REQUEST_FILE = f'{DATA_DIR}/web/request.json'   # кладёт дашборд
RESULT_FILE = f'{DATA_DIR}/action.json'          # ответ сборщика

INTERVAL = 15          # секунд между замерами
SLOW_EVERY = 60        # модули, службы, пинг — раз в минуту
ONLINE_SEC = 180       # клиент онлайн, если рукопожатие было не раньше
BUCKET = 300           # шаг графика за сутки
HISTORY_SEC = 86400
KEEP_DAYS = 31
MAX_SESSIONS = 500

DEFAULTS = {'ping_targets': ['1.1.1.1', '8.8.8.8']}

# Контейнеры Amnezia: (шаблон имени, название, тип). Порядок важен: awg3 раньше awg.
MODULES = [
    (r'amnezia-awg3', 'AmneziaWG 3.1', 'vpn'),
    (r'amnezia-awg2', 'AmneziaWG 2.0', 'vpn'),
    (r'amnezia-awg-legacy', 'AmneziaWG Legacy', 'vpn'),
    (r'amnezia-awg', 'AmneziaWG', 'vpn'),
    (r'amnezia-wireguard', 'WireGuard', 'vpn'),
    (r'amnezia-xray', 'Xray (VLESS Reality)', 'vpn'),
    (r'amnezia-openvpn-cloak|amnezia-cloak', 'OpenVPN over Cloak', 'vpn'),
    (r'amnezia-openvpn', 'OpenVPN', 'vpn'),
    (r'amnezia-shadowsocks|amnezia-ss', 'Shadowsocks', 'vpn'),
    (r'amnezia-ipsec|amnezia-ikev2', 'IKEv2', 'vpn'),
    (r'amnezia-exit', 'Exit-нода', 'vpn'),
    (r'amnezia-dns', 'AmneziaDNS', 'service'),
    (r'amnezia-adguard', 'AdGuard Home', 'service'),
    (r'amnezia-socks5proxy|amnezia-socks5|amnezia-socks', 'SOCKS5-прокси', 'service'),
    (r'amnezia-tor', 'Tor-сайт', 'service'),
    (r'amnezia-sftp', 'SFTP', 'service'),
    (r'amnezia-telemt|telemt', 'Telegram MTProxy', 'service'),
    (r'amnezia-warp|warp', 'Cloudflare WARP', 'service'),
    (r'amnezia_panel', 'Панель PRVTPRO', 'panel'),
]
# Контейнеры, из которых читаем клиентов и трафик (есть awg/wg)
PEER_CONTAINERS = re.compile(r'^amnezia-(awg\d*|awg-legacy|wireguard)(-\d+)?$')

# Службы на самом сервере: показываем только установленные
HOST_SERVICES = [
    ('x-ui', '3x-ui'),
    ('xray', 'Xray'),
    ('nginx', 'Nginx'),
    ('fail2ban', 'Fail2ban'),
    ('docker', 'Docker'),
]

# Что дашборд может попросить сделать (и ничего больше): действие -> (инструмент, аргумент)
ACTIONS = {
    'rkn_on': ('rkn', 'on'), 'rkn_off': ('rkn', 'off'), 'rkn_update': ('rkn', 'update'),
    'ru_install': ('ru', 'install'), 'ru_on': ('ru', 'on'), 'ru_off': ('ru', 'off'),
    'ru_update': ('ru', 'update'), 'ru_check': ('ru', 'check-update'), 'ru_test': ('ru', 'test'),
    'ru_uninstall': ('ru', 'uninstall'),
}
ACTION_TIMEOUT = 900       # установка sing-box через apt может занять несколько минут
RKN_TOOLS = [('rkn-shield', '/usr/local/sbin/rkn-shield'), ('rkn-extra-block', '/usr/local/sbin/rkn-extra-block')]
RU_TOOL = '/opt/vpn-dashboard/ru-filter.sh'
_action = {'thread': None}


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def sh(cmd, timeout=10):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout if r.returncode == 0 else ''
    except (OSError, subprocess.TimeoutExpired):
        return ''


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def save_json(path, data, mode=0o644):
    tmp = f'{path}.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, ensure_ascii=False)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def read_text(path, default=''):
    try:
        with open(path) as f:
            return f.read().strip()
    except OSError:
        return default


# ------------------------------------------------------------ модули (контейнеры)

def module_info(name):
    for pattern, title, kind in MODULES:
        if re.fullmatch(rf'(?:{pattern})(?:-\d+)?', name):
            suffix = re.search(r'-(\d+)$', name)
            return title + (f' #{suffix.group(1)}' if suffix else ''), kind
    return None, None


def simplify_ports(ports):
    """'0.0.0.0:37714->37714/udp, [::]:37714->...' -> ['37714/udp']; локальные — с адресом."""
    out = []
    for host, port, proto in re.findall(r'([\d.]+|\[::\]|::):(\d+)->\d+/(\w+)', ports or ''):
        item = f'{port}/{proto}' if host in ('0.0.0.0', '[::]', '::') else f'{host}:{port}/{proto}'
        if item not in out:
            out.append(item)
    return out


def docker_modules():
    if not shutil.which('docker'):
        return []
    out = sh(['docker', 'ps', '-a', '--format', '{{.Names}}\t{{.State}}\t{{.Status}}\t{{.Ports}}'])
    mods = []
    for line in out.splitlines():
        f = line.split('\t') + ['', '', '']
        title, kind = module_info(f[0])
        if not title and not f[0].startswith('amnezia'):
            continue
        mods.append({'container': f[0], 'title': title or f[0], 'kind': kind or 'service',
                     'running': f[1] == 'running', 'status': f[2], 'ports': simplify_ports(f[3])})
    return mods


def host_services():
    units = set()
    for line in sh(['systemctl', 'list-unit-files', '--type=service', '--no-legend', '--no-pager']).splitlines():
        if line.strip():
            unit = line.split()[0]
            units.add(unit[:-8] if unit.endswith('.service') else unit)
    res = []
    for unit, title in HOST_SERVICES:
        if unit in units:
            # выключенная намеренно служба (disabled) — не авария, показываем серой
            res.append({'unit': unit, 'title': title,
                        'running': sh(['systemctl', 'is-active', unit]).strip() == 'active',
                        'enabled': sh(['systemctl', 'is-enabled', unit]).strip() in ('enabled', 'static', 'alias')})
    return res


# ------------------------------------------------------------ клиенты VPN

PEER_SCRIPT = (
    'B=$(command -v awg || command -v wg); [ -n "$B" ] || exit 0; '
    'echo "@@BIN $(basename $B) $($B --version 2>/dev/null | head -1)"; '
    # параметры обфускации без секретных значений — по ним определяется версия протокола
    'for f in /opt/amnezia/*/*.conf; do [ -f "$f" ] && sed -n "/^\\[Interface\\]/,/^\\[Peer\\]/p" "$f" '
    '| grep -E "^(Jc|S3|S4|I1|H1|HeaderProtectionKey|RandomTrailers|DisableCookies) *=" '
    '| sed -E "s/^(HeaderProtectionKey) *=.*/\\1 = x/" | sed "s/^/@@CFG /"; done; '
    'for i in $($B show interfaces); do echo "@@IF $i"; $B show "$i" dump; done; '
    'for f in /opt/amnezia/*/clientsTable; do [ -f "$f" ] && { echo "@@CT"; cat "$f"; echo; }; done; true'
)


def protocol_title(binary, version_line, cfg):
    """Версия протокола по параметрам интерфейса, а не по имени контейнера:
    приложение Amnezia оставляет контейнер amnezia-awg2 и после перехода на AWG 3."""
    if binary == 'wg':
        return 'WireGuard'
    if {'HeaderProtectionKey', 'RandomTrailers', 'DisableCookies'} & cfg.keys():
        m = re.search(r'v?(3\.\d+)', version_line)
        return f'AmneziaWG {m.group(1) if m else "3"}'
    if {'S3', 'S4', 'I1'} & cfg.keys() or '-' in cfg.get('H1', ''):
        return 'AmneziaWG 2.0'
    if 'Jc' in cfg:
        return 'AmneziaWG 1.0'
    return 'AmneziaWG'


def read_peers(container):
    """-> ([(pubkey, ip, endpoint_ip, handshake, rx, tx)], {pubkey: имя}, название протокола или None)"""
    out = sh(['docker', 'exec', container, 'sh', '-c', PEER_SCRIPT], timeout=15)
    peers, names, mode, first, buf = [], {}, None, False, []
    binary, version_line, cfg = '', '', {}

    def flush_names():
        try:
            for c in json.loads('\n'.join(buf) or '[]'):
                if isinstance(c, dict) and c.get('clientId'):
                    names[c['clientId']] = (c.get('userData') or {}).get('clientName') or ''
        except ValueError:
            pass
        buf.clear()

    for line in out.splitlines():
        if line.startswith('@@BIN '):
            parts = line.split(' ', 2)
            binary, version_line = parts[1], (parts[2] if len(parts) > 2 else '')
        elif line.startswith('@@CFG '):
            k, _, v = line[6:].partition('=')
            cfg[k.strip()] = v.strip()
        elif line.startswith('@@IF '):
            if mode == 'ct':
                flush_names()
            mode, first = 'if', True
        elif line == '@@CT':
            if mode == 'ct':
                flush_names()
            mode = 'ct'
        elif mode == 'if':
            if first:          # первая строка — сам интерфейс
                first = False
                continue
            f = line.split('\t')
            if len(f) < 8:
                continue
            try:
                ep = f[2].rsplit(':', 1)[0].strip('[]') if f[2] != '(none)' else ''
                peers.append((f[0], f[3].split(',')[0].split('/')[0], ep, int(f[4]), int(f[5]), int(f[6])))
            except ValueError:
                continue
        elif mode == 'ct':
            buf.append(line)
    if mode == 'ct':
        flush_names()
    return peers, names, (protocol_title(binary, version_line, cfg) if binary else None)


# ------------------------------------------------------------ защита от РКН

def rkn_tool():
    for name, path in RKN_TOOLS:
        if os.path.exists(path):
            return name, path
    return None, None


def ipset_counts():
    counts, name = {}, None
    for line in sh(['ipset', 'list', '-t']).splitlines():
        if line.startswith('Name:'):
            name = line.split(':', 1)[1].strip()
        elif line.startswith('Number of entries:') and name:
            counts[name] = int(line.split(':', 1)[1])
    return counts


def drop_counter(chain):
    total = 0
    for ipt in ('iptables', 'ip6tables'):
        for line in sh([ipt, '-w', '-t', 'mangle', '-L', chain, '-vnx']).splitlines():
            f = line.split()
            if len(f) > 2 and f[2] == 'DROP' and f[0].isdigit():
                total += int(f[0])
    return total


def timer_next(unit):
    try:  # systemd 248+: точное время в микросекундах
        data = json.loads(sh(['systemctl', 'list-timers', unit, '--all', '--no-legend', '--output=json']) or '[]')
        if data and data[0].get('next'):
            return int(data[0]['next']) // 1_000_000
    except (ValueError, TypeError, KeyError):
        pass
    text = sh(['systemctl', 'show', unit, '-p', 'NextElapseUSecRealtime', '--value']).strip()
    secs = sh(['date', '-d', text, '+%s']).strip() if text else ''
    return int(secs) if secs.isdigit() else None


def rkn_info(st, today):
    name, path = rkn_tool()
    if not name:
        return {'installed': False}
    rules = sh(['iptables-save'])
    if name == 'rkn-shield':
        conf = read_text('/etc/rkn-shield/config')
        cnt = ipset_counts()
        info = {
            'installed': True, 'tool': name,
            'enabled': read_text('/etc/rkn-shield/state', 'off') == 'on' and 'RKN_SHIELD' in rules,
            'block_in': 'BLOCK_IN=no' not in conf, 'block_out': 'BLOCK_OUT=no' not in conf,
            'nets_in': cnt.get('rkns_in4', 0) + cnt.get('rkns_in6', 0),
            'nets_out': cnt.get('rkns_out4', 0) + cnt.get('rkns_out6', 0),
            'last_update': read_text('/var/lib/rkn-shield/last_update'),
            'next_update': timer_next('rkn-shield-update.timer'),
            'auto_update': sh(['systemctl', 'is-active', 'rkn-shield-update.timer']).strip() == 'active',
        }
        counter = drop_counter('RKN_SHIELD_IN')
    else:
        info = {'installed': True, 'tool': name, 'enabled': 'RKN_EXTRA' in rules,
                'block_in': True, 'block_out': True,
                'auto_update': sh(['systemctl', 'is-active', 'rkn-extra-block.timer']).strip() == 'active',
                'next_update': timer_next('rkn-extra-block.timer')}
        counter = 0
    # счётчик отбитых попыток обнуляется при перестройке правил — копим сами
    r = st.setdefault('rkn', {'last': 0, 'total': 0, 'days': {}})
    delta = counter - r['last'] if counter >= r['last'] else counter
    r['last'] = counter
    r['total'] += delta
    r['days'][today] = r['days'].get(today, 0) + delta
    for d in sorted(r['days'])[:-KEEP_DAYS]:
        del r['days'][d]
    info['blocked_total'] = r['total']
    info['blocked_today'] = r['days'].get(today, 0)
    return info


def ru_info():
    """Фильтр RU (ru-filter.sh + sing-box)."""
    if not os.path.exists(RU_TOOL):
        return {'available': False}
    try:
        info = json.loads(sh(['bash', RU_TOOL, 'status', '--json'], timeout=20) or '{}')
    except ValueError:
        info = {}
    info['available'] = True
    info['enabled'] = bool(info.get('installed') and info.get('state') == 'on' and info.get('active') and info.get('rules'))
    upd = info.get('update') or {}
    info['update_available'] = bool(upd.get('candidate') and upd.get('installed') and upd['candidate'] != upd['installed'])
    return info


def run_action(rid, path, arg, on_done):
    result = {'id': rid, 'ts': int(time.time()), 'ok': False}
    try:
        r = subprocess.run([path, arg], capture_output=True, text=True, timeout=ACTION_TIMEOUT)
        text = re.sub(r'\x1b\[[0-9;]*m', '', (r.stdout + r.stderr)).strip()
        result['ok'] = r.returncode == 0
        result['message'] = text.splitlines()[-1] if text else ('Готово' if result['ok'] else 'Ошибка')
    except (OSError, subprocess.TimeoutExpired) as e:
        result['message'] = f'Не удалось выполнить: {e}'
    result['ts'] = int(time.time())
    save_json(RESULT_FILE, result)
    on_done()


def handle_request(on_done=lambda: None):
    """Принять просьбу дашборда (только из ACTIONS) и выполнить её в фоне."""
    req = load_json(REQUEST_FILE, None)
    if req is None:
        return False
    try:
        os.remove(REQUEST_FILE)
    except OSError:
        pass
    if not isinstance(req, dict):
        return False
    rid = str(req.get('id', ''))
    if not re.fullmatch(r'[A-Za-z0-9_-]{1,40}', rid):
        return False

    def fail(message):
        save_json(RESULT_FILE, {'id': rid, 'ts': int(time.time()), 'ok': False, 'message': message})
        return True

    action = ACTIONS.get(req.get('action'))
    if time.time() - float(req.get('ts') or 0) > 120:
        return fail('Запрос устарел, попробуй ещё раз')
    if not action:
        return fail('Неизвестное действие')
    if _action['thread'] and _action['thread'].is_alive():
        return fail('Сейчас выполняется другое действие — подожди, пока оно закончится')
    tool, arg = action
    if tool == 'rkn':
        path = rkn_tool()[1]
        if not path:
            return fail('Защита от РКН не установлена')
    else:
        path = RU_TOOL
        if not os.path.exists(path):
            return fail('Нет файла ru-filter.sh — обнови дашборд')
    _action['thread'] = threading.Thread(target=run_action, args=(rid, path, arg, on_done), daemon=True)
    _action['thread'].start()
    return True


def wait_actions(timeout=None):
    """Для тестов: дождаться фонового действия."""
    if _action['thread']:
        _action['thread'].join(timeout)


# ------------------------------------------------------------ сервер

def ping(host):
    out = sh(['ping', '-c', '3', '-W', '2', '-q', host], timeout=15)
    m = re.search(r'= [\d.]+/([\d.]+)/', out)
    return round(float(m.group(1)), 1) if m else None


def default_route():
    out = sh(['ip', '-4', 'route', 'get', '1.1.1.1'])
    dev, src = re.search(r'dev (\S+)', out), re.search(r'src (\S+)', out)
    return (dev.group(1) if dev else 'eth0'), (src.group(1) if src else '')


def net_bytes(iface):
    for line in read_text('/proc/net/dev').splitlines():
        if line.strip().startswith(f'{iface}:'):
            v = line.split(':', 1)[1].split()
            return int(v[0]), int(v[8])
    return 0, 0


def cpu_times():
    f = [int(x) for x in read_text('/proc/stat').splitlines()[0].split()[1:]]
    idle = f[3] + (f[4] if len(f) > 4 else 0)
    return sum(f), idle


def system_static():
    os_name = 'Linux'
    for line in read_text('/etc/os-release').splitlines():
        if line.startswith('PRETTY_NAME='):
            os_name = line.split('=', 1)[1].strip('"')
    return {'hostname': socket.gethostname(), 'os': os_name, 'kernel': os.uname().release,
            'cpus': os.cpu_count() or 1}


def server_info():
    info = {}
    try:
        info['uptime'] = int(float(read_text('/proc/uptime').split()[0]))
        info['load'] = [float(x) for x in read_text('/proc/loadavg').split()[:3]]
        mem = {}
        for line in read_text('/proc/meminfo').splitlines():
            k, v = line.split(':', 1)
            mem[k] = int(v.split()[0]) * 1024
        info['mem_total'] = mem.get('MemTotal', 0)
        info['mem_used'] = mem.get('MemTotal', 0) - mem.get('MemAvailable', 0)
        info['swap_total'] = mem.get('SwapTotal', 0)
        info['swap_used'] = mem.get('SwapTotal', 0) - mem.get('SwapFree', 0)
    except (ValueError, IndexError):
        pass
    du = shutil.disk_usage('/')
    info['disk_total'], info['disk_used'] = du.total, du.used
    return info


# ------------------------------------------------------------ основной цикл

def sum_days(days, dates, idx):
    return sum(days.get(d, [0, 0])[idx] for d in dates)


def collect(cfg, state, ctx):
    now = time.time()
    today = time.strftime('%Y-%m-%d', time.localtime(now))
    week = [time.strftime('%Y-%m-%d', time.localtime(now - i * 86400)) for i in range(7)]
    dt = (now - ctx['prev_t']) if ctx.get('prev_t') else None
    peers_st = state.setdefault('peers', {})
    sessions = state.setdefault('sessions', [])
    history = state.setdefault('history', [])
    bucket = state.setdefault('bucket', [0, 0, 0])

    if now - ctx.get('slow_t', 0) >= SLOW_EVERY:
        ctx['slow_t'] = now
        ctx['pings'] = {h: ping(h) for h in cfg['ping_targets']}
        ctx['modules'] = docker_modules()
        ctx['services'] = host_services()
        ctx['wan'], ctx['ip'] = default_route()
        ctx['rkn'] = rkn_info(state, today)
        ctx['ru'] = ru_info()

    clients, sum_down, sum_up = [], 0, 0
    for mod in ctx['modules']:
        if not (mod['running'] and PEER_CONTAINERS.match(mod['container'])):
            continue
        peers, names, proto = read_peers(mod['container'])
        if proto:
            mod['title'] = proto + (f" #{mod['container'].rsplit('-', 1)[1]}"
                                    if re.search(r'-\d+$', mod['container']) else '')
        mod['clients'] = len(peers)
        mod['online'] = 0
        for pub, ip, ep, hs, rx, tx in peers:
            key = f"{mod['container']}:{pub}"
            if key not in peers_st and pub in peers_st:   # данные первой версии (без имени контейнера)
                peers_st[key] = peers_st.pop(pub)
            p = peers_st.get(key)
            if p is None:
                # первый замер: накопленное с запуска контейнера (могут быть недели) идёт только во «всё время»,
                # «сегодня», «неделя» и график начинаются с нуля
                p = peers_st[key] = {'rx': rx, 'tx': tx, 'total_rx': rx, 'total_tx': tx,
                                     'days': {}, 'first_seen': now}
                d_rx = d_tx = 0
            else:
                # счётчики сбрасываются при перезапуске контейнера
                d_rx = rx - p['rx'] if rx >= p['rx'] else rx
                d_tx = tx - p['tx'] if tx >= p['tx'] else tx
                p['rx'], p['tx'] = rx, tx
                p['total_rx'] += d_rx
                p['total_tx'] += d_tx
                day = p['days'].setdefault(today, [0, 0])
                day[0] += d_tx
                day[1] += d_rx
            for d in sorted(p['days'])[:-KEEP_DAYS]:
                del p['days'][d]
            if hs:
                p['hs'] = hs
            if d_rx or d_tx:
                p['active'] = now
            name = names.get(pub) or f'Клиент {ip}'
            p['name'] = name
            last_hs = p.get('hs', 0)
            online = bool(last_hs) and now - last_hs < ONLINE_SEC
            sess = p.get('open')
            if online and not sess:
                start = last_hs if last_hs > p.get('closed', 0) else now
                sess = p['open'] = {'start': start, 'rx0': p['total_rx'] - d_rx, 'tx0': p['total_tx'] - d_tx, 'ip': ep}
            if online:
                sess['last'] = max(last_hs, p.get('active', 0))
                if ep:
                    sess['ip'] = ep
            elif sess:
                end = sess.get('last') or last_hs or now
                sessions.append({'client': name, 'module': mod['title'], 'start': int(sess['start']),
                                 'end': int(end), 'down': p['total_tx'] - sess['tx0'],
                                 'up': p['total_rx'] - sess['rx0'], 'ip': sess.get('ip', '')})
                p['open'], p['closed'] = None, end
            sum_down += d_tx
            sum_up += d_rx
            mod['online'] += online
            days = p['days']
            clients.append({
                'name': name, 'ip': ip, 'module': mod['title'], 'online': online,
                'last_handshake': last_hs, 'endpoint': ep if online else '',
                'session_start': int(sess['start']) if online and sess else None,
                'down_speed': round(d_tx / dt) if dt else 0, 'up_speed': round(d_rx / dt) if dt else 0,
                'today_down': days.get(today, [0, 0])[0], 'today_up': days.get(today, [0, 0])[1],
                'week_down': sum_days(days, week, 0), 'week_up': sum_days(days, week, 1),
                'month_down': sum(v[0] for v in days.values()), 'month_up': sum(v[1] for v in days.values()),
                'total_down': p['total_tx'], 'total_up': p['total_rx'],
            })
    del sessions[:-MAX_SESSIONS]

    # график за сутки: трафик клиентов по 5-минутным интервалам
    start = int(now // BUCKET * BUCKET)
    if bucket[0] != start:
        if bucket[0]:
            history.append(bucket[:])
        bucket[:] = [start, 0, 0]
        while history and history[0][0] < now - HISTORY_SEC:
            history.pop(0)
    bucket[1] += sum_down
    bucket[2] += sum_up

    # по дням за месяц (все клиенты вместе)
    daily = {}
    for p in peers_st.values():
        for d, (down, up) in p.get('days', {}).items():
            daily.setdefault(d, [0, 0])
            daily[d][0] += down
            daily[d][1] += up

    srv = {**ctx['static'], **server_info(), 'ip': ctx.get('ip', ''), 'ping': ctx.get('pings', {})}
    total, idle = cpu_times()
    if ctx.get('cpu'):
        dtot, didle = total - ctx['cpu'][0], idle - ctx['cpu'][1]
        srv['cpu'] = round(100 * (dtot - didle) / dtot, 1) if dtot > 0 else 0
    ctx['cpu'] = (total, idle)
    net = net_bytes(ctx.get('wan', 'eth0'))
    prev = ctx.get('net')
    ok = dt and prev and net[0] >= prev[0] and net[1] >= prev[1]
    srv['net_down_speed'] = round((net[0] - prev[0]) / dt) if ok else 0
    srv['net_up_speed'] = round((net[1] - prev[1]) / dt) if ok else 0
    srv['net_rx_total'], srv['net_tx_total'] = net
    ctx['net'], ctx['prev_t'] = net, now

    clients.sort(key=lambda c: (not c['online'], c['name'].lower()))
    open_sessions = [{'client': c['name'], 'module': c['module'], 'start': c['session_start'], 'end': None,
                      'ip': c['endpoint']} for c in clients if c['online'] and c['session_start']]
    keys = ('down_speed', 'up_speed', 'today_down', 'today_up', 'week_down', 'week_up',
            'month_down', 'month_up', 'total_down', 'total_up')
    return {
        'updated': int(now),
        'server': srv,
        'modules': ctx['modules'],
        'services': ctx['services'],
        'rkn': ctx['rkn'],
        'ru_filter': ctx.get('ru', {}),
        'action_running': bool(_action['thread'] and _action['thread'].is_alive()),
        'clients': clients,
        'totals': {'clients': len(clients), 'online': sum(c['online'] for c in clients),
                   **{k: sum(c[k] for c in clients) for k in keys}},
        'history': history + [bucket],
        'daily': [[d, v[0], v[1]] for d, v in sorted(daily.items())[-30:]],
        'sessions': open_sessions + sessions[::-1][:300],
    }


def main():
    os.makedirs(DATA_DIR, exist_ok=True)
    cfg = {**DEFAULTS, **load_json(CONFIG_FILE, {})}
    state = load_json(STATE_FILE, {})
    ctx = {'static': system_static(), 'modules': [], 'services': [], 'rkn': {}}
    while True:
        t0 = time.time()
        try:
            save_json(STATS_FILE, collect(cfg, state, ctx))
            save_json(STATE_FILE, state, 0o600)
        except Exception as e:  # сборщик не должен падать из-за одного сбоя
            log(f'collect: {e!r}')
        # между замерами раз в секунду проверяем, не просит ли дашборд что-то сделать;
        # когда действие закончится, сразу пересобираем статус
        def refresh_soon():
            ctx['slow_t'] = 0
            ctx['wake'] = True
        while time.time() - t0 < INTERVAL and not ctx.pop('wake', False):
            try:
                handle_request(refresh_soon)
            except Exception as e:
                log(f'request: {e!r}')
            time.sleep(1)


if __name__ == '__main__':
    main()
