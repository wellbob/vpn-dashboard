#!/usr/bin/env python3
"""vpn-dashboard: веб-панель статистики VPN и Telegram-бот.

Работает от непривилегированного пользователя и читает готовый stats.json, который
пишет collector.py. Менять на сервере ничего не умеет. Единственное исключение —
кнопки защиты от РКН: дашборд кладёт просьбу в request.json, а сборщик выполняет
её, только если она из короткого белого списка (включить / выключить / обновить).
"""
import hashlib
import hmac
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http import cookies
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

APP_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_FILE = '/etc/vpn-dashboard/config.json'
DATA_DIR = '/var/lib/vpn-dashboard'
STATS_FILE = f'{DATA_DIR}/stats.json'
RESULT_FILE = f'{DATA_DIR}/action.json'
SETTINGS_FILE = f'{DATA_DIR}/web/settings.json'   # всё, что дашборд может менять, лежит в web/
REQUEST_FILE = f'{DATA_DIR}/web/request.json'

COOKIE = 'vpnd'
SESSION_TTL = 7 * 86400
LOGIN_MAX_FAILS = 10       # неудачных попыток входа ...
LOGIN_WINDOW = 300         # ... за столько секунд — дальше пауза
ACTIONS = ('rkn_on', 'rkn_off', 'rkn_update', 'ru_install', 'ru_on', 'ru_off', 'ru_update',
           'ru_check', 'ru_test', 'ru_uninstall')

DEFAULT_CONFIG = {'bind': ['127.0.0.1', 'amn0'], 'port': 8080}

settings_lock = threading.Lock()
sessions = {}              # токен -> срок действия
login_fails = {}           # ip -> [время неудачной попытки, ...]


def load_json(path, default):
    try:
        with open(path) as f:
            return json.load(f)
    except (OSError, ValueError):
        return default


def write_json(path, data, mode=0o600):
    tmp = f'{path}.tmp'
    with open(tmp, 'w') as f:
        json.dump(data, f, ensure_ascii=False, indent=1)
    os.chmod(tmp, mode)
    os.replace(tmp, path)


def get_settings():
    with settings_lock:
        return load_json(SETTINGS_FILE, {})


def update_settings(**changes):
    with settings_lock:
        s = load_json(SETTINGS_FILE, {})
        s.update(changes)
        write_json(SETTINGS_FILE, s)
        return s


def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    digest = hashlib.pbkdf2_hmac('sha256', password.encode(), bytes.fromhex(salt), 200_000).hex()
    return f'pbkdf2${salt}${digest}'


def check_password(password, stored):
    try:
        _, salt, digest = stored.split('$')
    except (AttributeError, ValueError):
        return False
    return hmac.compare_digest(hash_password(password, salt).split('$')[2], digest)


# ------------------------------------------------------------ форматирование

def fmt_bytes(n):
    n = float(n or 0)
    for unit in ('Б', 'КБ', 'МБ', 'ГБ', 'ТБ'):
        if n < 1024 or unit == 'ТБ':
            return f'{n:.0f} {unit}' if unit in ('Б', 'КБ') else f'{n:.1f} {unit}'
        n /= 1024


def fmt_speed(bps):
    mbit = (bps or 0) * 8 / 1_000_000
    return f'{mbit:.2f} Мбит/с' if mbit < 10 else f'{mbit:.0f} Мбит/с'


def fmt_ago(ts):
    if not ts:
        return 'ещё не подключался'
    d = int(time.time() - ts)
    if d < 180:
        return 'сейчас'
    if d < 3600:
        return f'{d // 60} мин назад'
    if d < 86400:
        return f'{d // 3600} ч назад'
    return f'{d // 86400} дн назад'


def fmt_dur(sec):
    sec = int(sec or 0)
    if sec < 3600:
        return f'{max(sec // 60, 1)} мин'
    h, m = divmod(sec // 60, 60)
    return f'{h} ч {m} мин' if h < 24 else f'{h // 24} дн {h % 24} ч'


def fmt_time(ts):
    return time.strftime('%d.%m %H:%M', time.localtime(ts)) if ts else '—'


def esc(s):
    return str(s).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;')


# ------------------------------------------------------------ Telegram-бот

bot_status = {'ok': False, 'text': 'не настроен'}


def rkn_installed(st):
    return bool((st.get('rkn') or {}).get('installed'))


def keyboard(st):
    """Кнопка «Защита» — только если защита установлена на сервере."""
    row2 = [{'text': '📜 История'}] + ([{'text': '🛡 Защита'}] if rkn_installed(st) else []) + [{'text': '🖥 Сервер'}]
    return {'keyboard': [[{'text': '📊 Сводка'}, {'text': '👥 Клиенты'}], row2], 'resize_keyboard': True}


def tg_api(token, method, params=None, timeout=35):
    data = json.dumps(params or {}).encode()
    req = urllib.request.Request(f'https://api.telegram.org/bot{token}/{method}', data=data,
                                 headers={'Content-Type': 'application/json'})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            res = json.load(r)
    except urllib.error.HTTPError as e:
        try:
            res = json.load(e)
        except ValueError:
            raise RuntimeError(f'HTTP {e.code}')
    if not res.get('ok'):
        raise RuntimeError(res.get('description', 'ошибка Telegram'))
    return res['result']


def status_lines(st):
    lines = []
    for m in st.get('modules', []):
        lines.append(f"{'✅' if m['running'] else '❌'} {esc(m['title'])}")
    for s in st.get('services', []):
        if s['running'] or s.get('enabled'):   # намеренно выключенные службы не показываем
            lines.append(f"{'✅' if s['running'] else '❌'} {esc(s['title'])}")
    ru = st.get('ru_filter') or {}
    if ru.get('installed'):
        lines.append(f"{'✅' if ru.get('enabled') else '⚠️'} Фильтр RU (sing-box {esc(ru.get('version', ''))})"
                     f"{'' if ru.get('enabled') else ' — выключен'}")
    rkn = st.get('rkn') or {}
    if rkn.get('installed'):
        lines.append(f"{'✅' if rkn.get('enabled') else '⚠️'} Защита от РКН"
                     f"{'' if rkn.get('enabled') else ' — выключена'}")
    return '\n'.join(lines)


def tg_summary(st):
    t = st.get('totals', {})
    ping = ', '.join(f'{h} — {v} мс' if v is not None else f'{h} — нет ответа'
                     for h, v in (st.get('server', {}).get('ping') or {}).items())
    return (f"📊 <b>Сводка VPN</b>\n\n"
            f"Онлайн: <b>{t.get('online', 0)} из {t.get('clients', 0)}</b>\n"
            f"Скорость сейчас: ↓ {fmt_speed(t.get('down_speed'))}  ↑ {fmt_speed(t.get('up_speed'))}\n"
            f"Сегодня: ↓ {fmt_bytes(t.get('today_down'))}  ↑ {fmt_bytes(t.get('today_up'))}\n"
            f"За неделю: ↓ {fmt_bytes(t.get('week_down'))}  ↑ {fmt_bytes(t.get('week_up'))}\n"
            f"За всё время: ↓ {fmt_bytes(t.get('total_down'))}  ↑ {fmt_bytes(t.get('total_up'))}\n"
            f"Пинг: {ping or '—'}\n\n{status_lines(st)}")


def tg_clients(st):
    lines = ['👥 <b>Клиенты</b>']
    for c in st.get('clients', []):
        lines.append(f"\n{'🟢' if c['online'] else '⚪️'} <b>{esc(c['name'])}</b> — {fmt_ago(c['last_handshake'])}")
        if c['online']:
            lines.append(f"   сейчас: ↓ {fmt_speed(c['down_speed'])}  ↑ {fmt_speed(c['up_speed'])}")
        lines.append(f"   сегодня: ↓ {fmt_bytes(c['today_down'])}  ↑ {fmt_bytes(c['today_up'])}")
        lines.append(f"   неделя: ↓ {fmt_bytes(c['week_down'])}  ↑ {fmt_bytes(c['week_up'])}")
        lines.append(f"   всего: ↓ {fmt_bytes(c['total_down'])}  ↑ {fmt_bytes(c['total_up'])}")
    if len(lines) == 1:
        lines.append('\nКлиентов пока нет.')
    return '\n'.join(lines)


def tg_history(st):
    lines = ['📜 <b>Последние подключения</b>\n']
    for s in st.get('sessions', [])[:12]:
        if s.get('end'):
            lines.append(f"⚪️ <b>{esc(s['client'])}</b> {fmt_time(s['start'])} — {fmt_dur(s['end'] - s['start'])}, "
                         f"↓ {fmt_bytes(s.get('down'))}")
        else:
            lines.append(f"🟢 <b>{esc(s['client'])}</b> с {fmt_time(s['start'])}, сейчас в сети")
    if len(lines) == 1:
        lines.append('Подключений пока не было.')
    return '\n'.join(lines)


def tg_protection(st):
    r = st.get('rkn') or {}
    if not r.get('installed'):
        return '🛡 <b>Защита от РКН</b>\n\nНе установлена.'
    nxt = fmt_time(r.get('next_update')) if r.get('next_update') else '—'
    return (f"🛡 <b>Защита от РКН</b> — {'включена ✅' if r.get('enabled') else 'ВЫКЛЮЧЕНА ⚠️'}\n\n"
            f"Сетей РКН в списке: {r.get('nets_in', '—')}\n"
            f"Сетей VK/OK/Max: {r.get('nets_out', '—')}\n"
            f"Отбито попыток: сегодня {r.get('blocked_today', 0)}, всего {r.get('blocked_total', 0)}\n"
            f"Списки обновлены: {r.get('last_update') or '—'}\n"
            f"Автообновление: {'да, следующее ' + nxt if r.get('auto_update') else 'выключено'}")


def tg_server(st):
    s = st.get('server', {})
    load = ' / '.join(str(x) for x in s.get('load', []))
    ping = '\n'.join(f'   {h}: {v} мс' if v is not None else f'   {h}: нет ответа'
                     for h, v in (s.get('ping') or {}).items())
    up = int(s.get('uptime') or 0)
    return (f"🖥 <b>Сервер</b> {esc(s.get('hostname', ''))}\n\n"
            f"Без перезагрузки: {fmt_dur(up)}\n"
            f"Процессор: {s.get('cpu', '—')}% · нагрузка {load}\n"
            f"Память: {fmt_bytes(s.get('mem_used'))} из {fmt_bytes(s.get('mem_total'))}\n"
            f"Диск: {fmt_bytes(s.get('disk_used'))} из {fmt_bytes(s.get('disk_total'))}\n"
            f"Канал сейчас: ↓ {fmt_speed(s.get('net_down_speed'))}  ↑ {fmt_speed(s.get('net_up_speed'))}\n"
            f"Пинг:\n{ping or '   —'}")


def tg_handle(token, msg, allowed, denied_recently):
    chat, user = msg['chat']['id'], (msg.get('from') or {}).get('id')
    text = (msg.get('text') or '').strip()
    if user not in allowed:
        if time.time() - denied_recently.get(user, 0) > 600:
            denied_recently[user] = time.time()
            tg_api(token, 'sendMessage', {'chat_id': chat, 'parse_mode': 'HTML', 'text':
                   f'⛔ Нет доступа.\n\nВаш Telegram ID: <code>{user}</code>\n'
                   f'Добавьте его в настройках дашборда VPN.'})
        return
    st = load_json(STATS_FILE, {})
    routes = [(('/clients', 'Клиенты'), tg_clients), (('/history', 'История'), tg_history),
              (('/server', 'Сервер'), tg_server), (('/stats', 'Сводка'), tg_summary)]
    if rkn_installed(st):
        routes.insert(2, (('/protection', 'Защита'), tg_protection))
    for (cmd, word), fn in routes:
        if text.startswith(cmd) or word in text:
            reply = fn(st)
            break
    else:
        reply = ('Привет! Я показываю статистику VPN — только по запросу.\n\n'
                 '📊 Сводка — онлайн, скорость, трафик, состояние\n'
                 '👥 Клиенты — кто онлайн и сколько скачал\n'
                 '📜 История — последние подключения\n'
                 + ('🛡 Защита — защита от РКН\n' if rkn_installed(st) else '') +
                 '🖥 Сервер — нагрузка, память, пинг')
    tg_api(token, 'sendMessage', {'chat_id': chat, 'text': reply, 'parse_mode': 'HTML',
                                  'reply_markup': keyboard(st)})


def bot_loop():
    offset, token_seen, denied = 0, None, {}
    while True:
        s = get_settings()
        token, allowed = s.get('tg_token') or '', set(s.get('tg_ids') or [])
        if not token:
            bot_status.update(ok=False, text='не настроен')
            time.sleep(5)
            continue
        if token != token_seen:
            token_seen, offset = token, 0
        try:
            updates = tg_api(token, 'getUpdates', {'offset': offset, 'timeout': 25,
                                                   'allowed_updates': ['message']})
            bot_status.update(ok=True, text=f"работает (@{s.get('tg_bot', '')})")
            for u in updates:
                offset = u['update_id'] + 1
                if 'message' in u:
                    try:
                        tg_handle(token, u['message'], allowed, denied)
                    except Exception as e:  # одно неудачное сообщение не должно ронять бота
                        print(f'bot: {e}', file=sys.stderr)
        except Exception as e:
            bot_status.update(ok=False, text=f'ошибка: {e}')
            time.sleep(15)


# ------------------------------------------------------------ веб

def page(name):
    with open(os.path.join(APP_DIR, 'web', name), 'rb') as f:
        return f.read()


class Handler(BaseHTTPRequestHandler):
    server_version = 'vpn-dashboard'

    def log_message(self, *args):
        pass

    def send(self, code, body=b'', ctype='text/html; charset=utf-8', headers=None):
        if isinstance(body, (dict, list)):
            body, ctype = json.dumps(body, ensure_ascii=False).encode(), 'application/json; charset=utf-8'
        elif isinstance(body, str):
            body = body.encode()
        self.send_response(code)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Content-Security-Policy',
                         "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(body)

    def redirect(self, to, headers=None):
        self.send(303, b'', headers={'Location': to, **(headers or {})})

    def session(self):
        c = cookies.SimpleCookie(self.headers.get('Cookie', ''))
        tok = c[COOKIE].value if COOKIE in c else ''
        exp = sessions.get(tok)
        if exp and exp > time.time():
            return tok
        sessions.pop(tok, None)
        return None

    def body(self):
        n = min(int(self.headers.get('Content-Length') or 0), 65536)
        return self.rfile.read(n).decode('utf-8', 'replace')

    def json_body(self):
        try:
            d = json.loads(self.body() or '{}')
            return d if isinstance(d, dict) else {}
        except ValueError:
            return {}

    # ---------------- GET
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        path = url.path
        if path == '/login':
            return self.send(200, page('login.html'))
        if path == '/favicon.ico':
            return self.send(204)
        if not self.session():
            return self.redirect('/login') if not path.startswith('/api/') else self.send(401, {'error': 'auth'})
        if path == '/':
            return self.send(200, page('index.html'))
        if path == '/api/stats':
            st = load_json(STATS_FILE, {})
            st['default_password'] = bool(get_settings().get('default_password'))
            return self.send(200, st)
        if path == '/api/settings':
            s = get_settings()
            return self.send(200, {'username': s.get('username', ''), 'tg_ids': s.get('tg_ids', []),
                                   'tg_token_set': bool(s.get('tg_token')), 'tg_bot': s.get('tg_bot', ''),
                                   'bot': bot_status})
        if path == '/api/action':
            rid = (urllib.parse.parse_qs(url.query).get('id') or [''])[0]
            res = load_json(RESULT_FILE, {})
            return self.send(200, res if res.get('id') == rid else {'id': rid, 'pending': True})
        self.send(404, {'error': 'not found'})

    # ---------------- POST
    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        if path == '/login':
            return self.login()
        if path == '/logout':
            tok = self.session()
            sessions.pop(tok, None)
            return self.redirect('/login', {'Set-Cookie': f'{COOKIE}=; Max-Age=0; Path=/'})
        if not self.session():
            return self.send(401, {'error': 'auth'})
        if self.headers.get('X-Requested-With') != 'fetch':
            return self.send(403, {'error': 'csrf'})
        routes = {'/api/password': self.change_password, '/api/telegram': self.change_telegram,
                  '/api/telegram/test': self.test_telegram, '/api/action': self.request_action}
        if path in routes:
            return routes[path](self.json_body())
        self.send(404, {'error': 'not found'})

    def login(self):
        ip, now = self.client_address[0], time.time()
        fails = [t for t in login_fails.get(ip, []) if now - t < LOGIN_WINDOW]
        login_fails[ip] = fails
        if len(fails) >= LOGIN_MAX_FAILS:
            return self.redirect('/login?e=wait')
        form = urllib.parse.parse_qs(self.body())
        user = (form.get('username') or [''])[0]
        pw = (form.get('password') or [''])[0]
        s = get_settings()
        if hmac.compare_digest(user, s.get('username', '')) and check_password(pw, s.get('password')):
            tok = secrets.token_urlsafe(32)
            sessions[tok] = now + SESSION_TTL
            login_fails.pop(ip, None)
            return self.redirect('/', {'Set-Cookie':
                                       f'{COOKIE}={tok}; Max-Age={SESSION_TTL}; Path=/; HttpOnly; SameSite=Strict'})
        fails.append(now)
        time.sleep(1)
        self.redirect('/login?e=1')

    def change_password(self, d):
        s = get_settings()
        if not check_password(d.get('current', ''), s.get('password')):
            return self.send(400, {'error': 'Текущий пароль неверный'})
        user = (d.get('username') or '').strip()
        new = d.get('password') or ''
        if not user or len(user) > 64:
            return self.send(400, {'error': 'Укажи логин'})
        if len(new) < 6:
            return self.send(400, {'error': 'Пароль — минимум 6 символов'})
        update_settings(username=user, password=hash_password(new), default_password=False)
        sessions.clear()  # все входы со старым паролем закрываются
        self.send(200, {'ok': True})

    @staticmethod
    def parse_ids(raw):
        return [int(x) for x in str(raw or '').replace(',', ' ').split()]

    def change_telegram(self, d):
        token = (d.get('token') or '').strip()
        try:
            ids = self.parse_ids(d.get('ids'))
        except ValueError:
            return self.send(400, {'error': 'ID — только цифры, через запятую'})
        changes = {'tg_ids': ids}
        if d.get('clear'):
            changes.update(tg_token='', tg_bot='')
        elif token:
            try:
                me = tg_api(token, 'getMe', timeout=10)
            except Exception as e:
                return self.send(400, {'error': f'Telegram не принял токен: {e}'})
            changes.update(tg_token=token, tg_bot=me.get('username', ''))
        update_settings(**changes)
        self.send(200, {'ok': True, 'bot': get_settings().get('tg_bot', '')})

    def test_telegram(self, d):
        s = get_settings()
        token = (d.get('token') or '').strip() or s.get('tg_token', '')
        try:
            ids = self.parse_ids(d.get('ids')) if str(d.get('ids') or '').strip() else s.get('tg_ids', [])
        except ValueError:
            return self.send(400, {'error': 'ID — только цифры, через запятую'})
        if not token:
            return self.send(400, {'error': 'Сначала вставь токен бота'})
        try:
            me = tg_api(token, 'getMe', timeout=10)
        except Exception as e:
            return self.send(400, {'error': f'Токен не работает: {e}'})
        if not ids:
            return self.send(200, {'ok': True, 'bot': me.get('username', ''), 'results': [],
                                   'note': 'Токен рабочий. Добавь свой ID, чтобы проверить отправку.'})
        results = []
        for i in ids:
            try:
                tg_api(token, 'sendMessage', {'chat_id': i, 'text': '✅ Проверка: бот дашборда VPN работает.',
                                              'reply_markup': keyboard(load_json(STATS_FILE, {}))}, timeout=10)
                results.append({'id': i, 'ok': True})
            except Exception as e:
                hint = ' — сначала напиши боту /start' if 'chat not found' in str(e).lower() else ''
                results.append({'id': i, 'ok': False, 'error': f'{e}{hint}'})
        self.send(200, {'ok': all(r['ok'] for r in results), 'bot': me.get('username', ''), 'results': results})

    def request_action(self, d):
        action = d.get('action')
        if action not in ACTIONS:
            return self.send(400, {'error': 'Неизвестное действие'})
        rid = secrets.token_hex(8)
        write_json(REQUEST_FILE, {'action': action, 'id': rid, 'ts': time.time()})
        self.send(200, {'id': rid})


def resolve(addr):
    """'amn0' -> IPv4-адрес интерфейса; адреса возвращаются как есть."""
    if re.fullmatch(r'[\d.]+|[0-9a-fA-F:]+', addr):
        return addr
    try:
        out = subprocess.run(['ip', '-4', '-o', 'addr', 'show', 'dev', addr],
                             capture_output=True, text=True, timeout=5).stdout
    except (OSError, subprocess.TimeoutExpired):
        return None
    m = re.search(r'inet ([\d.]+)', out)
    return m.group(1) if m else None


def serve(addr, port):
    while True:  # интерфейс VPN может появиться позже (или после переустановки) — ждём
        ip = resolve(addr)
        if ip:
            try:
                ThreadingHTTPServer((ip, port), Handler).serve_forever()
            except OSError as e:
                print(f'{ip}:{port}: {e}', file=sys.stderr)
        time.sleep(30)


def init_settings():
    if os.path.exists(SETTINGS_FILE):
        return
    update_settings(username='admin', password=hash_password('admin'), default_password=True,
                    tg_token='', tg_ids=[])


def main():
    if '--init' in sys.argv:
        return init_settings()
    if '--reset-password' in sys.argv:
        update_settings(username='admin', password=hash_password('admin'), default_password=True)
        return print('Логин и пароль сброшены на admin / admin.')
    cfg = {**DEFAULT_CONFIG, **load_json(CONFIG_FILE, {})}
    threading.Thread(target=bot_loop, daemon=True).start()
    for addr in cfg['bind'][1:]:
        threading.Thread(target=serve, args=(addr, cfg['port']), daemon=True).start()
    serve(cfg['bind'][0], cfg['port'])


if __name__ == '__main__':
    main()
