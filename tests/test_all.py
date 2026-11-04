#!/usr/bin/env python3
"""Тесты vpn-dashboard без настоящего сервера: команды системы подменяются.

Запуск: python3 tests/test_all.py
"""
import http.cookiejar
import json
import os
import sys
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), '..'))
import collector  # noqa: E402
import dashboard  # noqa: E402


class Clock:
    def __init__(self, t):
        self.t = t

    def __call__(self):
        return self.t


def make_ctx():
    return {'static': {'hostname': 'test', 'os': 'Test OS', 'kernel': '6.0', 'cpus': 2}, 'modules': [], 'services': []}


class FakeSystem:
    """Подменяет collector.sh: отвечает на команды по префиксу."""

    def __init__(self):
        self.answers = {}

    def __call__(self, cmd, timeout=10):
        key = ' '.join(cmd)
        for prefix, ans in self.answers.items():
            if key.startswith(prefix):
                return ans() if callable(ans) else ans
        return ''


def dump(peers):
    lines = ['privkey\tpubkey\t51820\toff\tjc...']  # строка интерфейса
    for pub, ip, ep, hs, rx, tx in peers:
        lines.append(f'{pub}\t(none)\t{ep}\t{ip}/32\t{hs}\t{rx}\t{tx}\toff')
    return '\n'.join(lines)


def peer_output(peers, names):
    table = json.dumps([{'clientId': k, 'userData': {'clientName': v}} for k, v in names.items()], indent=2)
    return f'@@IF awg0\n{dump(peers)}\n@@CT\n{table}\n'


class CollectorTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.fake = FakeSystem()
        self.clock = Clock(1_800_000_000)
        self.orig = (collector.sh, collector.time.time, collector.shutil.which, collector.RKN_TOOLS,
                     collector.REQUEST_FILE, collector.RESULT_FILE, collector.ping)
        collector.sh = self.fake
        collector.time.time = self.clock
        collector.ping = lambda h: 12.3
        collector.RKN_TOOLS = [('rkn-shield', os.path.join(self.tmp, 'no-such-tool'))]
        collector.REQUEST_FILE = os.path.join(self.tmp, 'request.json')
        collector.RESULT_FILE = os.path.join(self.tmp, 'action.json')

    def tearDown(self):
        (collector.sh, collector.time.time, collector.shutil.which, collector.RKN_TOOLS,
         collector.REQUEST_FILE, collector.RESULT_FILE, collector.ping) = self.orig

    def test_bare_server_without_docker_and_rkn(self):
        collector.shutil.which = lambda name: None
        state, ctx = {}, make_ctx()
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        self.assertEqual(st['clients'], [])
        self.assertEqual(st['modules'], [])
        self.assertFalse(st['rkn']['installed'])
        self.assertEqual(st['totals']['online'], 0)
        json.dumps(st)  # всё сериализуется

    def test_several_protocols_counters_and_sessions(self):
        collector.shutil.which = lambda name: '/usr/bin/' + name
        self.fake.answers['docker ps -a'] = (
            'amnezia-awg\trunning\tUp 2 hours\t0.0.0.0:51820->51820/udp\n'
            'amnezia-wireguard\trunning\tUp 2 hours\t0.0.0.0:51821->51821/udp, [::]:51821->51821/udp\n'
            'amnezia-xray\trunning\tUp 2 hours\t0.0.0.0:443->443/tcp\n'
            'amnezia-dns\texited\tExited (0)\t\n'
            'amnezia_panel\trunning\tUp\t127.0.0.1:5000->5000/tcp\n'
            'nginx-other\trunning\tUp\t0.0.0.0:80->80/tcp\n')
        self.fake.answers['systemctl list-unit-files'] = 'sing-box.service enabled enabled\nssh.service enabled enabled\n'
        self.fake.answers['systemctl is-active sing-box'] = 'active\n'
        t0 = self.clock.t
        awg = {'peers': [('A', '10.8.1.1', '1.2.3.4', t0 - 30, 1000, 5000)]}
        self.fake.answers['docker exec amnezia-awg '] = lambda: peer_output(awg['peers'], {'A': 'Телефон'})
        self.fake.answers['docker exec amnezia-wireguard '] = peer_output([('B', '10.8.2.2', '(none)', 0, 0, 0)], {})

        state, ctx = {}, make_ctx()
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        titles = {m['container']: m['title'] for m in st['modules']}
        self.assertEqual(titles['amnezia-awg'], 'AmneziaWG')
        self.assertEqual(titles['amnezia-wireguard'], 'WireGuard')
        self.assertEqual(titles['amnezia-xray'], 'Xray (VLESS Reality)')
        self.assertEqual(titles['amnezia_panel'], 'Панель PRVTPRO')
        self.assertNotIn('nginx-other', titles)
        self.assertEqual([m['ports'] for m in st['modules'] if m['container'] == 'amnezia-wireguard'][0], ['51821/udp'])
        self.assertEqual([s['title'] for s in st['services']], ['Фильтр RU (sing-box)'])
        names = {c['name']: c for c in st['clients']}
        self.assertTrue(names['Телефон']['online'])
        self.assertEqual(names['Телефон']['module'], 'AmneziaWG')
        self.assertIn('Клиент 10.8.2.2', names)
        self.assertFalse(names['Клиент 10.8.2.2']['online'])
        self.assertEqual(names['Телефон']['today_down'], 0)       # накопленное до установки — не «сегодня»
        self.assertEqual(names['Телефон']['total_down'], 5000)    # но во «всё время» попадает
        self.assertEqual(st['sessions'][0]['end'], None)  # идёт сейчас

        # +15 с: клиент скачал ещё 15000 байт
        self.clock.t += 15
        awg['peers'] = [('A', '10.8.1.1', '1.2.3.4', self.clock.t - 5, 2000, 20000)]
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        c = [x for x in st['clients'] if x['name'] == 'Телефон'][0]
        self.assertEqual(c['down_speed'], 1000)
        self.assertEqual(c['today_down'], 15000)
        self.assertEqual(c['week_down'], 15000)
        self.assertEqual(c['total_down'], 20000)

        # перезапуск контейнера: счётчики начались заново
        self.clock.t += 15
        awg['peers'] = [('A', '10.8.1.1', '1.2.3.4', self.clock.t - 5, 100, 700)]
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        c = [x for x in st['clients'] if x['name'] == 'Телефон'][0]
        self.assertEqual(c['total_down'], 20700)

        # клиент пропал на 10 минут: сессия закрывается и попадает в историю
        last_hs = self.clock.t - 5
        self.clock.t += 600
        awg['peers'] = [('A', '10.8.1.1', '1.2.3.4', last_hs, 100, 700)]
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        c = [x for x in st['clients'] if x['name'] == 'Телефон'][0]
        self.assertFalse(c['online'])
        closed = [s for s in st['sessions'] if s['end']]
        self.assertEqual(len(closed), 1)
        self.assertEqual(closed[0]['client'], 'Телефон')
        self.assertEqual(closed[0]['down'], 15700)  # за сессию: 20700 всего минус 5000, что было до первого замера
        self.assertEqual(closed[0]['ip'], '1.2.3.4')

        # снова подключился — новая сессия
        self.clock.t += 60
        awg['peers'] = [('A', '10.8.1.1', '5.6.7.8', self.clock.t - 2, 300, 900)]
        st = collector.collect({'ping_targets': ['1.1.1.1']}, state, ctx)
        self.assertEqual(st['sessions'][0]['end'], None)
        self.assertEqual(st['sessions'][0]['ip'], '5.6.7.8')
        self.assertEqual(len(st['daily']), 1)
        json.dumps(st)

    def test_protocol_version_from_config(self):
        collector.shutil.which = lambda name: '/usr/bin/' + name
        self.fake.answers['docker ps -a'] = ('amnezia-awg2\trunning\tUp\t\namnezia-awg\trunning\tUp\t\n'
                                             'amnezia-awg-2\trunning\tUp\t\namnezia-wireguard\trunning\tUp\t\n')
        head = '@@BIN awg amneziawg-tools v3.1.20260812 - https://amnezia.org\n'
        # контейнер называется awg2, но протокол уже 3.1
        self.fake.answers['docker exec amnezia-awg2 '] = (head + '@@CFG Jc = 5\n@@CFG S3 = 12\n@@CFG H1 = 1\n'
                                                          '@@CFG HeaderProtectionKey = x\n@@CFG RandomTrailers = on\n'
                                                          + peer_output([], {}))
        self.fake.answers['docker exec amnezia-awg '] = head + '@@CFG Jc = 4\n@@CFG H1 = 100-2000\n' + peer_output([], {})
        self.fake.answers['docker exec amnezia-awg-2 '] = head + '@@CFG Jc = 4\n@@CFG H1 = 1234567\n' + peer_output([], {})
        self.fake.answers['docker exec amnezia-wireguard '] = '@@BIN wg wireguard-tools v1.0.20210914\n' + peer_output([], {})
        st = collector.collect({'ping_targets': []}, {}, make_ctx())
        titles = {m['container']: m['title'] for m in st['modules']}
        self.assertEqual(titles['amnezia-awg2'], 'AmneziaWG 3.1')
        self.assertEqual(titles['amnezia-awg'], 'AmneziaWG 2.0')
        self.assertEqual(titles['amnezia-awg-2'], 'AmneziaWG 1.0 #2')
        self.assertEqual(titles['amnezia-wireguard'], 'WireGuard')

    def test_old_state_is_migrated(self):
        collector.shutil.which = lambda name: '/usr/bin/' + name
        self.fake.answers['docker ps -a'] = 'amnezia-awg2\trunning\tUp\t\n'
        self.fake.answers['docker exec'] = peer_output([('A', '10.8.1.1', '(none)', 0, 10, 10)], {})
        state = {'peers': {'A': {'rx': 5, 'tx': 5, 'total_rx': 500, 'total_tx': 500, 'days': {}}}}
        st = collector.collect({'ping_targets': []}, state, make_ctx())
        self.assertIn('amnezia-awg2:A', state['peers'])
        self.assertNotIn('A', state['peers'])
        self.assertEqual(st['clients'][0]['total_down'], 505)

    def test_rkn_shield_status_and_counter(self):
        collector.shutil.which = lambda name: None
        tool = os.path.join(self.tmp, 'rkn-shield')
        with open(tool, 'w') as f:
            f.write('#!/bin/sh\necho "\033[32mЗащита: $1\033[0m"\n')
        os.chmod(tool, 0o755)
        collector.RKN_TOOLS = [('rkn-shield', tool)]
        orig_read = collector.read_text
        collector.read_text = lambda p, d='': {'/etc/rkn-shield/state': 'on', '/etc/rkn-shield/config': 'BLOCK_OUT=no',
                                               '/var/lib/rkn-shield/last_update': '2026-11-05 00:21'}.get(p, orig_read(p, d))
        try:
            self.fake.answers['iptables-save'] = '-A PREROUTING -j RKN_SHIELD_IN\n'
            self.fake.answers['ipset list -t'] = ('Name: rkns_in4\nNumber of entries: 1151\nName: rkns_in6\n'
                                                  'Number of entries: 21\nName: rkns_out4\nNumber of entries: 204\n')
            counter = {'n': 7}
            self.fake.answers['iptables -w -t mangle -L RKN_SHIELD_IN'] = lambda: (
                'Chain RKN_SHIELD_IN\n pkts bytes target\n    0 0 RETURN all\n'
                f"    {counter['n']} 420 DROP all\n")
            self.fake.answers['systemctl list-timers rkn-shield-update.timer'] = '[{"next":1800086400123456}]'
            self.fake.answers['systemctl is-active rkn-shield-update.timer'] = 'active\n'
            state = {}
            st = collector.collect({'ping_targets': []}, state, make_ctx())
            r = st['rkn']
            self.assertTrue(r['enabled'])
            self.assertTrue(r['block_in'])
            self.assertFalse(r['block_out'])
            self.assertEqual(r['nets_in'], 1172)
            self.assertEqual(r['next_update'], 1800086400)
            self.assertEqual(r['blocked_total'], 7)
            counter['n'] = 2  # правила перестроены — счётчик с нуля
            st = collector.collect({'ping_targets': []}, state, make_ctx())
            self.assertEqual(st['rkn']['blocked_total'], 9)

            # просьба дашборда выключить защиту
            with open(collector.REQUEST_FILE, 'w') as f:
                json.dump({'action': 'rkn_off', 'id': 'abc123', 'ts': self.clock.t}, f)
            self.assertTrue(collector.handle_request())
            res = json.load(open(collector.RESULT_FILE))
            self.assertTrue(res['ok'])
            self.assertEqual(res['message'], 'Защита: off')
            self.assertFalse(os.path.exists(collector.REQUEST_FILE))
            # чужое действие не выполняется
            with open(collector.REQUEST_FILE, 'w') as f:
                json.dump({'action': 'rm -rf /', 'id': 'x1', 'ts': self.clock.t}, f)
            collector.handle_request()
            self.assertFalse(json.load(open(collector.RESULT_FILE))['ok'])
            # мусор в файле не роняет сборщик
            with open(collector.REQUEST_FILE, 'w') as f:
                f.write('not json')
            collector.handle_request()
        finally:
            collector.read_text = orig_read


class DashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        os.makedirs(os.path.join(cls.tmp, 'web'))
        dashboard.SETTINGS_FILE = os.path.join(cls.tmp, 'web', 'settings.json')
        dashboard.REQUEST_FILE = os.path.join(cls.tmp, 'web', 'request.json')
        dashboard.STATS_FILE = os.path.join(cls.tmp, 'stats.json')
        dashboard.RESULT_FILE = os.path.join(cls.tmp, 'action.json')
        dashboard.init_settings()
        with open(dashboard.STATS_FILE, 'w') as f:
            json.dump({'updated': 1, 'clients': [{'name': '<b>x</b>', 'online': True, 'last_handshake': time.time(),
                       'down_speed': 1, 'up_speed': 1, 'today_down': 1, 'today_up': 1, 'week_down': 1, 'week_up': 1,
                       'total_down': 1, 'total_up': 1}],
                       'sessions': [{'client': '<i>s1</i>', 'start': 1, 'end': 100, 'down': 5}, {'client': 's2', 'start': 1, 'end': None}],
                       'rkn': {'installed': True, 'enabled': False}, 'modules': [{'title': 'AWG', 'running': True}]}, f)
        srv = dashboard.ThreadingHTTPServer(('127.0.0.1', 0), dashboard.Handler)
        cls.port = srv.server_address[1]
        threading.Thread(target=srv.serve_forever, daemon=True).start()

    def opener(self):
        return urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def url(self, p):
        return f'http://127.0.0.1:{self.port}{p}'

    def post(self, op, path, data, fetch=True):
        req = urllib.request.Request(self.url(path), data=json.dumps(data).encode(),
                                     headers={'Content-Type': 'application/json', **({'X-Requested-With': 'fetch'} if fetch else {})})
        try:
            r = op.open(req)
            return r.status, json.load(r)
        except urllib.error.HTTPError as e:
            return e.code, json.load(e)

    def login(self, pw='admin'):
        op = self.opener()
        op.open(self.url('/login'), data=urllib.parse.urlencode({'username': 'admin', 'password': pw}).encode())
        return op

    def test_flow(self):
        op = self.opener()
        with self.assertRaises(urllib.error.HTTPError) as e:
            op.open(self.url('/api/stats'))
        self.assertEqual(e.exception.code, 401)
        r = self.login('wrong').open(self.url('/'))
        self.assertIn('/login', r.geturl())
        op = self.login()
        st = json.load(op.open(self.url('/api/stats')))
        self.assertTrue(st['default_password'])
        self.assertEqual(self.post(op, '/api/action', {'action': 'rkn_off'}, fetch=False)[0], 403)
        code, res = self.post(op, '/api/action', {'action': 'reboot'})
        self.assertEqual(code, 400)
        code, res = self.post(op, '/api/action', {'action': 'rkn_on'})
        self.assertEqual(code, 200)
        req = json.load(open(dashboard.REQUEST_FILE))
        self.assertEqual(req['action'], 'rkn_on')
        pend = json.load(op.open(self.url('/api/action?id=' + res['id'])))
        self.assertTrue(pend['pending'])
        code, res = self.post(op, '/api/telegram/test', {})
        self.assertEqual(code, 400)
        self.assertIn('токен', res['error'])
        code, _ = self.post(op, '/api/telegram', {'ids': '12, abc'})
        self.assertEqual(code, 400)

    def test_telegram_texts(self):
        st = json.load(open(dashboard.STATS_FILE))
        for fn in (dashboard.tg_summary, dashboard.tg_clients, dashboard.tg_history, dashboard.tg_protection, dashboard.tg_server):
            text = fn(st)
            self.assertNotIn('<b>x</b>', text)   # имена экранированы
            self.assertNotIn('<i>', text)
            fn({})                             # пустая статистика не роняет бота

    def test_protection_hidden_without_rkn(self):
        flat = lambda kb: [b['text'] for row in kb['keyboard'] for b in row]
        self.assertNotIn('🛡 Защита', flat(dashboard.keyboard({})))
        self.assertNotIn('🛡 Защита', flat(dashboard.keyboard({'rkn': {'installed': False}})))
        self.assertIn('🛡 Защита', flat(dashboard.keyboard({'rkn': {'installed': True}})))
        self.assertNotIn('РКН', dashboard.status_lines({'rkn': {'installed': False}, 'modules': [], 'services': []}))

    def test_resolve(self):
        self.assertEqual(dashboard.resolve('127.0.0.1'), '127.0.0.1')
        self.assertIsNone(dashboard.resolve('no-such-iface0'))


if __name__ == '__main__':
    unittest.main(verbosity=2)
