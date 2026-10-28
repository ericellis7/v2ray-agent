#!/usr/bin/env python3
# 使用隔离配置验证用户协议授权和实际订阅内容。
import itertools
import json
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile
import unittest
from urllib.parse import parse_qs, urlsplit

REPO = Path(__file__).resolve().parents[1]
SOURCE = (REPO / 'install.sh').read_text()
DEFINITIONS = {
    1: ('02_VLESS_TCP_inbounds.json', 0, 'VLESS_TCP/TLS_Vision'),
    2: ('07_VLESS_vision_reality_inbounds.json', 1, 'vless_reality_vision'),
    3: ('12_VLESS_XHTTP_inbounds.json', 0, 'VLESS_Reality_XHTTP'),
}
COMBINATIONS = [list(items) for count in (1, 2, 3)
                for items in itertools.combinations((1, 2, 3), count)]
OWNER = '00000000-0000-4000-8000-000000000001'
TARGET = '00000000-0000-4000-8000-000000000002'
OTHER = '00000000-0000-4000-8000-000000000003'


def extract_function(name):
    matches = list(re.finditer(r'^([A-Za-z_]\w*)\(\) \{$', SOURCE, re.MULTILINE))
    for index, match in enumerate(matches):
        if match.group(1) == name:
            boundary = matches[index + 1].start() if index + 1 < len(matches) else len(SOURCE)
            end = SOURCE.rfind('\n}', match.start(), boundary)
            return SOURCE[match.start():end + 2]
    raise AssertionError(f'Missing function: {name}')


FUNCTIONS = '\n\n'.join(extract_function(name) for name in (
    'restoreXrayUserConfigs', 'deleteXrayUserByUUID',
    'accountUserKey', 'accountUserMatches', 'collectAccountUsers',
    'selectAccountUser', 'customUUID', 'customUserEmail',
    'collectInstalledUserProtocols', 'collectProtocolUserIdentities',
    'readUserProtocols', 'selectUserProtocols', 'setUserProtocols',
    'refreshUserSubscriptions', 'addProtocolUsers',
    'manageUserProtocols', 'viewUserProtocols', 'addUser', 'removeUser',
    'defaultBase64Code', 'getRealitySubscriptionPort', 'showAccounts',
    'initXrayClients', 'initSingBoxClients',
))


class UserProtocolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='v2ray-agent-users-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.conf = self.root / 'conf'
        self.conf.mkdir()
        self.validator = self.root / 'xray'
        self.validator.write_text('#!/bin/bash\nexit "${TEST_CHECK_FAIL:-0}"\n')
        self.validator.chmod(0o755)
        self.helpers = self.root / 'functions.sh'
        self.helpers.write_text(FUNCTIONS)
        self.reset_configs()

    def reset_configs(self):
        for choice, (filename, index, suffix) in DEFINITIONS.items():
            client = {'id': OWNER, 'email': f'owner-{suffix}', 'level': 5}
            if choice != 3:
                client['flow'] = 'xtls-rprx-vision'
            inbound = {'protocol': 'vless', 'port': {1: 443, 2: 11921, 3: 15107}[choice],
                       'tag': f'node-{choice}', 'settings': {'clients': [client], 'decryption': 'none'},
                       'streamSettings': {'network': 'xhttp' if choice == 3 else 'tcp',
                                          'security': 'tls' if choice == 1 else 'reality'}}
            inbounds = [inbound]
            if index == 1:
                inbounds.insert(0, {'protocol': 'dokodemo-door', 'port': 11921,
                                   'settings': {'address': '127.0.0.1', 'port': 45987}})
            (self.conf / filename).write_text(json.dumps({'inbounds': inbounds, 'unchanged': choice}))
        self.original = self.snapshot()

    def snapshot(self):
        return {file.name: file.read_bytes() for file in self.conf.glob('*.json')}

    def run_shell(self, body, stdin='', env=None, expected=0):
        setup = f'''
source {shlex.quote(str(self.helpers))}
configPath={shlex.quote(str(self.conf) + '/')}
ctlPath={shlex.quote(str(self.validator))}
singBoxConfigPath="${{TEST_SINGBOX_CONFIG:-}}"
configPath="${{TEST_CONFIG_PATH:-$configPath}}"
coreInstallType="${{TEST_CORE_TYPE:-1}}"
currentInstallProtocolType=,0,7,12,
currentHost=node.example.test
currentDefaultPort=443
currentPath=test
currentCDNAddress=node.example.test
xrayVLESSRealityVisionPort=11921
xrayVLESSRealityXHTTPort=15107
xrayVLESSRealityServerName=target.example.test
xrayVLESSRealityXHTTPServerName=target.example.test
currentRealityPublicKey=test-key
currentRealityXHTTPPublicKey=test-key
currentRealityMldsa65Verify=
subscribePort=
reloadCount=0
echoContent() {{ printf '%b\\n' "$2"; }}
reloadCore() {{
    reloadCount=$((reloadCount + 1))
    if [[ "${{TEST_RELOAD_FAIL:-}}" == first && "${{reloadCount}}" == 1 ]]; then return 1; fi
    return 0
}}
readInstallType() {{ :; }}
readInstallProtocolType() {{ :; }}
readConfigHostPathUUID() {{ :; }}
readSingBoxConfig() {{ :; }}
readNginxSubscribe() {{ :; }}
manageAccount() {{ :; }}
getPublicIP() {{ printf '%s\\n' 192.0.2.10; }}
'''
        result = subprocess.run(['bash', '-o', 'pipefail', '-c', setup + '\n' + body],
                                input=stdin, text=True, capture_output=True,
                                env=dict(os.environ, **(env or {})), timeout=45)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result

    def apply(self, choices, user=TARGET, name='alice'):
        return self.run_shell(f'setUserProtocols {user} {shlex.quote(name)} {shlex.quote(json.dumps(choices))}')

    def assert_membership(self, user, choices):
        for choice, (filename, index, _) in DEFINITIONS.items():
            clients = json.loads((self.conf / filename).read_text())['inbounds'][index]['settings']['clients']
            found = [client for client in clients if client['id'] == user]
            self.assertEqual(len(found), int(choice in choices))
            for client in found:
                self.assertEqual(client.get('flow', ''), '' if choice == 3 else 'xtls-rprx-vision')

    def assert_owner_unchanged(self):
        for filename, before in self.original.items():
            original = json.loads(before)
            after = json.loads((self.conf / filename).read_text())
            for original_inbound, actual_inbound in zip(original['inbounds'], after['inbounds']):
                clients = actual_inbound.get('settings', {}).get('clients')
                if clients is not None:
                    actual_inbound['settings']['clients'] = [client for client in clients if client['id'] == OWNER]
            self.assertEqual(after, original)

    def subscription_protocols(self, user_key='alice'):
        output = self.root / 'subscriptions'
        if output.exists():
            for file in output.glob('*/*'):
                file.unlink()
        self.run_shell(f'showAccounts 1 {user_key} {shlex.quote(str(output))}')
        lines = (output / 'default' / user_key).read_text().splitlines()
        choices = []
        for line in lines:
            uri = urlsplit(line)
            args = parse_qs(uri.query)
            self.assertEqual(uri.username, TARGET)
            choice = 3 if args['type'] == ['xhttp'] else (1 if args['security'] == ['tls'] else 2)
            choices.append(choice)
        clash = (output / 'clashMeta' / user_key).read_text()
        self.assertEqual(clash.count('  - name:'), len(choices))
        self.assertNotIn(OWNER, clash)
        return sorted(choices)

    def test_all_seven_combinations_and_real_subscriptions(self):
        for choices in COMBINATIONS:
            with self.subTest(choices=choices):
                self.apply(choices)
                self.assert_membership(TARGET, choices)
                self.assert_owner_unchanged()
                self.assertEqual(self.subscription_protocols(), choices)

    def test_all_49_authorization_transitions(self):
        for before in COMBINATIONS:
            for after in COMBINATIONS:
                with self.subTest(before=before, after=after):
                    self.apply(before)
                    self.apply(after)
                    self.assert_membership(TARGET, after)
                    self.assert_owner_unchanged()

    def test_interleaved_users_do_not_regrant_protocols(self):
        self.apply([3])
        self.apply([1, 2], OTHER, 'bob')
        self.apply([2], TARGET)
        self.assert_membership(TARGET, [2])
        self.assert_membership(OTHER, [1, 2])
        self.assert_owner_unchanged()

    def test_add_menu_uses_selection_without_shared_clients(self):
        self.run_shell(f'addUser', f'1\n{TARGET}\nalice\n3\n')
        self.assert_membership(TARGET, [3])
        self.assert_owner_unchanged()
        self.run_shell(f'addUser', f'1\n{OTHER}\nbob\n1,2\n')
        self.assert_membership(TARGET, [3])
        self.assert_membership(OTHER, [1, 2])

    def test_batch_add_refreshes_each_committed_user_before_next_prompt(self):
        marker = self.root / 'refreshed'
        body = f'''
subscribePort=8443
subscribe() {{ printf '%s\\n' refreshed >> {shlex.quote(str(marker))}; }}
addUser
'''
        self.run_shell(body, f'2\n{TARGET}\nalice\n3\n{OTHER}\nbob\n4\n', expected=1)
        self.assert_membership(TARGET, [3])
        self.assert_membership(OTHER, [])
        self.assertEqual(marker.read_text().splitlines(), ['refreshed'])

    def test_change_menu_preserves_uuid_and_subscription_key(self):
        self.apply([3])
        self.run_shell('manageUserProtocols', '1\n1,2\n')
        self.assert_membership(TARGET, [1, 2])
        self.assertEqual(self.subscription_protocols(), [1, 2])

    def test_delete_xhttp_only_user_by_uuid(self):
        self.apply([3])
        self.run_shell('removeUser', '1\n')
        self.assert_membership(TARGET, [])
        self.assert_owner_unchanged()

    def test_user_collection_and_duplicate_checks_include_xhttp_only(self):
        self.apply([3])
        users = json.loads(self.run_shell('collectProtocolUserIdentities').stdout)
        self.assertIn({'id': TARGET, 'key': 'alice'},
                      [{key: user[key] for key in ('id', 'key')} for user in users])
        before = self.snapshot()
        self.assertIn('UUID不可重复', self.run_shell('customUUID', TARGET + '\n').stdout)
        self.assertIn('用户名不可重复', self.run_shell('customUserEmail', 'alice\n').stdout)
        self.assertEqual(before, self.snapshot())

    def test_invalid_and_uninstalled_choices_leave_configs_unchanged(self):
        before = self.snapshot()
        for selection in ('0', '4', '1,', '1;3', '1,,3'):
            with self.subTest(selection=selection):
                self.run_shell('selectUserProtocols', selection + '\n', expected=1)
                self.assertEqual(before, self.snapshot())
        (self.conf / DEFINITIONS[2][0]).unlink()
        self.run_shell('selectUserProtocols', '3\n', expected=1)

    def test_selection_defaults_and_duplicates(self):
        result = self.run_shell('selectUserProtocols >/dev/null; printf "%s" "$selectedUserProtocols"', '\n')
        self.assertEqual(json.loads(result.stdout), [1, 2, 3])
        result = self.run_shell('selectUserProtocols "[3]" >/dev/null; printf "%s" "$selectedUserProtocols"', '\n')
        self.assertEqual(json.loads(result.stdout), [3])
        result = self.run_shell('selectUserProtocols >/dev/null; printf "%s" "$selectedUserProtocols"', '3,1,3\n')
        self.assertEqual(json.loads(result.stdout), [1, 3])

    def test_config_check_failure_restores_exact_files(self):
        before = self.snapshot()
        self.run_shell(f"setUserProtocols {TARGET} alice '[1,3]'",
                       env={'TEST_CHECK_FAIL': '1'}, expected=1)
        self.assertEqual(before, self.snapshot())

    def test_reload_failure_restores_exact_files(self):
        before = self.snapshot()
        self.run_shell(f"setUserProtocols {TARGET} alice '[2,3]'",
                       env={'TEST_RELOAD_FAIL': 'first'}, expected=1)
        self.assertEqual(before, self.snapshot())

    def test_existing_selected_client_metadata_is_preserved(self):
        self.apply([3])
        path = self.conf / DEFINITIONS[3][0]
        data = json.loads(path.read_text())
        data['inbounds'][0]['settings']['clients'][-1]['level'] = 8
        path.write_text(json.dumps(data))
        self.apply([1, 3])
        data = json.loads(path.read_text())
        self.assertEqual(data['inbounds'][0]['settings']['clients'][-1]['level'], 8)

    def add_xray(self, filename, protocol='vless', network='ws', security='tls', empty=False):
        identity = 'password' if protocol == 'trojan' else 'id'
        client = {identity: OWNER, 'email': 'owner-' + filename.removesuffix('_inbounds.json')}
        if protocol == 'vless' and network == 'tcp':
            client['flow'] = 'xtls-rprx-vision'
        data = {'inbounds': [{'protocol': protocol, 'tag': filename, 'port': 12345,
                             'settings': {'clients': [] if empty else [client]},
                             'streamSettings': {'network': network, 'security': security}}]}
        (self.conf / filename).write_text(json.dumps(data))

    def catalog(self, env=None):
        return json.loads(self.run_shell('collectInstalledUserProtocols', env=env).stdout)

    def assert_catalog_membership(self, choices, env=None, user=TARGET):
        for entry in self.catalog(env):
            value = json.loads(Path(entry['file']).read_text())
            for component in entry['path']:
                value = value[component]
            clients = [client for client in value if client[entry['identity']] == user]
            self.assertEqual(len(clients), int(entry['choice'] in choices), entry)

    def singbox(self):
        base = self.root / 'sing-box'
        conf = base / 'conf' / 'config'
        conf.mkdir(parents=True)
        validator = base / 'sing-box'
        validator.write_text('#!/bin/bash\nexit "${TEST_SINGBOX_FAIL:-0}"\n')
        validator.chmod(0o755)
        return conf, {'TEST_SINGBOX_CONFIG': str(conf) + '/'}

    def add_singbox(self, conf, filename, protocol, empty=False, network=None):
        identity = 'uuid' if protocol in ('vless', 'vmess', 'tuic') else 'password'
        name = 'username' if protocol == 'naive' else 'name'
        client = {identity: OWNER, name: 'owner-' + protocol}
        if protocol == 'tuic':
            client['password'] = OWNER
        if protocol == 'vless' and network is None:
            client['flow'] = 'xtls-rprx-vision'
        inbound = {'type': protocol, 'users': [] if empty else [client],
                   'tls': {'enabled': True}, 'listen_port': 14443}
        if network is not None:
            inbound['transport'] = {'type': network}
        (conf / filename).write_text(json.dumps({'inbounds': [inbound]}))

    def test_catalog_follows_installed_files_and_renumbers(self):
        self.assertEqual(len(self.catalog()), 3)
        self.add_xray('03_VLESS_WS_inbounds.json')
        entries = self.catalog()
        self.assertEqual(len(entries), 4)
        ws = entries[1]
        self.assertEqual(Path(ws['file']).name, '03_VLESS_WS_inbounds.json')
        self.assertEqual(ws['choice'], 2)
        (self.conf / DEFINITIONS[2][0]).unlink()
        entries = self.catalog()
        self.assertEqual([entry['choice'] for entry in entries], [1, 2, 3])
        self.assertEqual(Path(entries[1]['file']).name, '03_VLESS_WS_inbounds.json')

    def test_more_than_nine_installed_protocols_can_be_combined(self):
        for number in range(15, 24):
            self.add_xray(f'{number}_VLESS_WS_inbounds.json')
        self.assertEqual(len(self.catalog()), 12)
        body = f'selectUserProtocols >/dev/null && setUserProtocols {TARGET} alice "$selectedUserProtocols"'
        self.run_shell(body, '1,10,12\n')
        self.assert_catalog_membership([1, 10, 12])

    def test_original_xray_families_use_correct_credentials(self):
        for filename, protocol, network, security in (
                ('03_VLESS_WS_inbounds.json', 'vless', 'ws', 'tls'),
                ('04_trojan_gRPC_inbounds.json', 'trojan', 'grpc', 'tls'),
                ('04_trojan_TCP_inbounds.json', 'trojan', 'tcp', 'tls'),
                ('05_VMess_WS_inbounds.json', 'vmess', 'ws', 'tls'),
                ('06_VLESS_gRPC_inbounds.json', 'vless', 'grpc', 'tls'),
                ('08_VLESS_vision_gRPC_inbounds.json', 'vless', 'grpc', 'reality'),
                ('11_VMess_HTTPUpgrade_inbounds.json', 'vmess', 'httpupgrade', 'tls'),
                ('14_VLESS_XHTTP_TLS_inbounds.json', 'vless', 'xhttp', 'tls')):
            self.add_xray(filename, protocol, network, security, empty=True)
        choices = [entry['choice'] for entry in self.catalog()]
        self.apply(choices)
        self.assert_catalog_membership(choices)
        for entry in self.catalog():
            value = json.loads(Path(entry['file']).read_text())
            for component in entry['path']:
                value = value[component]
            client = next(client for client in value if client[entry['identity']] == TARGET)
            if 'trojan' in entry['file']:
                self.assertEqual(client['password'], TARGET)
                self.assertNotIn('id', client)
            if 'VMess' in entry['file']:
                self.assertEqual(client['alterId'], 0)
            if 'gRPC' in entry['file'] or 'XHTTP' in entry['file']:
                self.assertNotIn('flow', client)

    def test_empty_tcp_vision_inbound_still_appears(self):
        for filename, index, _ in DEFINITIONS.values():
            path = self.conf / filename
            data = json.loads(path.read_text())
            data['inbounds'][index]['settings']['clients'] = []
            path.write_text(json.dumps(data))
        self.assertEqual(len(self.catalog()), 3)
        self.apply([1, 2, 3])
        self.assert_membership(TARGET, [1, 2, 3])

    def test_multiple_user_inbounds_in_one_file_are_independent(self):
        path = self.conf / DEFINITIONS[1][0]
        data = json.loads(path.read_text())
        data['inbounds'].append(dict(data['inbounds'][0], tag='second', port=10443))
        path.write_text(json.dumps(data))
        entries = self.catalog()
        self.assertEqual(len(entries), 4)
        self.apply([1, 3])
        self.assert_catalog_membership([1, 3])
        self.apply([2, 4])
        self.assert_catalog_membership([2, 4])

    def test_newly_installed_ws_generates_only_selected_subscription(self):
        self.add_xray('03_VLESS_WS_inbounds.json')
        self.apply([2])
        output = self.root / 'subscriptions'
        self.run_shell(f'currentInstallProtocolType=,0,1,7,12,; showAccounts 1 alice {shlex.quote(str(output))}')
        lines = (output / 'default' / 'alice').read_text().splitlines()
        self.assertEqual(len(lines), 1)
        uri = urlsplit(lines[0])
        self.assertEqual(uri.username, TARGET)
        self.assertEqual(parse_qs(uri.query)['type'], ['ws'])

    def test_mixed_xray_hysteria_tuic_can_share_arbitrary_subset(self):
        conf, env = self.singbox()
        self.add_singbox(conf, '06_hysteria2_inbounds.json', 'hysteria2')
        self.add_singbox(conf, '09_tuic_inbounds.json', 'tuic')
        entries = self.catalog(env)
        self.assertEqual(len(entries), 5)
        selected = [entry['choice'] for entry in entries
                    if entry['core'] == 'sing-box' or 'XHTTP' in entry['file']]
        self.run_shell(f'setUserProtocols {TARGET} alice {shlex.quote(json.dumps(selected))}', env=env)
        self.assert_catalog_membership(selected, env)
        users = json.loads(self.run_shell('collectProtocolUserIdentities', env=env).stdout)
        self.assertIn({'id': TARGET, 'key': 'alice'},
                      [{key: user[key] for key in ('id', 'key')} for user in users])
        tuic = json.loads((conf / '09_tuic_inbounds.json').read_text())['inbounds'][0]['users'][-1]
        self.assertEqual(tuic['uuid'], TARGET)
        self.assertEqual(tuic['password'], TARGET)
        self.run_shell('removeUser', '1\n', env=env)
        self.assert_catalog_membership([], env)
        self.assert_owner_unchanged()

    def test_singbox_only_catalog_deduplicates_and_handles_all_user_schemas(self):
        conf, env = self.singbox()
        for index, protocol in enumerate(('vless', 'vmess', 'trojan', 'hysteria2', 'tuic', 'naive', 'anytls'), 1):
            self.add_singbox(conf, f'{index:02d}_{protocol}_inbounds.json', protocol, empty=True)
        env.update(TEST_CONFIG_PATH=str(conf) + '/', TEST_CORE_TYPE='2')
        entries = self.catalog(env)
        self.assertEqual(len(entries), 7)
        self.run_shell(f'addUser', f'1\n{TARGET}\nalice\n2,3,4,5,6,7\n', env=env)
        self.assert_catalog_membership([2, 3, 4, 5, 6, 7], env)
        naive = json.loads((conf / '06_naive_inbounds.json').read_text())['inbounds'][0]['users'][-1]
        self.assertEqual(naive['username'], 'alice-naive')
        self.assertEqual(naive['password'], TARGET)
        self.run_shell('manageUserProtocols', '1\n1\n', env=env)
        self.assert_catalog_membership([1], env)
        self.run_shell('removeUser', '1\n', env=env)
        self.assert_catalog_membership([], env)

    def test_singbox_check_failure_restores_both_cores(self):
        conf, env = self.singbox()
        self.add_singbox(conf, '06_hysteria2_inbounds.json', 'hysteria2')
        before = {path: path.read_bytes() for path in [*self.conf.glob('*.json'), *conf.glob('*.json')]}
        env['TEST_SINGBOX_FAIL'] = '1'
        self.run_shell(f"setUserProtocols {TARGET} alice '[1,4]'", env=env, expected=1)
        self.assertEqual(before, {path: path.read_bytes() for path in before})

    def test_user_protocol_overview_shows_each_users_actual_subset(self):
        self.apply([3])
        self.apply([1, 2], OTHER, 'bob')
        before = self.snapshot()
        result = self.run_shell('reloadCore() { return 71; }; subscribe() { return 72; }; viewUserProtocols')
        sections = {section.split('\n')[0]: section.split('\n')[1]
                    for section in result.stdout.split('用户：')[1:]}
        self.assertEqual(sections['alice'], '已授权：3.VLESS XHTTP [xray]')
        self.assertEqual(sections['bob'], '已授权：1.VLESS TCP [xray]、2.VLESS vision reality [xray]')
        self.assertEqual(before, self.snapshot())

    def test_user_protocol_overview_reflects_changed_authorizations(self):
        self.apply([3])
        self.apply([2])
        result = self.run_shell('viewUserProtocols')
        alice = result.stdout.split('用户：alice\n')[1].split('\n\n')[0]
        self.assertEqual(alice, '已授权：2.VLESS vision reality [xray]')

    def test_user_protocol_overview_includes_cross_core_combinations(self):
        conf, env = self.singbox()
        self.add_singbox(conf, '06_hysteria2_inbounds.json', 'hysteria2')
        self.run_shell(f"setUserProtocols {TARGET} alice '[3,4]'", env=env)
        result = self.run_shell('viewUserProtocols', env=env)
        alice = result.stdout.split('用户：alice\n')[1].split('\n\n')[0]
        self.assertEqual(alice, '已授权：3.VLESS XHTTP [xray]、4.hysteria2 [sing-box]')

    def test_custom_username_is_preserved_in_config_views_and_subscription(self):
        for name in ('alice-phone', '张三', 'alice-phone-2'):
            with self.subTest(name=name):
                self.reset_configs()
                self.run_shell('addUser', f'1\n{TARGET}\n{name}\n3\n')
                users = json.loads(self.run_shell('collectProtocolUserIdentities').stdout)
                self.assertEqual(next(user['key'] for user in users if user['id'] == TARGET), name)
                accounts = json.loads(self.run_shell('collectAccountUsers').stdout)
                self.assertIn(name, [user['key'] for user in accounts])
                self.assertEqual(self.subscription_protocols(name), [3])
                self.assertIn(f'用户：{name}\n', self.run_shell('viewUserProtocols').stdout)

    def test_empty_username_keeps_original_uuid_prefix(self):
        self.run_shell('addUser', f'1\n{TARGET}\n\n3\n')
        expected_name = TARGET.split('-')[0]
        users = json.loads(self.run_shell('collectProtocolUserIdentities').stdout)
        self.assertEqual(next(user['key'] for user in users if user['id'] == TARGET), expected_name)
        self.assertEqual(self.subscription_protocols(expected_name), [3])

    def test_manually_entered_uuid_name_is_not_abbreviated(self):
        self.run_shell('addUser', f'1\n{TARGET}\n{TARGET}\n3\n')
        users = json.loads(self.run_shell('collectProtocolUserIdentities').stdout)
        self.assertEqual(next(user['key'] for user in users if user['id'] == TARGET), TARGET)
        self.assertEqual(self.subscription_protocols(TARGET), [3])

    def test_users_with_same_name_prefix_are_independent(self):
        self.run_shell('addUser', f'1\n{TARGET}\nalice-phone\n3\n')
        self.run_shell('addUser', f'1\n{OTHER}\nalice-tablet\n1,2\n')
        users = json.loads(self.run_shell('collectProtocolUserIdentities').stdout)
        self.assertEqual({user['key'] for user in users}, {'owner', 'alice-phone', 'alice-tablet'})
        self.assertIn('用户名不可重复', self.run_shell('customUserEmail', 'alice-phone\n').stdout)
        self.assert_membership(TARGET, [3])
        self.assert_membership(OTHER, [1, 2])
        self.assertEqual(self.subscription_protocols('alice-phone'), [3])

    def test_protocol_changes_keep_complete_custom_username(self):
        self.run_shell('addUser', f'1\n{TARGET}\nalice-phone\n3\n')
        self.run_shell('manageUserProtocols', '1\n1,2\n')
        self.assertEqual(self.subscription_protocols('alice-phone'), [1, 2])
        self.run_shell('removeUser', '1\n')
        self.assert_membership(TARGET, [])
        self.assert_owner_unchanged()

    def test_protocol_suffix_does_not_absorb_first_users_name(self):
        self.run_shell('addUser', f'1\n{TARGET}\nalice-phone\n3\n')
        self.run_shell(f"setUserProtocols {OWNER} owner '[]'")
        self.run_shell('addUser', f'1\n{OTHER}\nbob-tablet\n3\n')
        data = json.loads((self.conf / DEFINITIONS[3][0]).read_text())
        email = next(client['email'] for client in data['inbounds'][0]['settings']['clients'] if client['id'] == OTHER)
        self.assertEqual(email, 'bob-tablet-VLESS_Reality_XHTTP')

    def test_initializers_keep_full_custom_name_and_legacy_prefix(self):
        for core, function in (('xray', 'initXrayClients'), ('sing-box', 'initSingBoxClients')):
            with self.subTest(core=core):
                identity = 'id' if core == 'xray' else 'uuid'
                name_field = 'email' if core == 'xray' else 'name'
                clients = [{identity: TARGET, name_field: 'alice-phone-VLESS_TCP/TLS_Vision'},
                           {identity: OWNER, name_field: 'a1b2c3d4-VLESS_TCP/TLS_Vision'}]
                result = self.run_shell(f'currentClients={shlex.quote(json.dumps(clients))}; {function} 0')
                actual = json.loads(result.stdout)
                self.assertEqual([client[name_field] for client in actual],
                                 ['alice-phone-VLESS_TCP/TLS_Vision', 'a1b2c3d4-VLESS_TCP/TLS_Vision'])

    def test_script_keeps_installer_entrypoint(self):
        self.assertEqual(SOURCE.rstrip().splitlines()[-1], 'menu')
        result = subprocess.run(['bash', '-n', str(REPO / 'install.sh')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == '__main__':
    unittest.main(verbosity=2)
