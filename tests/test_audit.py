import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('audit', ROOT / 'audit.py')
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def baseline():
    return dict(schema_version=1, processes=[], tasks=[], startup=[], defender={},
                hosts=[], acl_blocks=[], remote={}, health=[], errors=[])


class AuditTests(unittest.TestCase):
    def rules(self, snapshot):
        return [f['rule'] for f in audit.analyze(snapshot)['findings']]

    def test_combined_miner_flags(self):
        s = baseline()
        s['processes'] = [dict(pid=10, path=r'C:\ProgramData\WindowsTask\MicrosoftHost.exe',
                               command='miner -o pool.example:443 --cpu-max-threads-hint=35 --cc-access-token=secret', signature='NotSigned')]
        report = audit.analyze(s)
        self.assertEqual(report['status'], 'attention')
        self.assertEqual(set(self.rules(s)), {'miner-command', 'process-masquerade'})
        self.assertNotIn('=secret', json.dumps(report))

    def test_unsigned_alone_and_real_steam_are_not_malware(self):
        s = baseline()
        s['processes'] = [dict(path=r'C:\Program Files\Steam\steamwebhelper.exe', signature='Valid'),
                          dict(path=r'C:\Users\Example\AppData\Local\Bridge\bridge.exe', signature='NotSigned')]
        self.assertEqual(self.rules(s), [])
        self.assertFalse(audit.miner_command('program -o output.txt'))

    def test_disabled_and_quarantined_references_are_inactive(self):
        s = baseline()
        s['tasks'] = [dict(name='old', enabled=False, command=r'C:\ProgramData\ReaItekHD\taskhost.exe')]
        result = audit.analyze(s)
        self.assertEqual(result['status'], 'no_rule_matches')
        self.assertFalse(result['findings'][0]['active'])

    def test_running_miner_cannot_hide_in_a_folder_named_quarantine(self):
        s = baseline()
        s['processes'] = [dict(path=r'C:\ProgramData\Quarantine\miner.exe',
                               command='miner -o pool.example:443 --donate-level=1')]
        self.assertIn('miner-command', self.rules(s))

    def test_defender_policy_in_addition_to_effective_exclusions(self):
        s = baseline()
        s['defender'] = dict(paths=[r'D:\Tools\Vortex'], policy_paths=[r'C:\ProgramData'], extensions=['*.exe'])
        self.assertEqual(self.rules(s).count('defender-broad-exclusion'), 2)

    def test_hosts_comments_and_domain_boundaries(self):
        s = baseline()
        s['hosts'] = ['# 8.8.4.4 malwarebytes.com', '127.0.0.1 docker.internal',
                      '8.8.4.4 download.eset.com', '0.0.0.0 notmicrosoft.com',
                      '0.0.0.0 alpha.telemetry.microsoft.com']
        self.assertEqual(self.rules(s), ['security-hosts-redirect'])

    def test_remote_access_and_privacy_are_information(self):
        s = baseline()
        s['remote'] = dict(rdp_listening=True)
        s['defender'] = dict(cloud_reporting=0)
        self.assertEqual(audit.analyze(s)['status'], 'no_rule_matches')

    def test_incomplete_is_not_clean(self):
        s = baseline()
        del s['tasks']
        self.assertEqual(audit.analyze(s)['status'], 'incomplete')
        s = baseline()
        s['errors'] = ['Access denied']
        self.assertEqual(audit.analyze(s)['status'], 'incomplete')

    def test_bad_schema_rejected(self):
        for sample in ({}, {'schema_version': 2}, [], dict(baseline(), processes={}),
                       dict(baseline(), processes=['bad']), dict(baseline(), defender={'paths': 'bad'})):
            with self.assertRaises(ValueError):
                audit.analyze(sample)

    def test_partial_collector_checkpoints(self):
        data = b'noise\n' + json.dumps(baseline()).encode() + b'\n{"truncated":'
        self.assertEqual(audit.decode_collector(data)['schema_version'], 1)
        with self.assertRaises(RuntimeError):
            audit.decode_collector(b'no usable output')

    def test_html_is_escaped_and_offline(self):
        s = baseline()
        s['errors'] = ['<script>alert(1)</script>']
        report = audit.analyze(s)
        for lang in ('en', 'ru'):
            page = audit.render_html(report, lang)
            self.assertNotIn('<script>', page)
            self.assertIn('&lt;script&gt;', page)
            self.assertIn("default-src 'none'", page)
            self.assertNotIn('https://', page)

    def test_redaction(self):
        value = audit.redact(r'C:\Users\Example\Desktop --password abc --token=secret https://example.test/?token=secret')
        self.assertNotIn('Example', value)
        self.assertNotIn('secret', value)
        self.assertNotIn(' abc', value)
        value = audit.redact('miner -u wallet-secret -p password-secret stratum+tcp://user:pass@pool.example')
        self.assertNotIn('wallet-secret', value)
        self.assertNotIn('password-secret', value)
        self.assertNotIn('user:pass', value)

    def test_unavailable_signature_is_not_assumed_unsigned(self):
        s = baseline()
        s['processes'] = [dict(path=r'C:\ProgramData\Tool\audiodg.exe', signature='Unavailable')]
        self.assertNotIn('process-masquerade', self.rules(s))

    def test_cli_writes_both_reports_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            source = temp / 'snapshot.json'
            for expected, change in [(0, {}), (1, {'health': [{'drive': 'C:', 'free_gb': 0.1}]}),
                                     (2, {'errors': ['denied']})]:
                source.write_text(json.dumps(dict(baseline(), **change)), encoding='utf-8')
                output = temp / str(expected)
                self.assertEqual(audit.main(['--snapshot', str(source), '--output', str(output), '--lang', 'ru']), expected)
                self.assertEqual(len(list(output.glob('*.html'))), 1)
                self.assertEqual(len(list(output.glob('*.json'))), 1)


if __name__ == '__main__':
    unittest.main()
