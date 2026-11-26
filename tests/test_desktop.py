import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
    import gui
    import desktop_ui
except ImportError:
    gui=None


@unittest.skipIf(gui is None,'Tkinter not installed on this test host')
class DesktopTests(unittest.TestCase):
    def test_rounded_corner_mask_has_fractional_coverage(self):
        mask = desktop_ui.corner_coverage(14)
        self.assertEqual(mask[0][0], 0)
        self.assertEqual(mask[-1][-1], 255)
        self.assertTrue(any(0 < alpha < 255 for row in mask for alpha in row))

    def test_both_languages_have_the_same_complete_key_set(self):
        self.assertEqual(set(gui.WORDS['ru']),set(gui.WORDS['en']))
        self.assertTrue(all(gui.WORDS[language].values() for language in ('ru','en')))

    def test_settings_roundtrip_and_bad_input(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'settings.json'
            self.assertEqual(desktop_ui.read_settings(path),{})
            desktop_ui.write_settings(path,dict(language='ru',theme='light'))
            self.assertEqual(desktop_ui.read_settings(path),dict(language='ru',theme='light'))
            path.write_text('invalid',encoding='utf-8')
            self.assertEqual(desktop_ui.read_settings(path),{})
            path.write_text(json.dumps(['not a mapping']),encoding='utf-8')
            self.assertEqual(desktop_ui.read_settings(path),{})

    def test_palette_contrast_modes(self):
        self.assertNotEqual(desktop_ui.PALETTES['dark']['bg'],desktop_ui.PALETTES['light']['bg'])
        for palette in desktop_ui.PALETTES.values():
            self.assertNotEqual(palette['text'],palette['bg'])

    def test_report_button_uses_browser_not_file_association(self):
        import browser_open
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'тест report.html';path.write_text('<html>Test</html>',encoding='utf-8')
            if sys.platform=='win32':
                with patch.object(browser_open,'browser_command',return_value=['browser.exe',path.as_uri()]),patch.object(browser_open.subprocess,'Popen') as popen:
                    browser_open.open_local_html(path)
                    self.assertEqual(popen.call_args.args[0],['browser.exe',path.as_uri()])
                    self.assertNotIn('shell',popen.call_args.kwargs)

    def test_last_saved_report_is_loaded_on_start(self):
        with tempfile.TemporaryDirectory() as folder:
            app=object.__new__(gui.AuditApp);app.storage=Path(folder)
            reports=app.storage/'reports';reports.mkdir()
            report=dict(status='attention',findings=[],coverage={'processes':True},duration_seconds=2.5)
            path=reports/'audit-20260101.json';path.write_text(json.dumps(report),encoding='utf-8')
            app.load_latest()
            self.assertEqual(app.report,report)
            self.assertEqual(app.report_path,path.with_suffix('.html'))


if __name__=='__main__':unittest.main()
