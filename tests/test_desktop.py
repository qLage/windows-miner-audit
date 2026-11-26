import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
try:
    import gui
    import desktop_ui
except ImportError:
    gui=None


@unittest.skipIf(gui is None,'Tkinter not installed on this test host')
class DesktopTests(unittest.TestCase):
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


if __name__=='__main__':unittest.main()
