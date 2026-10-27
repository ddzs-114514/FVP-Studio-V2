"""Public release-boundary tests using synthetic data only."""
# SPDX-License-Identifier: GPL-3.0-or-later
import hashlib
import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from fvp_studio import gui_actor_nod as nod
from fvp_studio import gui_audio_checkpoint as checkpoint
from fvp_studio import prepare_local
from fvp_studio.gui_runtime import GuiRuntimeError


class UpdateTests(unittest.TestCase):
    def test_nod_defaults_keep_legacy_distinct(self):
        self.assertEqual(nod.contract()['default'], dict(amp=75, unit='script',
            timing='original', duration_ms=450, curve=3))
        self.assertFalse(nod.contract()['default_is_each_target_original_preset_verified'])

    def test_checkpoint_is_absent_and_explicit_requests_refused(self):
        self.assertFalse(checkpoint.enabled({}))
        self.assertEqual(checkpoint.bridge_options(False), {})
        c = checkpoint.contract()
        for field in ('supported', 'implementation_distributed', 'production_export_enabled', 'runtime_verified'):
            self.assertIs(c[field], False)
        with self.assertRaises(GuiRuntimeError):
            checkpoint.enabled({checkpoint.REQUEST_FIELD: True})
        with self.assertRaises(GuiRuntimeError):
            checkpoint.enabled({checkpoint.REQUEST_FIELD: 1})
        with self.assertRaises(GuiRuntimeError):
            checkpoint.bridge_options(True)
        for name in ('native_audio_checkpoint', 'native_audio_checkpoint_bridge',
                     'native_audio_checkpoint_binding', 'native_audio_save_runtime', 'native_audio_save_binding'):
            self.assertIsNone(importlib.util.find_spec('fvp_studio.' + name))

    def test_signature_collection_ignores_line_movement_not_identity(self):
        value = b'synthetic-private-signature'
        keys = ['toy:1:0', 'toy:2:0']
        approved = {key: hashlib.sha256(value).hexdigest() for key in keys}
        with tempfile.TemporaryDirectory(prefix='fvp-pattern-update-') as directory:
            root = Path(directory)
            path = root / 'toy.py'
            path.write_text('\n\n\nVALUE = ' + repr(value) + '\n', encoding='utf-8')
            with patch.object(prepare_local, 'APPROVED', approved), patch.object(prepare_local, 'ACTIVE', keys), \
                    patch('fvp_studio.engine_patterns.APPROVED', approved):
                result = prepare_local.collect_patterns(root)
                self.assertEqual(set(result['patterns']), set(keys))
                path.write_text('VALUE = b"changed"\n', encoding='utf-8')
                with self.assertRaises(ValueError):
                    prepare_local.collect_patterns(root)


if __name__ == '__main__':
    unittest.main()
