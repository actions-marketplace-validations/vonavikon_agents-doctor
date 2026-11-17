"""Regression tests for the static UI assets (v2.1.1 bug class).

The v2.1.0 dashboard shipped with an empty finding-card overlay that
covered the whole page: component display rules (.card-overlay,
.panel) override the UA stylesheet's [hidden] rule, so elements
carrying the hidden attribute rendered anyway. The guard rule
[hidden]{display:none !important} in style.css is what prevents every
future occurrence; these tests pin it and sweep for display rules on
elements that start hidden.
"""
import re
import sys
import unittest
from pathlib import Path

UI = Path(__file__).resolve().parents[1] / 'skills' / 'agents-doctor' / 'scripts' / 'ui' / 'static'


class HiddenGuardTest(unittest.TestCase):
    def test_guard_rule_present(self):
        css = (UI / 'style.css').read_text(encoding='utf-8')
        self.assertRegex(
            css, r'\[hidden\]\s*\{\s*display\s*:\s*none\s*!important',
            'the [hidden]{display:none !important} guard rule must stay '
            'at the top of style.css — it is the v2.1.1 fix')

    def test_guard_before_any_component_rule(self):
        css = (UI / 'style.css').read_text(encoding='utf-8')
        guard = css.find('[hidden]')
        first_rule = re.search(r'\.[\w-]+\s*\{', css)
        self.assertIsNotNone(first_rule)
        self.assertLess(guard, first_rule.start(),
                        'the guard must come first so authors see it')


class HiddenElementsTest(unittest.TestCase):
    """Every element that starts hidden in HTML must have no static
    display rule that would defeat the attribute (belt and braces:
    the !important guard already wins, but a component that both
    starts hidden and sets display is a latent surprise)."""

    def test_hidden_marked_elements_have_no_static_display(self):
        html = (UI / 'index.html').read_text(encoding='utf-8')
        css = (UI / 'style.css').read_text(encoding='utf-8')
        hidden_ids = re.findall(r'id="([\w-]+)"[^>]*\bhidden\b', html)
        self.assertTrue(hidden_ids, 'expected elements to start hidden')
        offenders = []
        for el_id in hidden_ids:
            # a rule like `#id { ... display: X ... }` (not inside a
            # [hidden] selector) would fight the hidden attribute
            for m in re.finditer(r'(#%s)\s*\{([^}]*)\}' % el_id, css):
                body = m.group(2)
                if 'display' in body and '[hidden]' not in m.group(0):
                    offenders.append((el_id, body.strip()[:60]))
        self.assertEqual(offenders, [],
                         'elements that start hidden must not set '
                         'display outside the [hidden] guard: %r' % offenders)


if __name__ == '__main__':
    unittest.main()
