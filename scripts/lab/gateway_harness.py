"""Operator-pinned lexer checks; never collect tests from the submitted release."""

import contextlib
import io
import json
from pathlib import Path
import sys
import types
import unittest


def run(source):
    sys.path.insert(0, str(source / 'src'))
    for name, relative in [('malpdf', 'malpdf'), ('malpdf.static', 'malpdf/static'), ('malpdf.extraction', 'malpdf/extraction')]:
        package = types.ModuleType(name)
        package.__path__ = [str(source / 'src' / relative)]
        sys.modules[name] = package
    from malpdf.extraction.raw_syntax import Lexer, SyntaxBudget, SyntaxIssue, parse_value

    def value(data, *, depth=16, nodes=64):
        return parse_value(Lexer(data, SyntaxBudget(128, nodes, depth, 1024)))

    class PinnedLexerTests(unittest.TestCase):
        def test_integer(self):
            self.assertEqual(value(b'42').value, 42)

        def test_reference(self):
            node = value(b'8 2 R')
            self.assertEqual((node.kind, node.value), ('reference', (8, 2)))

        def test_name(self):
            self.assertEqual(value(b'/Safe#20Name').value, b'/Safe Name')

        def test_literal(self):
            self.assertEqual(value(b'(safe\\040text)').value, b'safe text')

        def test_boolean(self):
            self.assertIs(value(b'true').value, True)

        def test_depth_limit(self):
            with self.assertRaises(SyntaxIssue):
                value(b'[[[[1]]]]', depth=1)

    suite = unittest.defaultTestLoader.loadTestsFromTestCase(PinnedLexerTests)
    with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
        outcome = unittest.TextTestRunner(stream=io.StringIO()).run(suite)
    failures = len(outcome.failures) + len(outcome.errors)
    if outcome.testsRun != 6 or outcome.skipped:
        raise ValueError('worker_failed')
    return {'passed': 6 - failures, 'failed': failures}


if __name__ == '__main__':
    result = run(Path(sys.argv[1]))
    print(json.dumps(result, sort_keys=True))
    raise SystemExit(1 if result['failed'] else 0)
