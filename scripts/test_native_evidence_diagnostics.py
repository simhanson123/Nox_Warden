"""A known loader warning must never turn a panic/extra error into expected refusal."""
import unittest

from smoke_native_evidence import collector_diagnostic


class CollectorDiagnosticTests(unittest.TestCase):
    warning = "/lab/fw_linux_executor: /lib/x86_64-linux-gnu/libc.so.6: weak version `GLIBC_2.39' not found (required by /lab/fw_linux_executor)\n"
    refusal = 'OBSERVER_KEY_REJECTED\n'

    def test_known_leading_loader_warning_is_separate_from_exact_diagnostic(self):
        self.assertEqual(collector_diagnostic(self.refusal), (self.refusal, False))
        self.assertEqual(collector_diagnostic(self.warning + self.refusal), (self.refusal, True))

    def test_missing_refusal_panics_and_repeated_warnings_cannot_look_like_refusal(self):
        for stderr in [self.warning, self.warning * 2 + self.refusal,
                       self.warning + self.refusal + 'thread main panicked at DO_NOT_PRINT\n',
                       self.warning + 'thread main panicked at DO_NOT_PRINT\n',
                       self.refusal + self.warning]:
            self.assertNotEqual(collector_diagnostic(stderr)[0], self.refusal)

    def test_unknown_versions_binaries_and_libraries_are_never_filtered(self):
        for warning in [self.warning.replace('2.39', '2.40'),
                        self.warning.replace('fw_linux_executor', 'another_binary'),
                        self.warning.replace('libc.so.6', 'libcrypto.so.3'),
                        self.warning.rstrip('\n'), 'arbitrary warning\n']:
            self.assertEqual(collector_diagnostic(warning + self.refusal), (warning + self.refusal, False))


if __name__ == '__main__':
    unittest.main()
