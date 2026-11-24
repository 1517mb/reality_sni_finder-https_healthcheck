"""Offline integration checks for deployment and launcher behavior."""

from pathlib import Path
import os
import shutil
import subprocess
import tarfile
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
PROJECT_FILES = (
    '.gitattributes', '.gitignore', 'LICENSE', 'README.md', 'README.ru.md',
    'reality_sni_finder.py', 'https_healthcheck.py', 'install.sh', 'run.sh', 'deploy.sh',
    'tests/test_shell_scripts.py',
)


def find_bash():
    if os.environ.get('BASH_BIN'):
        return os.environ['BASH_BIN']
    if os.name == 'nt':
        git_bash = Path(os.environ.get('ProgramFiles', 'C:/Program Files')) / 'Git/bin/bash.exe'
        if git_bash.is_file():
            return str(git_bash)
    return shutil.which('bash')


BASH = find_bash()
LOG_CALL = """
printf 'BEGIN\\0%s\\0' "${0##*/}" >> "$TEST_LOG"
printf '%s\\0' "$@" >> "$TEST_LOG"
printf 'END\\0' >> "$TEST_LOG"
"""


@unittest.skipUnless(BASH, 'Bash is required (Git Bash is supported on Windows)')
class ShellScriptsTest(unittest.TestCase):
    def shell_path(self, path):
        if os.name != 'nt':
            return str(path)
        return subprocess.check_output(
            [BASH, '-c', 'cygpath -u "$1"', 'test-path', str(path)], text=True,
        ).strip()

    def stub(self, name, body):
        target = self.bin / name
        target.write_text('#!/usr/bin/env bash\nset -eu\n' + body, encoding='utf-8', newline='\n')
        target.chmod(0o755)

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='reality-shell-test-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name).resolve()
        self.project = self.base / 'project with spaces'
        self.project.mkdir()
        for name in PROJECT_FILES:
            (self.project / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(ROOT / name, self.project / name)
        self.bin = self.base / 'bin'
        self.bin.mkdir()
        self.log = self.base / 'calls'
        self.archive = self.base / 'upload.tar.gz'
        self.remote = self.base / 'remote'
        self.remote.mkdir()
        self.env = os.environ.copy()
        self.env.pop('BASH_ENV', None)
        for key in list(self.env):
            if key.startswith(('TEST_', 'RSF_')):
                self.env.pop(key)
        self.env.update({
            'PYTHON_BIN': 'test-python',
            'RSF_LANG': 'en',
            'TEST_LOG': self.shell_path(self.log),
            'TEST_ARCHIVE': self.shell_path(self.archive),
            'TEST_REMOTE_ROOT': self.shell_path(self.remote),
        })
        self.stub('test-python', """
if [[ "${1:-}" == -c ]]; then
    case "$2" in
        *sys.version_info*) exit "${TEST_PYTHON_VERSION_EXIT:-0}" ;;
        *HAS_TLSv1_3*) exit "${TEST_PYTHON_TLS_EXIT:-0}" ;;
        *) exit 0 ;;
    esac
fi
if [[ "${1:-}" == --version ]]; then printf 'Python 3.11.0 (test)\\n'; exit 0; fi
""" + LOG_CALL + '\nexit "${TEST_SCRIPT_EXIT:-0}"\n')
        self.stub('sudo', LOG_CALL + '\n[[ "${1:-}" != -- ]] || shift\nexec "$@"\n')
        self.stub('apt-get', LOG_CALL)
        self.stub('uname', "printf 'Linux\\n'\n")
        self.stub('curl', "printf 'Features: %s\\n' \"${TEST_CURL_FEATURES-HTTP2 SSL}\"\n")
        self.stub('masscan', 'exit 0\n')
        self.stub('openssl', 'exit 0\n')
        self.stub('ssh', LOG_CALL + """
if [[ "${1:-}" == -t ]]; then exit "${TEST_SSH_INSTALL_EXIT:-0}"; fi
cat > "$TEST_ARCHIVE"
if [[ "${TEST_SSH_UNPACK:-0}" == 1 ]]; then
    cd "$TEST_REMOTE_ROOT"
    bash -c "${@: -1}" < "$TEST_ARCHIVE"
fi
exit "${TEST_SSH_TRANSFER_EXIT:-0}"
""")

    def run_script(self, script='run.sh', *args, input_text='', env=None):
        environment = self.env.copy()
        environment.update(env or {})
        result = subprocess.run(
            [BASH, '-c', 'export PATH="$1:$PATH"; shift; exec bash "$@"',
             'shell-test', self.shell_path(self.bin), self.shell_path(self.project / script), *args],
            cwd=self.base, env=environment, input=input_text.encode('utf-8'),
            capture_output=True, timeout=20,
        )
        return subprocess.CompletedProcess(
            result.args, result.returncode, result.stdout.decode('utf-8', errors='replace'),
            result.stderr.decode('utf-8', errors='replace'),
        )

    def calls(self, name=None):
        if not self.log.exists():
            return []
        fields = self.log.read_bytes().decode('utf-8').split('\0')
        records = []
        while fields and fields[0]:
            self.assertEqual(fields.pop(0), 'BEGIN')
            end = fields.index('END')
            record, fields = fields[:end], fields[end + 1:]
            if name is None or record[0] == name:
                records.append(record)
        return records

    def test_bash_syntax_and_help(self):
        for name in ('run.sh', 'install.sh', 'deploy.sh'):
            with self.subTest(name=name):
                result = subprocess.run([BASH, '-n', self.shell_path(self.project / name)], capture_output=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                result = self.run_script(name, '--help')
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('Usage:', result.stdout)
        self.assertEqual(self.calls(), [])

    def test_check_detects_python_tls_and_http2_failures(self):
        self.assertEqual(self.run_script('run.sh', 'check').returncode, 0)
        for environment, message in (
            ({'TEST_PYTHON_VERSION_EXIT': '1'}, 'Python 3.11+ required'),
            ({'TEST_PYTHON_TLS_EXIT': '1'}, 'TLS 1.3'),
            ({'TEST_CURL_FEATURES': 'SSL'}, 'HTTP/2'),
        ):
            with self.subTest(environment=environment):
                result = self.run_script('run.sh', 'check', env=environment)
                self.assertEqual(result.returncode, 1)
                self.assertIn(message, result.stderr)

    def test_healthcheck_preserves_arguments_and_exit_code_without_sudo(self):
        result = self.run_script(
            'run.sh', 'healthcheck', '--authorized', '--output', 'report with spaces.json',
            'my-domain.example', env={'TEST_SCRIPT_EXIT': '3'},
        )
        self.assertEqual(result.returncode, 3, result.stderr)
        self.assertEqual(self.calls('sudo'), [])
        self.assertEqual(self.calls('test-python')[0][2:], [
            '--authorized', '--output', 'report with spaces.json', 'my-domain.example',
        ])

    def test_finder_sets_default_output_and_preserves_custom_output(self):
        result = self.run_script('run.sh', 'finder', '--blocks', '0', '--output', 'custom list.txt')
        self.assertEqual(result.returncode, 0, result.stderr)
        call = self.calls('test-python')[0]
        self.assertEqual(call[2:4], ['--output', self.shell_path(self.project / 'results/domains.txt')])
        self.assertEqual(call[4:], ['--blocks', '0', '--output', 'custom list.txt'])
        uid = subprocess.check_output([BASH, '-c', 'printf "%s" "$EUID"'], text=True).strip()
        self.assertEqual(bool(self.calls('sudo')), uid != '0')

    def test_python_help_avoids_sudo_and_output_directory(self):
        result = self.run_script('run.sh', 'finder', '--help')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls('sudo'), [])
        self.assertEqual(self.calls('test-python')[0][2:], ['--help'])
        self.assertFalse((self.project / 'results').exists())

    def test_menu_language_switch_and_windows_line_endings(self):
        result = self.run_script(input_text='4\r\n0\r\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('SNI FINDER + HTTPS HEALTHCHECK', result.stdout)
        self.assertIn('Find SNI candidates', result.stdout)
        self.assertIn('Найти SNI-кандидатов', result.stdout)
        self.assertNotIn('Unknown menu item', result.stdout)
        self.assertEqual(self.calls(), [])

    def test_declining_authorization_does_not_run_healthcheck(self):
        result = self.run_script(input_text='2\nmy-domain.example\ny\n8\nn\n\n0\n')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(self.calls('test-python'), [])
        self.assertFalse((self.project / 'results').exists())

    def test_menu_validates_timeout_and_returns_after_failed_healthcheck(self):
        result = self.run_script(
            input_text='2\nmy-domain.example\ny\n0\n31\n10\ny\n\n0\n',
            env={'TEST_SCRIPT_EXIT': '1'},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Enter an integer from 2 to 30.', result.stdout)
        self.assertIn('Command exited with code 1.', result.stdout)
        call = self.calls('test-python')[0]
        self.assertEqual(call[2:6], ['--authorized', '--http', '--timeout', '10'])
        report = call[call.index('--output') + 1]
        self.assertIn('/results/healthcheck-', report)
        self.assertTrue(report.endswith('.json'))
        self.assertEqual(call[-1], 'my-domain.example')

    def test_installer_checks_only_when_skip_deps_is_set(self):
        result = self.run_script('install.sh', '--skip-deps')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('Ready.', result.stdout)
        self.assertEqual(self.calls('apt-get'), [])
        self.assertEqual(self.calls('sudo'), [])

    def test_installer_uses_expected_packages_and_stops_on_check_failure(self):
        result = self.run_script('install.sh')
        self.assertEqual(result.returncode, 0, result.stderr)
        apt_calls = self.calls('apt-get')
        self.assertEqual(apt_calls[0][1:], ['update'])
        self.assertEqual(apt_calls[1][1:], [
            'install', '-y', 'python3', 'git', 'masscan', 'curl', 'openssl', 'ca-certificates',
        ])
        result = self.run_script('install.sh', '--skip-deps', env={'TEST_PYTHON_VERSION_EXIT': '1'})
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('Ready.', result.stdout)

    def test_deployment_archive_excludes_results_and_credentials_and_quotes_path(self):
        (self.project / '.env').write_text('NOT_FOR_UPLOAD=secret', encoding='utf-8')
        (self.project / 'results').mkdir()
        (self.project / 'results/old.json').write_text('{}', encoding='utf-8')
        destination = "folder with spaces'; touch INJECTED; #"
        result = self.run_script(
            'deploy.sh', '--dir', destination, '--skip-deps', 'user@example.invalid',
            env={'TEST_SSH_UNPACK': '1'},
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        with tarfile.open(self.archive) as archive:
            self.assertEqual(set(archive.getnames()), set(PROJECT_FILES))
        self.assertTrue((self.remote / destination / 'run.sh').is_file())
        self.assertFalse((self.remote / 'INJECTED').exists())
        calls = self.calls('ssh')
        self.assertEqual(len(calls), 2)
        self.assertEqual(calls[0][1:3], ['--', 'user@example.invalid'])
        self.assertEqual(calls[1][1:4], ['-t', '--', 'user@example.invalid'])
        self.assertTrue(calls[1][-1].endswith('bash install.sh --skip-deps'))

    def test_deployment_failure_stops_before_installation(self):
        result = self.run_script(
            'deploy.sh', 'user@example.invalid', env={'TEST_SSH_TRANSFER_EXIT': '7'},
        )
        self.assertEqual(result.returncode, 7, result.stderr)
        self.assertEqual(len(self.calls('ssh')), 1)
        self.assertNotIn('Deployment complete.', result.stdout)

    def test_invalid_shell_options_fail_before_running_commands(self):
        for script, args in (
            ('run.sh', ['unknown']), ('run.sh', ['check', 'extra']),
            ('install.sh', ['--unknown']), ('deploy.sh', []),
            ('deploy.sh', ['--dir']), ('deploy.sh', ['--unknown']),
            ('deploy.sh', ['one@host', 'two@host']),
        ):
            with self.subTest(script=script, args=args):
                result = self.run_script(script, *args)
                self.assertEqual(result.returncode, 2, result.stderr)
        self.assertEqual(self.calls(), [])


if __name__ == '__main__':
    unittest.main()
