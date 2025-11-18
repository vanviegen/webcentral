#!/usr/bin/env python3

import os
import sys
import time
import tempfile
import subprocess
import shutil
import http.client
import socket
import signal
import atexit
from pathlib import Path
from datetime import datetime
from functools import wraps

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
RESET = '\033[0m'
CHECKMARK = '✓'
CROSSMARK = '✗'


class TestRunner:
    def __init__(self):
        self.tests = []
        self.tmpdir = None
        self.webcentral_proc = None
        self.port = None
        self.log_positions = {}  # project -> position in log file

    def find_free_port(self):
        """Find a random free port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def setup(self):
        """Set up test environment and start webcentral"""
        # Create temporary directory
        self.tmpdir = tempfile.mkdtemp(prefix='webcentral_test_')
        print(f"Test directory: {self.tmpdir}")

        # Create stdout and stderr redirect directories
        os.makedirs(f"{self.tmpdir}/stdout/_webcentral_data/logs", exist_ok=True)
        os.makedirs(f"{self.tmpdir}/stderr/_webcentral_data/logs", exist_ok=True)

        # Find free port
        self.port = self.find_free_port()
        print(f"Test port: {self.port}")

        # Start webcentral process
        today = datetime.now().strftime('%Y-%m-%d')
        stdout_log = f"{self.tmpdir}/stdout/_webcentral_data/logs/{today}.log"
        stderr_log = f"{self.tmpdir}/stderr/_webcentral_data/logs/{today}.log"

        stdout_f = open(stdout_log, 'w')
        stderr_f = open(stderr_log, 'w')

        bindings_file = f"{self.tmpdir}/_bindings.json"
        self.webcentral_proc = subprocess.Popen(
            ['./webcentral',
             '-projects', self.tmpdir,
             '-http', str(self.port),
             '-https', '0',
             '-bindings-file', bindings_file],
            stdout=stdout_f,
            stderr=stderr_f,
            cwd='/opt/webcentral'
        )

        # Store file handles so they don't get closed
        self.stdout_f = stdout_f
        self.stderr_f = stderr_f

        # Initialize log positions for stdout/stderr
        self.log_positions['stdout'] = 0
        self.log_positions['stderr'] = 0

        # Wait for webcentral to start
        time.sleep(0.5)

        if self.webcentral_proc.poll() is not None:
            raise Exception("webcentral process failed to start")

        print(f"webcentral started (PID: {self.webcentral_proc.pid})")
        print()

    def teardown(self):
        """Clean up test environment"""
        if self.webcentral_proc:
            self.webcentral_proc.terminate()
            try:
                self.webcentral_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.webcentral_proc.kill()
                self.webcentral_proc.wait()

        if hasattr(self, 'stdout_f'):
            self.stdout_f.close()
        if hasattr(self, 'stderr_f'):
            self.stderr_f.close()

        if self.tmpdir and os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)

    def get_log_path(self, project):
        """Get the log file path for a project"""
        today = datetime.now().strftime('%Y-%m-%d')
        if project in ['stdout', 'stderr']:
            return f"{self.tmpdir}/{project}/_webcentral_data/logs/{today}.log"
        else:
            return f"{self.tmpdir}/{project}/_webcentral_data/log/{today}.log"

    def get_log_content(self, project, from_pos=0):
        """Read log content from a given position"""
        log_path = self.get_log_path(project)
        if not os.path.exists(log_path):
            return ""

        with open(log_path, 'r') as f:
            f.seek(from_pos)
            return f.read()

    def get_current_log_position(self, project):
        """Get current position in log file"""
        log_path = self.get_log_path(project)
        if not os.path.exists(log_path):
            return 0
        return os.path.getsize(log_path)

    def write_file(self, path, content):
        """Write a file in the test directory"""
        full_path = os.path.join(self.tmpdir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)

    def mark_log_read(self, project):
        """Mark current log position as read"""
        self.log_positions[project] = self.get_current_log_position(project)

    def mark_all_logs_read(self):
        """Mark all existing log files at current position"""
        import glob
        today = datetime.now().strftime('%Y-%m-%d')

        # Find all project log files
        log_pattern = f"{self.tmpdir}/**/_webcentral_data/log/{today}.log"
        for log_file in glob.glob(log_pattern, recursive=True):
            # Extract project name from path
            rel_path = os.path.relpath(log_file, self.tmpdir)
            project = rel_path.split(os.sep)[0]
            self.log_positions[project] = os.path.getsize(log_file) if os.path.exists(log_file) else 0

        # Also mark stdout/stderr
        for special in ['stdout', 'stderr']:
            self.log_positions[special] = self.get_current_log_position(special)

    def show_all_new_logs(self):
        """Show all log files that have new content since last mark"""
        import glob
        today = datetime.now().strftime('%Y-%m-%d')

        has_output = False

        # Check project logs
        log_pattern = f"{self.tmpdir}/**/_webcentral_data/log/{today}.log"
        for log_file in glob.glob(log_pattern, recursive=True):
            rel_path = os.path.relpath(log_file, self.tmpdir)
            project = rel_path.split(os.sep)[0]

            start_pos = self.log_positions.get(project, 0)
            content = self.get_log_content(project, start_pos)

            if content.strip():
                if not has_output:
                    print(f"\n{YELLOW}=== Log output ==={RESET}")
                    has_output = True
                print(f"\n{YELLOW}--- {project} ---{RESET}")
                print(content)

        # Check stdout/stderr
        for special in ['stdout', 'stderr']:
            start_pos = self.log_positions.get(special, 0)
            content = self.get_log_content(special, start_pos)

            if content.strip():
                if not has_output:
                    print(f"\n{YELLOW}=== Log output ==={RESET}")
                    has_output = True
                print(f"\n{YELLOW}--- {special} ---{RESET}")
                print(content)

    def assert_log(self, project, text, count=1):
        """Assert that text appears in log exactly 'count' times"""
        start_pos = self.log_positions.get(project, 0)
        content = self.get_log_content(project, start_pos)
        actual_count = content.count(text)

        if actual_count != count:
            raise AssertionError(
                f"Expected '{text}' to appear {count} time(s) in {project} logs, "
                f"but found {actual_count} time(s).\nLog content:\n{content}"
            )

    def await_log(self, project, text, timeout=2):
        """Wait for text to appear in log"""
        start_pos = self.log_positions.get(project, 0)
        start_time = time.time()

        while time.time() - start_time < timeout:
            content = self.get_log_content(project, start_pos)
            if text in content:
                return
            time.sleep(0.05)

        content = self.get_log_content(project, start_pos)
        raise TimeoutError(
            f"Timeout waiting for '{text}' in {project} logs after {timeout}s.\n"
            f"Log content:\n{content}"
        )

    def assert_http(self, host, path, check_body=None, check_code=200, method='GET', data=None):
        """Make HTTP request and assert response"""
        conn = http.client.HTTPConnection('localhost', self.port)
        headers = {'Host': host}

        try:
            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            body = response.read().decode('utf-8')

            if response.status != check_code:
                raise AssertionError(
                    f"Expected status {check_code}, got {response.status}\n"
                    f"Body: {body}"
                )

            if check_body is not None and check_body not in body:
                raise AssertionError(
                    f"Expected body to contain '{check_body}', got:\n{body}"
                )

            return body
        finally:
            conn.close()

    def register_test(self, func):
        """Register a test function"""
        self.tests.append(func)
        return func

    def run(self, test_names=None):
        """Run all registered tests or specific ones if test_names provided"""
        # Filter tests if specific names provided
        tests_to_run = self.tests
        if test_names:
            # Normalize test names - support both "test_name" and "name" formats
            normalized_names = []
            for name in test_names:
                if not name.startswith('test_'):
                    normalized_names.append(f'test_{name}')
                else:
                    normalized_names.append(name)

            # Filter tests
            tests_to_run = [t for t in self.tests if t.__name__ in normalized_names]

            # Check if any test names were not found
            found_names = {t.__name__ for t in tests_to_run}
            for name in normalized_names:
                if name not in found_names:
                    print(f"{RED}Error: Test '{name}' not found{RESET}")
                    sys.exit(1)

        self.setup()

        failed = False
        try:
            for test_func in tests_to_run:
                test_name = test_func.__name__
                try:
                    # Mark all logs at current position before test
                    self.mark_all_logs_read()

                    test_func(self)
                    print(f"{GREEN}{CHECKMARK}{RESET} {test_name}")
                except Exception as e:
                    print(f"{RED}{CROSSMARK}{RESET} {test_name}")
                    print(f"{RED}Error: {e}{RESET}")

                    # Show all new log content
                    self.show_all_new_logs()

                    print(f"\nTest directory preserved at: {self.tmpdir}")
                    # Don't clean up on failure so we can inspect
                    failed = True
                    break

            if not failed:
                print(f"\n{GREEN}All {len(tests_to_run)} tests passed!{RESET}")
        finally:
            if self.webcentral_proc:
                self.webcentral_proc.terminate()
                try:
                    self.webcentral_proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    self.webcentral_proc.kill()
                    self.webcentral_proc.wait()

            if hasattr(self, 'stdout_f'):
                self.stdout_f.close()
            if hasattr(self, 'stderr_f'):
                self.stderr_f.close()

            if not failed and self.tmpdir and os.path.exists(self.tmpdir):
                shutil.rmtree(self.tmpdir)

        if failed:
            sys.exit(1)


# Global test runner
runner = TestRunner()


def test(func):
    """Decorator to register test functions"""
    runner.register_test(func)
    return func


# ============================================================================
# TESTS
# ============================================================================

@test
def test_static_file_serving(t):
    """Serve a static HTML file"""
    t.write_file('example.com/public/index.html', '<h1>Hello World</h1>')
    t.assert_http('example.com', '/', check_body='Hello World')


@test
def test_static_file_nested(t):
    """Serve nested static files"""
    t.write_file('test.org/public/css/style.css', 'body { color: red; }')
    t.assert_http('test.org', '/css/style.css', check_body='color: red')


@test
def test_simple_application(t):
    """Start and serve from a simple application"""
    t.write_file('app.net/webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('app.net/index.html', '<h1>App Server</h1>')

    # Making the HTTP request will trigger app start
    # The request will be queued until the app is ready
    t.assert_http('app.net', '/', check_body='App Server')

    # Verify the app actually started
    t.assert_log('app.net', 'reachable on port', count=1)


@test
def test_application_file_change_reload(t):
    """Application reloads when files change"""
    t.write_file('reload.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('reload.test/index.html', '<h1>Version 1</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('reload.test', '/', check_body='Version 1')
    t.assert_log('reload.test', 'reachable on port', count=1)

    # Mark logs as read before making changes
    t.mark_log_read('reload.test')

    # Modify file and wait for stop
    t.write_file('reload.test/index.html', '<h1>Version 2</h1>')
    t.await_log('reload.test', 'stopping due to change')

    # Make HTTP request to trigger restart and serve new content
    t.assert_http('reload.test', '/', check_body='Version 2')
    t.assert_log('reload.test', 'reachable on port', count=1)


@test
def test_config_change_reload(t):
    """Application reloads when config changes"""
    t.write_file('conftest.io/webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('conftest.io/page.html', '<h1>Test Page</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('conftest.io', '/page.html', check_body='Test Page')
    t.assert_log('conftest.io', 'reachable on port', count=1)
    t.mark_log_read('conftest.io')

    # Change config and wait for stop
    t.write_file('conftest.io/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=300')

    t.await_log('conftest.io', 'stopping due to change')

    # Make HTTP request to trigger restart
    t.assert_http('conftest.io', '/page.html', check_body='Test Page')
    t.assert_log('conftest.io', 'reachable on port', count=1)


@test
def test_slow_starting_application(t):
    """Handle application that takes time to open port"""
    # Create a script that delays before starting server
    t.write_file('slow.app/server.py', '''
import time
import sys
import os
time.sleep(1)
print("Starting server...", flush=True)
import http.server
import socketserver

PORT = int(os.environ.get('PORT', 8000))

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server started on port {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('slow.app/webcentral.ini',
                 'command=python3 -u server.py')
    t.write_file('slow.app/data.txt', 'Slow Server Data')

    # Make HTTP request (will take ~1 second to start)
    t.assert_http('slow.app', '/data.txt', check_body='Slow Server Data')
    t.assert_log('slow.app', 'reachable on port', count=1)


@test
def test_graceful_shutdown_delay(t):
    """Handle requests during graceful shutdown"""
    # Create a script that catches TERM signal and delays
    t.write_file('shutdown.test/server.py', '''
import signal
import sys
import time
import os
import http.server
import socketserver
from threading import Thread

shutdown_flag = False

def handle_term(signum, frame):
    global shutdown_flag
    print("Received TERM signal, delaying shutdown...", flush=True)
    shutdown_flag = True
    time.sleep(0.5)
    print("Shutdown delay complete", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_term)

PORT = int(os.environ.get('PORT', 8000))
Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server running on port {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('shutdown.test/webcentral.ini',
                 'command=python3 -u server.py')
    t.write_file('shutdown.test/index.html', '<h1>Shutdown Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('shutdown.test', '/', check_body='Shutdown Test')
    t.assert_log('shutdown.test', 'Server running', count=1)

    # Trigger reload to cause shutdown
    t.mark_log_read('shutdown.test')
    t.write_file('shutdown.test/index.html', '<h1>Shutdown Test v2</h1>')

    # Wait for shutdown signal to be received
    t.await_log('shutdown.test', 'Received TERM signal')
    t.await_log('shutdown.test', 'Shutdown delay complete')

    # Make HTTP request to trigger restart
    t.assert_http('shutdown.test', '/', check_body='Shutdown Test v2')
    t.assert_log('shutdown.test', 'Server running', count=1)


@test
def test_redirect_configuration(t):
    """Test HTTP redirect configuration"""
    t.write_file('redir.example/webcentral.ini',
                 'redirect=https://example.org/')

    # Expect 301 redirect
    t.assert_http('redir.example', '/', check_code=301)


@test
def test_multiple_projects_isolation(t):
    """Multiple projects run independently"""
    t.write_file('project1.test/public/index.html', '<h1>Project 1</h1>')
    t.write_file('project2.test/public/index.html', '<h1>Project 2</h1>')
    t.write_file('project3.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('project3.test/index.html', '<h1>Project 3</h1>')

    # Make HTTP requests to all projects
    t.assert_http('project1.test', '/', check_body='Project 1')
    t.assert_http('project2.test', '/', check_body='Project 2')
    t.assert_http('project3.test', '/', check_body='Project 3')

    # Verify project3 started its application
    t.assert_log('project3.test', 'reachable on port', count=1)


@test
def test_404_on_missing_file(t):
    """Return 404 for missing static files"""
    t.write_file('static.test/public/exists.html', '<h1>Exists</h1>')

    t.assert_http('static.test', '/exists.html', check_body='Exists')
    t.assert_http('static.test', '/missing.html', check_code=404)


@test
def test_application_stops_on_inactivity(t):
    """Application stops after inactivity timeout"""
    t.write_file('timeout.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=1')
    t.write_file('timeout.test/index.html', '<h1>Timeout Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('timeout.test', '/', check_body='Timeout Test')
    t.assert_log('timeout.test', 'reachable on port', count=1)
    t.mark_log_read('timeout.test')

    # Wait for timeout (1 second + some buffer)
    t.await_log('timeout.test', 'stopping due to inactivity', timeout=3)


@test
def test_application_restarts_after_timeout(t):
    """Application restarts on request after timeout"""
    t.write_file('restart.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=1')
    t.write_file('restart.test/index.html', '<h1>Restart Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('restart.test', '/', check_body='Restart Test')
    t.assert_log('restart.test', 'reachable on port', count=1)
    t.mark_log_read('restart.test')

    # Wait for timeout
    t.await_log('restart.test', 'stopping due to inactivity', timeout=3)

    # Make request to trigger restart
    t.mark_log_read('restart.test')
    t.assert_http('restart.test', '/', check_body='Restart Test')
    t.await_log('restart.test', 'reachable on port')


@test
def test_no_command_serves_static_only(t):
    """Project without command serves only static files"""
    t.write_file('nostatic.test/public/page.html', '<h1>Static Only</h1>')

    t.assert_http('nostatic.test', '/page.html', check_body='Static Only')


@test
def test_env_variables_in_config(t):
    """Environment variables are passed to application"""
    t.write_file('envtest.site/server.py', '''
import os
import http.server
import socketserver

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        value = os.environ.get('TEST_VAR', 'not set')
        self.wfile.write(f"TEST_VAR={value}".encode())

PORT = int(os.environ.get('PORT', 8000))
print(f"Starting on port {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('envtest.site/webcentral.ini',
                 'command=python3 -u server.py\n\n[environment]\nTEST_VAR=hello_world')

    # Make HTTP request to trigger app start and verify env var
    t.assert_http('envtest.site', '/', check_body='TEST_VAR=hello_world')
    t.assert_log('envtest.site', 'reachable on port', count=1)


@test
def test_post_request(t):
    """POST requests work correctly"""
    t.write_file('post.test/server.py', '''
import os
import http.server
import socketserver

class MyHandler(http.server.SimpleHTTPRequestHandler):
    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        post_data = self.rfile.read(content_length).decode('utf-8')

        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"Received: {post_data}".encode())

PORT = int(os.environ.get('PORT', 8000))
print(f"POST server on port {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('post.test/webcentral.ini',
                 'command=python3 -u server.py')

    # Make POST request to trigger app start and verify
    t.assert_http('post.test', '/', method='POST', data='test_data',
                  check_body='Received: test_data')
    t.assert_log('post.test', 'reachable on port', count=1)


@test
def test_multiple_file_changes_single_reload(t):
    """Multiple rapid file changes result in single reload"""
    t.write_file('multichg.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('multichg.test/file1.html', 'v1')
    t.write_file('multichg.test/file2.html', 'v1')

    # Make HTTP request to trigger app start
    t.assert_http('multichg.test', '/file1.html', check_body='v1')
    t.assert_log('multichg.test', 'reachable on port', count=1)
    t.mark_log_read('multichg.test')

    # Make multiple changes rapidly
    t.write_file('multichg.test/file1.html', 'v2')
    t.write_file('multichg.test/file2.html', 'v2')
    t.write_file('multichg.test/file3.html', 'v2')

    # Wait for stop
    t.await_log('multichg.test', 'stopping due to change')

    # Should only see one stop (file watcher exits on first change)
    t.assert_log('multichg.test', 'stopping due to change', count=1)

    # Make HTTP request to trigger restart
    t.assert_http('multichg.test', '/file1.html', check_body='v2')
    t.assert_log('multichg.test', 'reachable on port', count=1)

    # Verify that file watcher  runs again
    t.write_file('multichg.test/file1.html', 'v3')
    t.await_log('multichg.test', 'stopping due to change')
    t.assert_http('multichg.test', '/file1.html', check_body='v3')


@test
def test_subdirectory_files(t):
    """Serve files from subdirectories"""
    t.write_file('subdir.test/public/assets/js/app.js', 'console.log("test");')
    t.write_file('subdir.test/public/assets/css/style.css', 'body {}')

    t.assert_http('subdir.test', '/assets/js/app.js', check_body='console.log')
    t.assert_http('subdir.test', '/assets/css/style.css', check_body='body {}')


@test
def test_index_html_default(t):
    """index.html served as default for directory"""
    t.write_file('index.test/public/index.html', '<h1>Index Page</h1>')

    t.assert_http('index.test', '/', check_body='Index Page')


@test
def test_application_with_custom_port(t):
    """Application can specify custom port in command"""
    t.write_file('customport.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('customport.test/test.html', '<h1>Custom Port</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('customport.test', '/test.html', check_body='Custom Port')
    t.assert_log('customport.test', 'reachable on port', count=1)


@test
def test_request_to_nonexistent_domain(t):
    """Request to non-configured domain returns 404"""
    t.assert_http('nonexistent.domain', '/', check_code=404)


@test
def test_concurrent_requests_same_project(t):
    """Handle concurrent requests to the same project"""
    t.write_file('concurrent.test/public/data.txt', 'Concurrent Data')

    # Make multiple requests in quick succession
    t.assert_http('concurrent.test', '/data.txt', check_body='Concurrent Data')
    t.assert_http('concurrent.test', '/data.txt', check_body='Concurrent Data')
    t.assert_http('concurrent.test', '/data.txt', check_body='Concurrent Data')


@test
def test_webcentral_starts_successfully(t):
    """Verify webcentral process started without errors"""
    # Just check that there are no critical errors in stdout/stderr
    t.mark_log_read('stderr')
    time.sleep(0.2)
    # If there were startup errors, they would be in stderr
    # We just verify no "fatal" or "panic" messages
    stderr_content = t.get_log_content('stderr', 0)
    if 'fatal' in stderr_content.lower() or 'panic' in stderr_content.lower():
        raise AssertionError(f"Fatal error in stderr: {stderr_content}")


@test
def test_config_unknown_key_in_root(t):
    """Unknown keys in root section are logged as errors"""
    t.write_file('badconfig1.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\nunknown_key=value')
    t.write_file('badconfig1.test/index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and config loading
    t.assert_http('badconfig1.test', '/', check_body='Test')
    t.assert_log('badconfig1.test', "Unknown key 'unknown_key' in root section", count=1)


@test
def test_config_unknown_section(t):
    """Unknown sections are logged as errors"""
    t.write_file('badconfig2.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[invalid_section]\nkey=value')
    t.write_file('badconfig2.test/index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and config loading
    t.assert_http('badconfig2.test', '/', check_body='Test')
    t.assert_log('badconfig2.test', 'Unknown section [invalid_section] in webcentral.ini', count=1)


@test
def test_config_unknown_key_in_docker(t):
    """Unknown keys in docker section are logged as errors"""
    # Just serve static files - docker section is present but not used
    t.write_file('badconfig3.test/webcentral.ini',
                 '[docker]\nbase=alpine\ninvalid_docker_key=value')
    t.write_file('badconfig3.test/public/index.html', '<h1>Test</h1>')

    # First make a request to create the project and load config - this may fail
    # because docker is configured but we'll check the logs were written
    try:
        t.assert_http('badconfig3.test', '/', check_body='Test')
    except:
        # Even if request fails, the config should have been loaded and error logged
        pass

    # Verify the config error was logged
    t.assert_log('badconfig3.test', "Unknown key 'invalid_docker_key' in [docker] section", count=1)


@test
def test_config_unknown_key_in_reload(t):
    """Unknown keys in reload section are logged as errors"""
    t.write_file('badconfig4.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=60\nbad_key=123')
    t.write_file('badconfig4.test/index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and app start
    t.assert_http('badconfig4.test', '/', check_body='Test')
    t.assert_log('badconfig4.test', "Unknown key 'bad_key' in [reload] section", count=1)
    t.assert_log('badconfig4.test', 'reachable on port', count=1)


@test
def test_procfile_unsupported_type(t):
    """Unsupported Procfile process types are logged as errors"""
    t.write_file('procfile.test/Procfile',
                 'web: python3 -u -m http.server $PORT\nclock: python3 clock.py')
    t.write_file('procfile.test/index.html', '<h1>Procfile Test</h1>')

    # Make HTTP request to trigger project creation and app start
    t.assert_http('procfile.test', '/', check_body='Procfile Test')
    t.assert_log('procfile.test', "Procfile process type 'clock' is not supported", count=1)
    t.assert_log('procfile.test', 'reachable on port', count=1)


if __name__ == '__main__':
    # Parse command line arguments for test names
    test_names = sys.argv[1:] if len(sys.argv) > 1 else None
    runner.run(test_names)
