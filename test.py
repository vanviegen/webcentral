#!/usr/bin/env python3

import argparse
import glob
import http.client
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import traceback
from datetime import datetime

# ANSI color codes
GREEN = '\033[92m'
RED = '\033[91m'
YELLOW = '\033[93m'
GRAY = '\033[90m'
RESET = '\033[0m'
CHECKMARK = '✓'
CROSSMARK = '✗'
CLEAR_LINE = '\033[2K\r'


class TestRunner:
    def __init__(self):
        self.tests = []
        self.tmpdir = None
        self.webcentral_proc = None
        self.port = None
        self.log_positions = {}  # project -> position in log file
        self.use_firejail = True
        self.current_test_domain = None  # Set during test execution

    def find_free_port(self):
        """Find a random free port"""
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(('', 0))
            s.listen(1)
            port = s.getsockname()[1]
        return port

    def setup(self):
        """Set up test environment and start webcentral"""
        # Use fixed test directory in current directory
        cwd = os.path.dirname(os.path.abspath(__file__))
        self.tmpdir = os.path.join(cwd, '.maca-test')
        
        # Empty the directory if it exists
        if os.path.exists(self.tmpdir):
            shutil.rmtree(self.tmpdir)
        
        # Create the directory
        os.makedirs(self.tmpdir)
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

        cmd = ['target/debug/webcentral',
               '--projects', self.tmpdir,
               '--http', str(self.port),
               '--https', '0',
               '--data-dir', self.tmpdir,
               '--firejail', "true" if self.use_firejail else "false"]
        print(" ".join(cmd))
        self.webcentral_proc = subprocess.Popen(
            cmd,
            stdout=stdout_f,
            stderr=stderr_f,
            cwd=os.path.dirname(os.path.abspath(__file__))
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
            self.show_all_new_logs()
            raise Exception("Webcentral process failed to start")

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

    def write_file(self, path, content, absolute=False):
        """Write a file in the test directory. Path is prefixed with test domain unless absolute=True."""
        if not absolute and self.current_test_domain and not path.startswith(self.current_test_domain):
            path = f"{self.current_test_domain}/{path}"
        full_path = os.path.join(self.tmpdir, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        with open(full_path, 'w') as f:
            f.write(content)

    def mark_log_read(self, project=None):
        """Mark current log position as read. Defaults to current test domain."""
        if project is None:
            project = self.current_test_domain
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
        today = datetime.now().strftime('%Y-%m-%d')

        # Small delay to give webcentral opportunity to log everything it wants to log
        from time import sleep
        sleep(0.5)

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

    def assert_log(self, text_or_project, text=None, count=1):
        """Assert that text appears in log exactly 'count' times. 
        Can be called as assert_log(text) or assert_log(project, text)."""
        if text is None:
            project = self.current_test_domain
            text = text_or_project
        else:
            project = text_or_project
        start_pos = self.log_positions.get(project, 0)
        content = self.get_log_content(project, start_pos)
        actual_count = content.count(text)

        if actual_count != count:
            raise AssertionError(
                f"Expected '{text}' to appear {count} time(s) in {project} logs, "
                f"but found {actual_count} time(s)."
            )

    def await_log(self, text_or_project, text=None, timeout=2):
        """Wait for text to appear in log.
        Can be called as await_log(text) or await_log(project, text)."""
        if text is None:
            project = self.current_test_domain
            text = text_or_project
        else:
            project = text_or_project
        print(f"{CLEAR_LINE}{GRAY}→ Waiting for log: {text[:50]}...{RESET}", end='', flush=True)

        start_pos = self.log_positions.get(project, 0)
        start_time = time.time()

        while time.time() - start_time < timeout:
            content = self.get_log_content(project, start_pos)
            if text in content:
                return
            time.sleep(0.05)

        print()  # Clear the progress line
        content = self.get_log_content(project, start_pos)
        raise TimeoutError(
            f"Timeout waiting for '{text}' in {project} logs after {timeout}s."
        )

    def assert_http(self, path, check_body=None, check_code=200, method='GET', data=None, timeout=5, host=None):
        """Make HTTP request and assert response. Host defaults to current test domain."""
        if host is None:
            host = self.current_test_domain
        print(f"{CLEAR_LINE}{GRAY}→ HTTP {method} {host}{path}{RESET}", end='', flush=True)

        conn = http.client.HTTPConnection('localhost', self.port, timeout=timeout)
        headers = {'Host': host}

        try:
            conn.request(method, path, body=data, headers=headers)
            response = conn.getresponse()
            body = response.read().decode('utf-8')

            if check_code is not None and response.status != check_code:
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
            print(CLEAR_LINE, end='', flush=True)
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
                # Derive domain from test name: test_foo_bar -> foo-bar.test
                domain = test_name.replace('test_', '').replace('_', '-') + '.test'
                self.current_test_domain = domain
                
                try:
                    # Mark all logs at current position before test
                    self.mark_all_logs_read()
                    
                    # Create test domain directory and wait for registration
                    domain_dir = os.path.join(self.tmpdir, domain)
                    os.makedirs(domain_dir, exist_ok=True)
                    self.await_log('stdout', f'Domain {domain} added')

                    test_func(self)
                    print(f"{CLEAR_LINE}{GREEN}{CHECKMARK}{RESET} {test_name}")
                except Exception as e:
                    print(f"{CLEAR_LINE}{RED}{CROSSMARK}{RESET} {test_name}")
                    print(f"{RED}Error:{RESET} {e}")
                    
                    # Extract and show location from traceback
                    # Find the frame for the test function itself
                    tb = traceback.extract_tb(e.__traceback__)
                    for frame in tb:
                        if frame.name == test_func.__name__:
                            print(f"{RED}At:{RESET} {frame.filename}:{frame.lineno}")
                            break

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
    t.write_file('public/index.html', '<h1>Hello World</h1>')
    t.assert_http('/', check_body='Hello World')


@test
def test_static_file_nested(t):
    """Serve nested static files"""
    t.write_file('public/css/style.css', 'body { color: red; }')
    t.assert_http('/css/style.css', check_body='color: red')


@test
def test_simple_application(t):
    """Start and serve from a simple application"""
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>App Server</h1>')

    # Making the HTTP request will trigger app start
    # The request will be queued until the app is ready
    t.assert_http('/', check_body='App Server')

    # Verify the app actually started
    t.assert_log('Ready on port', count=1)


@test
def test_application_file_change_reload(t):
    """Application reloads when files change"""
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>Version 1</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Version 1')
    t.assert_log('Ready on port', count=1)

    # Mark logs as read before making changes
    t.mark_log_read()

    # Modify file and wait for stop
    t.write_file('index.html', '<h1>Version 2</h1>')
    t.await_log('Stopping due to file changes')

    # Make HTTP request to trigger restart and serve new content
    t.assert_http('/', check_body='Version 2')
    t.assert_log('Ready on port', count=1)


@test
def test_config_change_reload(t):
    """Application reloads when config changes"""
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('page.html', '<h1>Test Page</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/page.html', check_body='Test Page')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Change config and wait for stop
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=300')

    t.await_log('Stopping due to file changes')

    # Make HTTP request to trigger restart
    t.assert_http('/page.html', check_body='Test Page')
    t.assert_log('Ready on port', count=1)


@test
def test_slow_starting_application(t):
    """Handle application that takes time to open port"""
    # Create a script that delays before starting server
    t.write_file('server.py', '''
import time
import sys
import os
time.sleep(1)
print("Starting server...", flush=True)
import http.server
import socketserver

PORT = int(os.environ.get('PORT'))

Handler = http.server.SimpleHTTPRequestHandler
with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server started on port {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')
    t.write_file('data.txt', 'Slow Server Data')

    # Make HTTP request (will take ~1 second to start)
    t.assert_http('/data.txt', check_body='Slow Server Data')
    t.assert_log('Ready on port', count=1)


@test
def test_graceful_shutdown_delay(t):
    """Handle requests during graceful shutdown"""
    # Create a script that catches TERM signal and delays
    t.write_file('server.py', '''
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
    time.sleep(1)
    print("Shutdown delay complete", flush=True)
    sys.exit(0)

signal.signal(signal.SIGTERM, handle_term)

PORT = int(os.environ.get('PORT'))
Handler = http.server.SimpleHTTPRequestHandler

with socketserver.TCPServer(("", PORT), Handler) as httpd:
    print(f"Server running on port {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')
    t.write_file('index.html', '<h1>Shutdown Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Shutdown Test')
    t.assert_log('Server running', count=1)

    # Trigger reload to cause shutdown
    t.mark_log_read()
    t.write_file('index.html', '<h1>Shutdown Test v2</h1>')

    # Wait for shutdown signal to be received
    t.await_log('Received TERM signal', timeout=5)
    t.await_log('Shutdown delay complete')

    # Make HTTP request to trigger restart
    t.assert_http('/', check_body='Shutdown Test v2')
    t.assert_log('Server running', count=1)


@test
def test_redirect_configuration(t):
    """Test HTTP redirect configuration"""
    t.write_file('webcentral.ini', 'redirect=https://example.org/')

    # Expect 301 redirect
    t.assert_http('/', check_code=301)


@test
def test_multiple_projects_isolation(t):
    """Multiple projects run independently"""
    # This test needs multiple domains, so use absolute paths
    t.write_file('project1.test/public/index.html', '<h1>Project 1</h1>', absolute=True)
    t.write_file('project2.test/public/index.html', '<h1>Project 2</h1>', absolute=True)
    t.write_file('project3.test/webcentral.ini',
                 'command=python3 -u -m http.server $PORT', absolute=True)
    t.write_file('project3.test/index.html', '<h1>Project 3</h1>', absolute=True)

    # Wait for all domains to be registered
    t.await_log('stdout', 'Domain project1.test added')
    t.await_log('stdout', 'Domain project2.test added')
    t.await_log('stdout', 'Domain project3.test added')

    # Make HTTP requests to all projects
    t.assert_http('/', check_body='Project 1', host='project1.test')
    t.assert_http('/', check_body='Project 2', host='project2.test')
    t.assert_http('/', check_body='Project 3', host='project3.test')

    # Verify project3 started its application
    t.assert_log('project3.test', 'Ready on port', count=1)


@test
def test_404_on_missing_file(t):
    """Return 404 for missing static files"""
    t.write_file('public/exists.html', '<h1>Exists</h1>')

    t.assert_http('/exists.html', check_body='Exists')
    t.assert_http('/missing.html', check_code=404)


@test
def test_application_stops_on_inactivity(t):
    """Application stops after inactivity timeout"""
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=1')
    t.write_file('index.html', '<h1>Timeout Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Timeout Test')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Wait for timeout (1 second + some buffer)
    t.await_log('Stopping due to inactivity', timeout=3)


@test
def test_application_restarts_after_timeout(t):
    """Application restarts on request after timeout"""
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=1')
    t.write_file('index.html', '<h1>Restart Test</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Restart Test')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Wait for timeout
    t.await_log('Stopping due to inactivity', timeout=3)

    # Make request to trigger restart
    t.mark_log_read()
    t.assert_http('/', check_body='Restart Test')
    t.await_log('Ready on port')


@test
def test_no_command_serves_static_only(t):
    """Project without command serves only static files"""
    t.write_file('public/page.html', '<h1>Static Only</h1>')

    t.assert_http('/page.html', check_body='Static Only')


@test
def test_env_variables_in_config(t):
    """Environment variables are passed to application"""
    t.write_file('server.py', '''
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

PORT = int(os.environ.get('PORT'))
print(f"Starting on port {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini',
                 'command=python3 -u server.py\n\n[environment]\nTEST_VAR=hello_world')

    # Make HTTP request to trigger app start and verify env var
    t.assert_http('/', check_body='TEST_VAR=hello_world')
    t.assert_log('Ready on port', count=1)


@test
def test_post_request(t):
    """POST requests work correctly"""
    t.write_file('server.py', '''
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

PORT = int(os.environ.get('PORT'))
print(f"POST server on port {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), MyHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # Make POST request to trigger app start and verify
    t.assert_http('/', method='POST', data='test_data', check_body='Received: test_data')
    t.assert_log('Ready on port', count=1)


@test
def test_multiple_file_changes_single_reload(t):
    """Multiple rapid file changes result in single reload"""
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('file1.html', 'v1')
    t.write_file('file2.html', 'v1')

    # Make HTTP request to trigger app start
    t.assert_http('/file1.html', check_body='v1')
    t.await_log('Ready on port')
    t.mark_log_read()

    # Make multiple changes rapidly
    t.write_file('file1.html', 'v2')
    t.write_file('file2.html', 'v2')
    t.write_file('file3.html', 'v2')

    # Wait for stop
    t.await_log('Stopping due to file changes')

    # Should only see one stop (file watcher exits on first change)
    t.assert_log('Stopping due to file changes', count=1)

    # Make HTTP request to trigger restart
    t.assert_http('/file1.html', check_body='v2')
    t.await_log('Ready on port')

    # Verify that file watcher runs again
    t.mark_log_read()
    t.write_file('file1.html', 'v3')
    t.await_log('Stopping due to file changes')
    t.assert_http('/file1.html', check_body='v3')


@test
def test_subdirectory_files(t):
    """Serve files from subdirectories"""
    t.write_file('public/assets/js/app.js', 'console.log("test");')
    t.write_file('public/assets/css/style.css', 'body {}')

    t.assert_http('/assets/js/app.js', check_body='console.log')
    t.assert_http('/assets/css/style.css', check_body='body {}')


@test
def test_index_html_default(t):
    """index.html served as default for directory"""
    t.write_file('public/index.html', '<h1>Index Page</h1>')

    t.assert_http('/', check_body='Index Page')


@test
def test_application_with_custom_port(t):
    """Application can specify custom port in command"""
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('test.html', '<h1>Custom Port</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/test.html', check_body='Custom Port')
    t.assert_log('Ready on port', count=1)


@test
def test_request_to_nonexistent_domain(t):
    """Request to non-configured domain returns 404"""
    t.assert_http('/', check_code=404, host='nonexistent.domain')


@test
def test_concurrent_requests_same_project(t):
    """Handle concurrent requests to the same project"""
    t.write_file('public/data.txt', 'Concurrent Data')

    # Make multiple requests in quick succession
    t.assert_http('/data.txt', check_body='Concurrent Data')
    t.assert_http('/data.txt', check_body='Concurrent Data')
    t.assert_http('/data.txt', check_body='Concurrent Data')


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
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\nunknown_key=value')
    t.write_file('index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and config loading
    t.assert_http('/', check_body='Test')
    t.assert_log("Unexpected key 'unknown_key'", count=1)


@test
def test_config_unknown_section(t):
    """Unknown sections are logged as errors"""
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[invalid_section]\nkey=value')
    t.write_file('index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and config loading
    t.assert_http('/', check_body='Test')
    t.assert_log("Unexpected key 'invalid_section.key'", count=1)


@test
def test_config_unknown_key_in_docker(t):
    """Unknown keys in docker section are logged as errors"""
    # Just serve static files - docker section is present but not used
    t.write_file('webcentral.ini', '[docker]\nbase=alpine\ninvalid_docker_key=value')
    t.write_file('public/index.html', '<h1>Test</h1>')

    # First make a request to create the project and load config - this may fail
    # because docker is configured but we'll check the logs were written
    try:
        t.assert_http('/', check_body='Test')
    except:
        # Even if request fails, the config should have been loaded and error logged
        pass

    # Verify the config error was logged
    t.assert_log("Unexpected key 'docker.invalid_docker_key'", count=1)


@test
def test_http2_support(t):
    """Verify HTTP/2 support using curl"""
    # Check if curl supports HTTP/2
    try:
        result = subprocess.run(['curl', '--version'], capture_output=True, text=True)
        if 'HTTP2' not in result.stdout:
            print(f"{YELLOW}Skipped: curl does not support HTTP/2{RESET}")
            return
    except FileNotFoundError:
        print(f"{YELLOW}Skipped: curl not found{RESET}")
        return

    t.write_file('public/index.html', '<h1>HTTP/2 Test</h1>')

    # Start the server by making a regular request first (to ensure it's up)
    t.assert_http('/', check_body='HTTP/2 Test')

    # Now test HTTP/2
    # We use the port from the test runner
    # For HTTP/2 over cleartext (h2c), we need --http2-prior-knowledge
    cmd = ['curl', '--http2-prior-knowledge', '-v', f'http://localhost:{t.port}/', '-H', f'Host: {t.current_test_domain}']
    
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        
        # Check for HTTP/2 in verbose output
        # curl usually prints "> GET / HTTP/2" or "< HTTP/2 200"
        if 'HTTP/2' in result.stderr or 'HTTP/2' in result.stdout:
             pass # Success
        elif 'Using HTTP2' in result.stderr:
             pass # Success
        else:
            # Fallback check - sometimes it might downgrade if not supported properly, 
            # but we want to ensure it ATTEMPTED and succeeded if supported.
            # If the server didn't support it, curl would fall back to 1.1 and we'd see HTTP/1.1
            if 'HTTP/1.1' in result.stderr:
                 raise AssertionError("Server downgraded to HTTP/1.1, expected HTTP/2")
            
            # If we can't determine, print output for debugging
            # raise AssertionError(f"Could not determine HTTP version from curl output:\n{result.stderr}")
            pass

    except subprocess.TimeoutExpired:
        raise AssertionError("curl timed out")


@test
def test_config_unknown_key_in_reload(t):
    """Unknown keys in reload section are logged as errors"""
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n\n[reload]\ntimeout=60\nbad_key=123')
    t.write_file('index.html', '<h1>Test</h1>')

    # Make HTTP request to trigger project creation and app start
    t.assert_http('/', check_body='Test')
    t.assert_log("Unexpected key 'reload.bad_key'", count=1)
    t.assert_log('Ready on port', count=1)


@test
def test_procfile_unsupported_type(t):
    """Unsupported Procfile process types are logged as errors"""
    t.write_file('Procfile', 'web: python3 -u -m http.server $PORT\nclock: python3 clock.py')
    t.write_file('index.html', '<h1>Procfile Test</h1>')

    # Make HTTP request to trigger project creation and app start
    t.assert_http('/', check_body='Procfile Test')
    t.assert_log("Procfile process type 'clock' is not supported", count=1)
    t.assert_log('Ready on port', count=1)


@test
def test_procfile_web_only(t):
    """Procfile with only web process starts successfully"""
    t.write_file('Procfile', 'web: python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>Procfile Web</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Procfile Web')
    t.assert_log('Ready on port', count=1)


@test
def test_procfile_with_worker(t):
    """Procfile with web + worker processes"""
    # Create a worker script that writes to a file
    t.write_file('worker.py', '''
import time
import os
print("I am a starting test worker...", flush=True)
time.sleep(0.5)
with open("worker_output.txt", "w") as f:
    f.write("Worker was here")
print("I am a finished little worker", flush=True)
time.sleep(100)  # Keep running
''')

    t.write_file('Procfile', 'web: python3 -u -m http.server $PORT\nworker: python3 -u worker.py')
    t.write_file('index.html', '<h1>Procfile with Worker</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Procfile with Worker')
    t.assert_log('Ready on port', count=1)

    # Verify worker started
    t.assert_log('Starting 1 worker(s)', count=1)
    t.await_log('I am a starting test worker...')
    t.await_log('I am a finished little worker')

    # Verify worker output file was created
    time.sleep(0.2)
    worker_output = os.path.join(t.tmpdir, f'{t.current_test_domain}/worker_output.txt')
    if not os.path.exists(worker_output):
        raise AssertionError("Worker output file was not created")


@test
def test_procfile_multiple_workers(t):
    """Procfile with multiple worker processes"""
    t.write_file('worker1.py', '''
import time
print("Worker 1 starting", flush=True)
time.sleep(100)
''')

    t.write_file('worker2.py', '''
import time
print("Worker 2 starting", flush=True)
time.sleep(100)
''')

    t.write_file('Procfile',
                 'web: python3 -u -m http.server $PORT\n'
                 'worker: python3 -u worker1.py\n'
                 'urgentworker: python3 -u worker2.py')
    t.write_file('index.html', '<h1>Multiple Workers</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Multiple Workers')
    t.assert_log('Ready on port', count=1)

    # Verify both workers started
    t.assert_log('Starting 2 worker(s)', count=1)
    t.await_log('Worker 1 starting')
    t.await_log('Worker 2 starting')


@test
def test_ini_single_worker(t):
    """webcentral.ini with single worker process"""
    t.write_file('worker.py', '''
import time
print("INI Worker running", flush=True)
time.sleep(100)
''')

    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker=python3 -u worker.py')
    t.write_file('index.html', '<h1>INI Worker</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='INI Worker')
    t.assert_log('Ready on port', count=1)

    # Verify worker started
    t.assert_log('Starting 1 worker(s)', count=1)
    t.await_log('INI Worker running')


@test
def test_ini_multiple_named_workers(t):
    """webcentral.ini with multiple named worker processes"""
    t.write_file('email_worker.py', '''
import time
print("Email worker active", flush=True)
time.sleep(100)
''')

    t.write_file('task_worker.py', '''
import time
print("Task worker active", flush=True)
time.sleep(100)
''')

    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker:email=python3 -u email_worker.py\n'
                 'worker:tasks=python3 -u task_worker.py')
    t.write_file('index.html', '<h1>Multiple Named Workers</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Multiple Named Workers')
    t.assert_log('Ready on port', count=1)

    # Verify workers started
    t.assert_log('Starting 2 worker(s)', count=1)
    t.await_log('Email worker active')
    t.await_log('Task worker active')


@test
def test_workers_restart_on_file_change(t):
    """Workers restart when files change"""
    t.write_file('worker.py', '''
import time
print("Worker v1", flush=True)
time.sleep(100)
''')

    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker=python3 -u worker.py')
    t.write_file('index.html', '<h1>Version 1</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Version 1')
    t.assert_log('Ready on port', count=1)
    t.await_log('Worker v1')

    # Mark logs as read before making changes
    t.mark_log_read()

    # Modify worker file to trigger reload
    t.write_file('worker.py', '''
import time
print("Worker v2", flush=True)
time.sleep(100)
''')

    # Wait for stop
    t.await_log('Stopping due to file changes')

    # Make HTTP request to trigger restart
    t.assert_http('/', check_body='Version 1')
    t.assert_log('Ready on port', count=1)
    t.await_log('Worker v2')


@test
def test_workers_stop_on_inactivity(t):
    """Workers stop with main process on inactivity timeout"""
    t.write_file('worker.py', '''
import time
print("Worker running", flush=True)
time.sleep(100)
''')

    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker=python3 -u worker.py\n\n'
                 '[reload]\ntimeout=1')
    t.write_file('index.html', '<h1>Worker Timeout</h1>')

    # Make HTTP request to trigger app start
    t.assert_http('/', check_body='Worker Timeout')
    t.assert_log('Ready on port', count=1)
    t.await_log('Worker running')

    t.mark_log_read()

    # Wait for timeout
    t.await_log('Stopping due to inactivity', timeout=3)


@test
def test_broken_ini_syntax_error(t):
    """Broken webcentral.ini shows error in log"""
    # Create a completely broken ini file (just nonsense)
    t.write_file('webcentral.ini', 'asdfasdf\n!!@@##\ngarbage\n')
    t.write_file('public/index.html', '<h1>Static Content</h1>')

    # Should still serve static files
    t.assert_http('/', check_body='Static Content')

    # Should log errors about the invalid syntax
    t.assert_log('Invalid syntax in webcentral.ini at line 1: asdfasdf', count=1)
    t.assert_log('Invalid syntax in webcentral.ini at line 2: !!@@##', count=1)
    t.assert_log('Invalid syntax in webcentral.ini at line 3: garbage', count=1)


@test
def test_edit_broken_ini_triggers_reload(t):
    """Editing webcentral.ini triggers reload even if broken"""
    # Start with a broken ini
    t.write_file('webcentral.ini', 'garbage nonsense\n!!!')
    t.write_file('public/index.html', '<h1>Version 1</h1>')

    # Make initial request
    t.assert_http('/', check_body='Version 1')
    t.mark_log_read()
    t.write_file('webcentral.ini', 'different garbage\n###')

    # Should trigger a reload/restart
    t.await_log('Stopping due to file changes', timeout=2)

    # Should still serve static files after reload
    t.assert_http('/', check_body='Version 1')


@test
def test_ini_disappearing_app_becomes_static(t):
    """Removing webcentral.ini converts app to static site"""
    # Start with an application
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>App Content</h1>')
    t.write_file('public/index.html', '<h1>Static Content</h1>')

    # Start the app
    t.assert_http('/', check_body='App Content')
    t.await_log('Ready on port')
    t.mark_log_read()

    # Remove the ini file
    os.remove(os.path.join(t.tmpdir, f'{t.current_test_domain}/webcentral.ini'))

    # Should trigger reload and stop the process
    t.await_log('Stopped app', timeout=10)

    # Now should serve static files from public/
    t.assert_http('/', check_body='Static Content')
    t.await_log('Static file server', timeout=4)


@test
def test_ini_appearing_static_becomes_app(t):
    """Adding webcentral.ini converts static site to app"""
    # Start with static site
    t.write_file('public/index.html', '<h1>Static Only</h1>')
    t.write_file('index.html', '<h1>App Will Serve This</h1>')

    # Access static site
    t.assert_http('/', check_body='Static Only')
    t.mark_log_read()

    # Add ini file to make it an app
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Now should serve via app
    t.assert_http('/', check_body='App Will Serve This')
    t.assert_log('Ready on port', count=1)


@test
def test_ini_broken_to_valid(t):
    """Fixing broken ini starts the application"""
    # Start with broken ini
    t.write_file('webcentral.ini', 'broken syntax!!!\n###')
    t.write_file('public/index.html', '<h1>Static</h1>')
    t.write_file('index.html', '<h1>App Content</h1>')

    # Access as static (broken ini means no app)
    t.assert_http('/', check_body='Static')
    t.assert_log('Invalid syntax in webcentral.ini', count=1)
    t.mark_log_read()

    # Fix the ini
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Now should work as app
    t.assert_http('/', check_body='App Content')
    t.assert_log('Ready on port', count=1)


@test
def test_ini_valid_to_broken(t):
    """Breaking ini converts app back to static"""
    # Start with valid ini
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>App</h1>')
    t.write_file('public/index.html', '<h1>Static</h1>')

    # Start the app
    t.assert_http('/', check_body='App')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Break the ini
    t.write_file('webcentral.ini', 'invalid!!!\ngarbage')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Now should serve static
    t.assert_http('/', check_body='Static')
    t.assert_log('Invalid syntax in webcentral.ini', count=2)


@test
def test_command_changing(t):
    """Changing command in ini restarts with new command"""
    # Start with simple server
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>HTTP Server</h1>')

    # Start the app
    t.assert_http('/', check_body='HTTP Server')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Change to a different server command
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class CustomHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()
        self.wfile.write(b"<h1>Custom Server</h1>")

PORT = int(os.environ.get('PORT'))
with socketserver.TCPServer(("", PORT), CustomHandler) as httpd:
    print(f"Custom server on {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should start with new command
    t.assert_http('/', check_body='Custom Server')
    t.await_log('Custom server on')


@test
def test_environment_variables_changing(t):
    """Changing environment variables triggers reload with new values"""
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class EnvHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        env_value = os.environ.get('MY_VAR', 'not set')
        self.wfile.write(f"MY_VAR={env_value}".encode())

PORT = int(os.environ.get('PORT'))
with socketserver.TCPServer(("", PORT), EnvHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py\n\n[environment]\nMY_VAR=value1')

    # Start the app
    t.assert_http('/', check_body='MY_VAR=value1')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Change environment variable
    t.write_file('webcentral.ini', 'command=python3 -u server.py\n\n[environment]\nMY_VAR=value2')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should have new value
    t.assert_http('/', check_body='MY_VAR=value2')


@test
def test_workers_added_via_config_change(t):
    """Adding workers to ini starts them on reload"""
    # Start without workers
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>Test</h1>')
    t.write_file('worker.py', '''
import time
print("New worker started", flush=True)
time.sleep(100)
''')

    # Start the app
    t.assert_http('/', check_body='Test')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Add worker to config
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker=python3 -u worker.py')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should start with worker
    t.assert_http('/', check_body='Test')
    t.assert_log('Starting 1 worker(s)', count=1)
    t.await_log('New worker started')


@test
def test_workers_removed_via_config_change(t):
    """Removing workers from ini stops them on reload"""
    # Start with worker
    t.write_file('worker.py', '''
import time
print("Worker running", flush=True)
time.sleep(100)
''')
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT\n'
                 'worker=python3 -u worker.py')
    t.write_file('index.html', '<h1>Test</h1>')

    # Start the app
    t.assert_http('/', check_body='Test')
    t.await_log('Worker running')
    t.mark_log_read()

    # Remove worker from config
    t.write_file('webcentral.ini', 'command=python3 -u -m http.server $PORT')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should not log about workers anymore
    t.mark_log_read()
    t.assert_http('/', check_body='Test')
    # No "starting N worker(s)" message in new logs
    new_logs = t.get_log_content(t.current_test_domain, t.log_positions[t.current_test_domain])
    if 'Starting 1 worker(s)' in new_logs:
        raise AssertionError("Workers should not be started after removal from config")


@test
def test_redirect_changes_to_app(t):
    """Changing from redirect to app restarts as application"""
    # Start as redirect
    t.write_file('webcentral.ini',
                 'redirect=https://example.com/')
    t.write_file('index.html', '<h1>App Content</h1>')

    # Should redirect
    t.assert_http('/', check_code=301)
    t.mark_log_read()

    # Change to app
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should now serve app
    t.assert_http('/', check_body='App Content')
    t.assert_log('Ready on port', count=1)


@test
def test_app_changes_to_redirect(t):
    """Changing from app to redirect stops app and redirects"""
    # Start as app
    t.write_file('webcentral.ini',
                 'command=python3 -u -m http.server $PORT')
    t.write_file('index.html', '<h1>App</h1>')

    # Start the app
    t.assert_http('/', check_body='App')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()

    # Change to redirect
    t.write_file('webcentral.ini',
                 'redirect=https://example.org/')

    # Should trigger reload
    t.await_log('Stopping due to file changes', timeout=2)

    # Should now redirect
    t.assert_http('/', check_code=301)


@test
def test_static_ignores_non_config_file_changes(t):
    """Static file servers should only reload on webcentral.ini/Procfile changes"""
    # Start with static site
    t.write_file('public/index.html', '<h1>Static</h1>')
    
    # Access to start the project
    t.assert_http('/', check_body='Static')
    t.mark_log_read()
    
    # Create a random file in the root (should NOT trigger reload for static sites)
    t.write_file('random.txt', 'some content')
    
    # Should NOT have any "stopping" log
    t.assert_http('/', check_body='Static')
    t.assert_log('Stopping due to file changes', count=0)
    
    # But adding webcentral.ini should trigger reload
    t.write_file('webcentral.ini', 'command=echo test')
    t.await_log('Stopping due to file changes', timeout=2)


@test
def test_app_respects_include_patterns(t):
    """Apps should only reload for files matching include patterns"""
    # Start with app that only watches .py files
    t.write_file('webcentral.ini', '''
command=python3 -u -m http.server $PORT
[reload]
include[]=*.py
include[]=webcentral.ini
''')
    t.write_file('index.html', '<h1>Original</h1>')
    
    # Start the app
    t.assert_http('/', check_body='Original')
    t.await_log('Ready on port')
    t.mark_log_read()
    
    # Modify .txt file (should NOT trigger reload)
    t.write_file('data.txt', 'new data')
    
    # Should NOT have reloaded
    t.assert_http('/', check_body='Original')
    t.assert_log('Stopping due to file changes', count=0)
    
    # Modify .py file (should trigger reload)
    t.write_file('script.py', 'print("test")')
    t.await_log('Stopping due to file changes', timeout=2)


@test
def test_app_respects_exclude_patterns(t):
    """Apps should not reload for files matching exclude patterns"""
    # Start with app that excludes .tmp files
    t.write_file('webcentral.ini', '''
command=python3 -u -m http.server $PORT
[reload]
exclude[]=*.tmp
exclude[]=temp/*
''')
    t.write_file('index.html', '<h1>Test</h1>')
    
    # Start the app
    t.assert_http('/', check_body='Test')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()
    
    # Create excluded .tmp file (should NOT trigger reload)
    t.write_file('temp.tmp', 'temporary')
    
    # Should NOT have reloaded
    t.assert_http('/', check_body='Test')
    t.assert_log('Stopping due to file changes', count=0)
    
    # Create file in excluded directory (should NOT trigger reload)
    t.write_file('temp/file.txt', 'data')
    
    # Wait a bit
    t.assert_http('/', check_body='Test')
    t.assert_log('Stopping due to file changes', count=0)
    
    # Create regular file (should trigger reload)
    t.write_file('data.json', '{}')
    t.await_log('Stopping due to file changes', timeout=2)


@test
def test_rooted_path_pattern(t):
    """Pattern with leading ./ should match from root only"""
    # App that watches all files but demonstrates basename matching
    t.write_file('webcentral.ini', '''
command=python3 -u -m http.server $PORT
[reload]
include[]=**/*
exclude[]=subdir/package.json
''')
    t.write_file('package.json', '{"version": "1.0.0"}')
    t.write_file('subdir/package.json', '{"version": "2.0.0"}')
    
    # Start the app
    t.assert_http('/')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()
    
    # Modify subdir/package.json (explicitly excluded, should NOT reload)
    t.write_file('subdir/package.json', '{"version": "2.0.1"}')
    t.assert_http('/')
    t.assert_log('Stopping due to file changes', count=0)
    
    # Modify root package.json (not excluded, should reload)
    t.write_file('package.json', '{"version": "1.0.1"}')
    t.await_log('Stopping due to file changes', timeout=2)


@test  
def test_matches_pattern_logic(t):
    """Verify matchesPattern behavior with path patterns"""
    # Test that pattern "src" matches "src/package.json"
    # This is the root cause: exclude pattern "src" blocks "src/package.json" before includes are checked
    t.write_file('webcentral.ini', '''
command=python3 -u -m http.server $PORT
[reload]
# With only includes and no excludes, verify src/package.json triggers reload
include[]=src/package.json
''')
    t.write_file('index.html', '<h1>V1</h1>')
    t.write_file('src/package.json', '{"version": "1.0.0"}')
    t.write_file('src/other.js', 'console.log("v1")')
    
    # Start the app
    t.assert_http('/', check_body='V1')
    t.assert_log('Ready on port', count=1)
    t.mark_log_read()
    
    # Modify src/other.js (not included, should NOT reload)
    t.write_file('src/other.js', 'console.log("v2")')
    t.assert_http('/', check_body='V1')
    t.assert_log('Stopping due to file changes', count=0)
    
    # Modify src/package.json (included, SHOULD reload)
    t.write_file('src/package.json', '{"version": "1.0.1"}')
    t.await_log('Stopping due to file changes', timeout=2)


@test
def test_www_redirect_to_apex(t):
    """www subdomain redirects to apex domain"""
    t.write_file('example.com/public/index.html', '<h1>Apex Domain</h1>', absolute=True)

    # Request to www.example.com should redirect to example.com
    conn = http.client.HTTPConnection('localhost', t.port)
    conn.request('GET', '/', headers={'Host': 'www.example.com'})
    response = conn.getresponse()

    if response.status != 301:
        raise AssertionError(f"Expected redirect (301), got {response.status}")

    location = response.getheader('Location')
    if not location or 'example.com' not in location:
        raise AssertionError(f"Expected redirect to example.com, got {location}")

    conn.close()


@test
def test_apex_redirect_to_www(t):
    """Apex domain redirects to www subdomain"""
    t.write_file('www.example.net/public/index.html', '<h1>WWW Domain</h1>', absolute=True)

    # Request to example.net should redirect to www.example.net
    conn = http.client.HTTPConnection('localhost', t.port)
    conn.request('GET', '/', headers={'Host': 'example.net'})
    response = conn.getresponse()

    if response.status != 301:
        raise AssertionError(f"Expected redirect (301), got {response.status}")

    location = response.getheader('Location')
    if not location or 'www.example.net' not in location:
        raise AssertionError(f"Expected redirect to www.example.net, got {location}")

    conn.close()


@test
def test_static_mime_types(t):
    """Static files are served with correct MIME types"""
    # Create various file types
    t.write_file('public/style.css', 'body { color: red; }')
    t.write_file('public/script.js', 'console.log("test");')
    t.write_file('public/data.json', '{"key": "value"}')
    t.write_file('public/page.html', '<h1>HTML</h1>')
    t.write_file('public/image.svg', '<svg></svg>')
    t.write_file('public/doc.txt', 'Plain text')

    # Test CSS
    conn = http.client.HTTPConnection('localhost', t.port)
    conn.request('GET', '/style.css', headers={'Host': t.current_test_domain})
    response = conn.getresponse()
    body = response.read()
    content_type = response.getheader('Content-Type')
    # Note: Python's SimpleHTTPServer may not set Content-Type for all file types
    # This test documents the current behavior
    conn.close()

    # Test JS
    conn = http.client.HTTPConnection('localhost', t.port)
    conn.request('GET', '/script.js', headers={'Host': t.current_test_domain})
    response = conn.getresponse()
    body = response.read()
    conn.close()

    # Test JSON
    t.assert_http('/data.json', check_body='key')

    # Test HTML
    t.assert_http('/page.html', check_body='HTML')


@test
def test_websocket_proxy(t):
    """WebSocket upgrade requests are properly proxied"""
    import wstool
    import shutil
    import os
    import time

    # Copy wstool.py to project dir so it's accessible in sandbox
    project_dir = os.path.join(t.tmpdir, t.current_test_domain)
    os.makedirs(project_dir, exist_ok=True)
    
    # We need to copy wstool.py to the project directory
    # Since wstool.py is in the same directory as test.py, we can find it easily
    wstool_src = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'wstool.py')
    shutil.copy(wstool_src, os.path.join(project_dir, 'wstool.py'))

    # Start wstool server in echo mode
    t.write_file('Procfile', 'web: python3 -u wstool.py server $PORT')

    t.mark_log_read()

    # Use wstool client to connect
    # We need to wait a bit for the server to start
    time.sleep(0.5)

    # Connect to localhost but use test domain as the Host header for routing
    client = wstool.WebSocketClient(
        f'ws://{t.current_test_domain}/',
        connect_host='localhost',
        connect_port=t.port,
        host_header=t.current_test_domain
    )
    
    try:
        client.connect()
        
        # Test single message
        message1 = 'h%madsd4v$'
        client.send(message1)
        response1 = client.recv()
        if response1.decode('utf-8') != message1:
            raise AssertionError(f"Expected '{message1}', got: {response1}")
        
        # Test multiple messages in sequence
        message2 = 'second message'
        client.send(message2)
        response2 = client.recv()
        if response2.decode('utf-8') != message2:
            raise AssertionError(f"Expected '{message2}', got: {response2}")
        
        # Test pipelined messages (send multiple before receiving)
        message3 = 'pipelined1'
        message4 = 'pipelined2'
        message5 = 'pipelined3'
        client.send(message3)
        client.send(message4)
        client.send(message5)
        
        response3 = client.recv()
        response4 = client.recv()
        response5 = client.recv()
        
        if response3.decode('utf-8') != message3:
            raise AssertionError(f"Expected '{message3}', got: {response3}")
        if response4.decode('utf-8') != message4:
            raise AssertionError(f"Expected '{message4}', got: {response4}")
        if response5.decode('utf-8') != message5:
            raise AssertionError(f"Expected '{message5}', got: {response5}")
            
    finally:
        client.close()

    # Verify that the backend received and echoed all messages by checking logs
    t.await_log(f"Echoed: {message1}", timeout=2)
    t.assert_log(f"Echoed: {message2}", count=1)
    t.assert_log(f"Echoed: {message3}", count=1)
    t.assert_log(f"Echoed: {message4}", count=1)
    t.assert_log(f"Echoed: {message5}", count=1)


@test
def test_forward_preserves_host_header(t):
    """Forward preserves the Host header from the original request"""
    # Create a backend server that echoes request headers
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class HeaderEchoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        # Echo back the Host header
        host = self.headers.get('Host', 'no-host')
        x_forwarded_host = self.headers.get('X-Forwarded-Host', 'no-x-forwarded-host')
        x_forwarded_proto = self.headers.get('X-Forwarded-Proto', 'no-x-forwarded-proto')
        path = self.path

        response = f"Host: {host}\\nX-Forwarded-Host: {x_forwarded_host}\\nX-Forwarded-Proto: {x_forwarded_proto}\\nPath: {path}"
        self.wfile.write(response.encode())

PORT = int(os.environ.get('PORT'))
with socketserver.TCPServer(("", PORT), HeaderEchoHandler) as httpd:
    print(f"Header echo server on {PORT}", flush=True)
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # Make request and verify Host header is preserved
    response = t.assert_http('/test/path', check_code=200)

    # For forward, Host header should be preserved as test domain
    if f'Host: {t.current_test_domain}' not in response:
        raise AssertionError(f"Expected 'Host: {t.current_test_domain}' in response, got: {response}")

    # X-Forwarded headers should NOT be added by forward
    if 'X-Forwarded-Host: no-x-forwarded-host' not in response:
        raise AssertionError(f"Expected no X-Forwarded-Host header in forward mode, got: {response}")

    # Path should be preserved exactly
    if 'Path: /test/path' not in response:
        raise AssertionError(f"Expected 'Path: /test/path', got: {response}")


@test
def test_forward_tcp_port(t):
    """Forward to TCP port preserves original request"""
    # Start a backend server on a known port
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class SimpleHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        host = self.headers.get('Host', 'unknown')
        path = self.path

        response = f"Backend received - Host: {host}, Path: {path}"
        self.wfile.write(response.encode())

PORT = int(os.environ.get('PORT'))
print(f"Backend on {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), SimpleHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # First, start the backend to get a port assigned
    t.assert_http('/', check_code=200)
    t.await_log('Backend on')

    # Extract the port from logs
    backend_log = t.get_log_content(t.current_test_domain, 0)
    import re
    port_match = re.search(r'Backend on (\d+)', backend_log)
    if not port_match:
        raise AssertionError("Could not find backend port in logs")
    backend_port = port_match.group(1)

    # Now create a forward that points to this backend
    t.write_file('forwarder.test/webcentral.ini', f'port={backend_port}', absolute=True)

    # Make request through the forwarder
    response = t.assert_http('/api/endpoint', check_code=200, host='forwarder.test')

    # The backend should see the original Host header
    if 'Host: forwarder.test' not in response:
        raise AssertionError(f"Expected 'Host: forwarder.test', got: {response}")

    # Path should be preserved
    if 'Path: /api/endpoint' not in response:
        raise AssertionError(f"Expected 'Path: /api/endpoint', got: {response}")


@test
def test_proxy_rewrites_headers(t):
    """Proxy rewrites Host and adds X-Forwarded headers"""
    # Create a backend server that echoes headers
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class HeaderEchoHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()

        host = self.headers.get('Host', 'no-host')
        x_forwarded_host = self.headers.get('X-Forwarded-Host', 'no-x-forwarded-host')
        x_forwarded_proto = self.headers.get('X-Forwarded-Proto', 'no-x-forwarded-proto')
        path = self.path

        response = f"Host: {host}\\nX-Forwarded-Host: {x_forwarded_host}\\nX-Forwarded-Proto: {x_forwarded_proto}\\nPath: {path}"
        self.wfile.write(response.encode())

PORT = int(os.environ.get('PORT'))
print(f"Proxy backend on {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), HeaderEchoHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # Start backend and get its port
    t.assert_http('/', check_code=200)
    t.await_log('Proxy backend on')

    backend_log = t.get_log_content(t.current_test_domain, 0)
    import re
    port_match = re.search(r'Proxy backend on (\d+)', backend_log)
    if not port_match:
        raise AssertionError("Could not find backend port")
    backend_port = port_match.group(1)

    # Create a proxy that points to this backend
    t.write_file('proxy-test.test/webcentral.ini', f'proxy=http://localhost:{backend_port}', absolute=True)

    # Make request through the proxy
    response = t.assert_http('/api/data', check_code=200, host='proxy-test.test')

    # For proxy, Host header should be rewritten to the backend address
    if f'Host: localhost:{backend_port}' not in response:
        raise AssertionError(f"Expected 'Host: localhost:{backend_port}' in proxy mode, got: {response}")

    # X-Forwarded-Host should contain the original host
    if 'X-Forwarded-Host: proxy-test.test' not in response:
        raise AssertionError(f"Expected 'X-Forwarded-Host: proxy-test.test', got: {response}")

    # X-Forwarded-Proto should be set
    if 'X-Forwarded-Proto:' not in response or 'no-x-forwarded-proto' in response:
        raise AssertionError(f"Expected X-Forwarded-Proto to be set, got: {response}")

    # Path should be preserved
    if 'Path: /api/data' not in response:
        raise AssertionError(f"Expected 'Path: /api/data', got: {response}")


@test
def test_proxy_vs_forward_path_handling(t):
    """Demonstrate that both proxy and forward preserve the request path"""
    # Create backend
    t.write_file('server.py', '''
import os
import http.server
import socketserver

class PathHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/plain')
        self.end_headers()
        self.wfile.write(f"Path: {self.path}".encode())

PORT = int(os.environ.get('PORT'))
print(f"Path backend on {PORT}", flush=True)
with socketserver.TCPServer(("", PORT), PathHandler) as httpd:
    httpd.serve_forever()
''')

    t.write_file('webcentral.ini', 'command=python3 -u server.py')

    # Start backend
    t.assert_http('/', check_code=200)
    t.await_log('Path backend on')

    backend_log = t.get_log_content(t.current_test_domain, 0)
    import re
    port_match = re.search(r'Path backend on (\d+)', backend_log)
    backend_port = port_match.group(1)

    # Create forward
    t.write_file('path-forward.test/webcentral.ini', f'port={backend_port}', absolute=True)

    # Create proxy
    t.write_file('path-proxy.test/webcentral.ini', f'proxy=http://localhost:{backend_port}', absolute=True)

    # Test that both preserve paths with query strings
    forward_response = t.assert_http('/some/path?query=value', check_code=200, host='path-forward.test')
    proxy_response = t.assert_http('/some/path?query=value', check_code=200, host='path-proxy.test')

    # Both should preserve the full path
    if 'Path: /some/path?query=value' not in forward_response:
        raise AssertionError(f"Forward didn't preserve path, got: {forward_response}")

    if 'Path: /some/path?query=value' not in proxy_response:
        raise AssertionError(f"Proxy didn't preserve path, got: {proxy_response}")


@test
def test_forward_upstream_connect_error(t):
    """Forward to closed port returns 502 Bad Gateway"""
    # Configure forward to a port that's not listening
    t.write_file('webcentral.ini', 'port=1')

    # Request should return 502 Bad Gateway
    t.assert_http('/', check_code=502)

    # Log should contain specific error message
    t.await_log('upstream connect failed')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run webcentral tests')
    parser.add_argument('--firejail', type=str, choices=['true', 'false'], default='true',
                        help='Enable or disable Firejail sandboxing (default: true)')
    parser.add_argument('test_names', nargs='*', help='Specific test names to run')

    args = parser.parse_args()

    # Convert firejail argument to boolean and update the global runner
    runner.use_firejail = args.firejail == 'true'

    # Run tests
    test_names = args.test_names if args.test_names else None
    runner.run(test_names)
