# Rust Translation Status

## Completed

1. **All Go code translated to Rust** - The entire webcentral codebase has been translated from Go to Rust
2. **Compiler warnings fixed** - All unused imports and variables addressed
3. **Code compiles successfully** - Both debug and release builds work
4. **Firejail installed** - Sandboxing support is available
5. **Basic proxy implementation** - HTTP proxy logic translated (with known issue)
6. **Project lifecycle management** - State machine converted to Rust with Mutex-based locking

## Known Issues

### Critical: Application Proxying Deadlock

**Status**: Identified but not yet fixed

**Issue**: When an HTTP request comes in for an application project, the request hangs in `ensure_started()` and never completes. The application process starts successfully (visible in logs), but the request handler never proxies to it.

**Root Cause**: The `ensure_started()` function waits in a loop for the state to transition to `Running`, but there appears to be a synchronization issue where:
1. The application starts successfully
2. Port becomes reachable
3. State should transition to `Running`
4. But the waiting loop in `ensure_started()` never sees this transition

**Debug Trace**:
```
handle_http: got request for /
handle_http: domain=testapp.local
handle_http: project_dir=/tmp/test-webcentral/testapp.local
handle_http: calling route_request
route_request: start
route_request: getting project
route_request: got project, calling handle
project.handle_impl: start
project.handle_impl: determining handler
project.handle_impl: application
handle_application: ensuring app started
[HANGS HERE - never reaches "handle_application: getting port"]
```

**Application Log Shows**:
```
22:47:35 starting on port 36643
22:47:35 starting command: ...
22:47:35 [out] Serving HTTP on 0.0.0.0 port 36643 ...
22:47:35 reachable on port 36643
```

**Fix Needed**: The `start_process()` function spawns a background task that sets the state to `Running`, but the `ensure_started()` loop may not be seeing this update. Possible solutions:
1. Use a condition variable or channel to signal state changes
2. Review the locking strategy - may need to release and reacquire lock in the wait loop
3. Simplify the state machine - consider using channels for state transitions

## Not Yet Implemented

1. **ACME Certificate Acquisition** - instant-acme integration skeleton exists but not functional
2. **TLS/SNI Handling** - HTTPS server accepts connections but doesn't use TLS (runs as HTTP)
3. **Socket forwarding** - Unix socket proxy support not tested

## Test Results

- **Static file serving**: ✓ PASSING (2/2 tests)
- **Simple application**: ✗ FAILING (hangs indefinitely)
- **Remaining tests**: Not run due to application proxy issue

## Next Steps

1. **Fix the deadlock in `ensure_started()`** - This is blocking all application-based tests
2. **Remove debug logging** once tests pass
3. **Implement ACME certificate acquisition** using instant-acme
4. **Add TLS/SNI support** for HTTPS connections
5. **Run full test suite** and fix any remaining issues
6. **Performance optimization** and code simplification

## Code Quality

The current Rust implementation:
- Uses idiomatic Rust patterns (Arc, Mutex, tokio async)
- Proper error handling with Result types
- Clean separation of concerns
- Could benefit from simplification once functional
