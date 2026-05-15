# Security Scan

- Bandit exit code: `0`
- Bandit status: `passed`
- High issues: 0
- Medium issues: 0
- Low issues: 0
- `# nosec` count in key source files: 5

Known warnings:
- Bandit output is a static scan and does not prove runtime isolation.
- Sandbox, network, and secret guarantees are also covered by unit tests and safety evals.

# Bandit Raw Output

## bandit

- Command: `bandit -r src`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `0.715`
- Truncated: `False`

### stdout

```text
Run started:2026-05-15 10:42:49.895909+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 6659
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 15

Run metrics:
	Total issues (by severity):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
	Total issues (by confidence):
		Undefined: 0
		Low: 0
		Medium: 0
		High: 0
Files skipped (0):

```

### stderr

```text
[main]	INFO	profile include tests: None
[main]	INFO	profile exclude tests: None
[main]	INFO	cli include tests: None
[main]	INFO	cli exclude tests: None
[main]	INFO	running on Python 3.14.4
[manager]	WARNING	Test in comment: container is not a test name or id, ignoring
[manager]	WARNING	Test in comment: internal is not a test name or id, ignoring
[manager]	WARNING	Test in comment: tmpfs is not a test name or id, ignoring
[manager]	WARNING	Test in comment: mount is not a test name or id, ignoring
[manager]	WARNING	Test in comment: target is not a test name or id, ignoring
[manager]	WARNING	Test in comment: not is not a test name or id, ignoring
[manager]	WARNING	Test in comment: a is not a test name or id, ignoring
[manager]	WARNING	Test in comment: host is not a test name or id, ignoring
[manager]	WARNING	Test in comment: temp is not a test name or id, ignoring
[manager]	WARNING	Test in comment: path is not a test name or id, ignoring
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: constructed is not a test name or id, ignoring
[manager]	WARNING	Test in comment: without is not a test name or id, ignoring
[manager]	WARNING	Test in comment: shell is not a test name or id, ignoring
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:217
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:218
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:219
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:220
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:221
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:223
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:224
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:225
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:226
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:227
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:229
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:231
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:233
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:235

```

