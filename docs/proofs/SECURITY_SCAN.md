# Security Scan

- Bandit exit code: `0`
- Bandit status: `passed`
- High issues: 0
- Medium issues: 0
- Low issues: 0
- `# nosec` count in key source files: 7

Known warnings:
- Bandit output is a static scan and does not prove runtime isolation.
- Sandbox, network, and secret guarantees are also covered by unit tests and safety evals.

# Bandit Raw Output

## bandit

- Command: `bandit -r src`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `0.986`
- Truncated: `False`

### stdout

```text
Run started:2026-05-19 09:47:34.186248+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 9718
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 18

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
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:230
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:231
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:232
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:233
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:234
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:236
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:237
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:238
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:239
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:240
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:242
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:244
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:246
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:248

```

