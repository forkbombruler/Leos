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
- Duration seconds: `0.69`
- Truncated: `False`

### stdout

```text
Run started:2026-05-15 08:16:25.598243+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 6637
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
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:197
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:198
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:199
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:200
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:201
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:203
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:205
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:206
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:207
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:208
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:209
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:211
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:213
[tester]	WARNING	nosec encountered (B108), but no failed test on file src/leos_agent/sandbox.py:215

```

