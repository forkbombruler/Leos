# Security Scan

## bandit

- Command: `bandit -r src`
- Exit code: `0`
- Status: `passed`
- Duration seconds: `0.654`
- Started: `2026-05-15T10:22:50Z`
- Finished: `2026-05-15T10:22:50Z`

### stdout

```text
Run started:2026-05-15 10:22:50.786677+00:00

Test results:
	No issues identified.

Code scanned:
	Total lines of code: 6564
	Total lines skipped (#nosec): 0
	Total potential issues skipped due to specifically being disabled (e.g., #nosec BXXX): 13

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
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: only is not a test name or id, ignoring
[manager]	WARNING	Test in comment: subprocess is not a test name or id, ignoring
[manager]	WARNING	Test in comment: execution is not a test name or id, ignoring
[manager]	WARNING	Test in comment: for is not a test name or id, ignoring
[manager]	WARNING	Test in comment: local is not a test name or id, ignoring
[manager]	WARNING	Test in comment: dev is not a test name or id, ignoring
[manager]	WARNING	Test in comment: tools is not a test name or id, ignoring
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: only is not a test name or id, ignoring
[manager]	WARNING	Test in comment: git is not a test name or id, ignoring
[manager]	WARNING	Test in comment: invocation is not a test name or id, ignoring
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: only is not a test name or id, ignoring
[manager]	WARNING	Test in comment: test is not a test name or id, ignoring
[manager]	WARNING	Test in comment: command is not a test name or id, ignoring
[manager]	WARNING	Test in comment: scheme is not a test name or id, ignoring
[manager]	WARNING	Test in comment: checked is not a test name or id, ignoring
[manager]	WARNING	Test in comment: by is not a test name or id, ignoring
[manager]	WARNING	Test in comment: tool is not a test name or id, ignoring
[manager]	WARNING	Test in comment: proof is not a test name or id, ignoring
[manager]	WARNING	Test in comment: generation is not a test name or id, ignoring
[manager]	WARNING	Test in comment: runs is not a test name or id, ignoring
[manager]	WARNING	Test in comment: explicit is not a test name or id, ignoring
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: commands is not a test name or id, ignoring
[manager]	WARNING	Test in comment: explicit is not a test name or id, ignoring
[manager]	WARNING	Test in comment: argv is not a test name or id, ignoring
[manager]	WARNING	Test in comment: intentional is not a test name or id, ignoring
[manager]	WARNING	Test in comment: subprocess is not a test name or id, ignoring
[manager]	WARNING	Test in comment: sandboxing is not a test name or id, ignoring
[manager]	WARNING	Test in comment: workspace is not a test name or id, ignoring
[manager]	WARNING	Test in comment: scoped is not a test name or id, ignoring
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
