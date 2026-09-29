"""Fake interactive process tests; no agent account or configuration."""
import os
import sys

from hookconf.pty import Exchange, run, visible


def test_expect_answers_two_prompts(tmp_path):
    code = ("import sys\n"
            "print('Proceed? [y/n]', flush=True)\n"
            "first = sys.stdin.readline().strip()\n"
            "print('Remember grant? [y/n]', flush=True)\n"
            "second = sys.stdin.readline().strip()\n"
            "print('RESULT:' + first + ',' + second, flush=True)\n")
    result = run([sys.executable, "-u", "-c", code], cwd=str(tmp_path),
                 env=dict(os.environ, PYTHONIOENCODING="utf-8"),
                 exchanges=[Exchange(r"Proceed\? \[y/n\]", "y\r"),
                            Exchange(r"Remember grant\? \[y/n\]", "n\r")], timeout_s=12)
    assert result.backend in ("windows-conpty", "posix-pty")
    assert not result.timed_out and not result.pending
    assert "RESULT:y,n" in visible(result.output)


def test_unmatched_prompt_does_not_send_an_answer(tmp_path):
    code = "import sys; print('Different prompt', flush=True); sys.stdin.readline()"
    result = run([sys.executable, "-u", "-c", code], cwd=str(tmp_path),
                 env=dict(os.environ, PYTHONIOENCODING="utf-8"),
                 exchanges=[Exchange(r"Approve exactly this action\?", "y\r", timeout_s=0.8)], timeout_s=2)
    assert result.timed_out and result.pending == [r"Approve exactly this action\?"]
    assert "Different prompt" in visible(result.output)


def test_stop_after_observed_completion(tmp_path):
    code = "import time; print('HK-DONE', flush=True); time.sleep(30)"
    result = run([sys.executable, "-u", "-c", code], cwd=str(tmp_path), env=dict(os.environ),
                 exchanges=[Exchange(r"HK-DONE", "", stop=True)], timeout_s=3)
    assert result.matched == ["HK-DONE"]
    assert result.pending == [] and not result.timed_out
