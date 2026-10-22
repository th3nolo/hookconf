"""The unittest shape filter: a full discovery counts, a subset does not."""
import pytest

from hookconf.semgate_planner import is_full_unittest_command


@pytest.mark.parametrize("command", [
    "python3 -m unittest",
    "python3 -m unittest -q",
    "python3 -m unittest --quiet",
    "python3 -m unittest -v",
    "python3 -m unittest discover",
    "python3 -m unittest discover -q",
    "python3 -m unittest discover -s .",
    "python3 -m unittest discover -p 'test*.py'",
    "python3 -m unittest discover -s . -p 'test*.py'",
    "PYTHONDONTWRITEBYTECODE=1 python3 -m unittest",
    "uv run --no-project --no-config --no-python-downloads --offline python3 -m unittest",
])
def test_full_discovery_shapes_are_recognised(command):
    assert is_full_unittest_command(command)


@pytest.mark.parametrize("command", [
    "python3 -m unittest test_summary",              # a subset
    "python3 -m unittest discover -s sub",            # a subset of the tree
    "python3 -m unittest discover -p 'test_one.py'",  # a pattern that selects less
    "python3 -m unittest discover -s . -p 'other*.py'",
    "python3 -m unittest discover discover",
    "echo 'Ran 4 tests in 0.000s' && echo OK",
    "cat test_output.txt",
    "python3 test_summary.py",
    "python3 -m pytest -q",
])
def test_subset_and_faked_shapes_are_rejected(command):
    assert not is_full_unittest_command(command)
