"""/tests/test_threat_intelligence_toolkit.py"""

import pytest
import sys
from threat_intelligence_toolkit import (
    strip_non_alphanum,
    str_to_bool,
    parse_command_line_args
)

def test_strip_non_alphanum() -> None:
    assert strip_non_alphanum("abc123") == "abc123"
    assert strip_non_alphanum("abc!@#123") == "abc123"
    assert strip_non_alphanum("!@#") == ""
    assert strip_non_alphanum("abc def") == "abcdef"
    assert strip_non_alphanum("a$b%c^") == "abc"

def test_str_to_bool() -> None:
    assert str_to_bool("True") is True
    assert str_to_bool("false") is False
    assert str_to_bool("Yes") is True
    assert str_to_bool("No") is False
    assert str_to_bool("1") is True
    assert str_to_bool("0") is False
    assert str_to_bool("unexpected") is True  # Default behavior

def test_parse_command_line_args_basic() -> None:
    test_args = [
        'threat_intelligence_toolkit.py',
        '-o', 'output_dir',
        '-tc', 'TestCollection'
    ]
    sys.argv = test_args
    args = parse_command_line_args()
    assert args.output_dir == 'output_dir'
    assert args.threat_collection_name == 'TestCollection'

def test_parse_command_line_args_generate_stix() -> None:
    test_args = [
        'threat_intelligence_toolkit.py',
        '-o', 'output_dir',
        '-tc', 'TestCollection',
        '--generate-stix',
        '--input-file', 'input.txt',
        '--list-type', 'ip'
    ]
    sys.argv = test_args
    args = parse_command_line_args()
    assert args.generate_stix is True
    assert args.input_file == 'input.txt'
    assert args.list_type == 'ip'

def test_parse_command_line_args_missing_generate_stix_args() -> None:
    test_args = [
        'threat_intelligence_toolkit.py',
        '-o', 'output_dir',
        '-tc', 'TestCollection',
        '--generate-stix'
    ]
    sys.argv = test_args
    with pytest.raises(SystemExit):
        parse_command_line_args()
