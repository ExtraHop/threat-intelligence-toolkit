"""/tests/test_threat_intelligence_toolkit.py"""

import pytest
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from threat_intelligence_toolkit import (
    strip_non_alphanum,
    str_to_bool,
    parse_command_line_args,
    threatcollection_api_request,
    generate_stix_file
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


def test_threatcollection_api_request_success(tmp_path: Path) -> None:
    # Prepare test data
    eh_host = 'otx.alienvault.com'
    eh_apikey = 'test_api_key'
    eh_verify_cert = True
    threatcollection_name = 'example_collection'
    file_name = 'test_file.tgz'
    file_content = b'Test content'
    verbose = False

    # Create a temporary file
    file_path = tmp_path / file_name
    with open(file_path, 'wb') as f:
        f.write(file_content)

    # Mock requests.put to return a successful response
    with patch('threat_intelligence_toolkit.requests.put') as mock_put:
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = 'Success'
        mock_put.return_value = mock_response

        # Call the function
        threatcollection_api_request(
            eh_host,
            eh_apikey,
            eh_verify_cert,
            threatcollection_name,
            file_name,
            str(file_path),
            verbose
        )

        # Check that requests.put was called with the correct parameters
        mock_put.assert_called_once()
        args, kwargs = mock_put.call_args

        expected_url = f'https://{eh_host}/api/v1/threatcollections/~{strip_non_alphanum(threatcollection_name)}'
        assert args[0] == expected_url
        assert kwargs['headers']['Authorization'] == f'ExtraHop apikey={eh_apikey}'
        assert kwargs['verify'] == eh_verify_cert
        assert 'files' in kwargs
        assert 'data' in kwargs
        # Ensure the file was read correctly
        uploaded_file = kwargs['files']['file']
        assert uploaded_file[0] == file_name  # Filename
        # The file content is not accessible since file is opened in binary mode in context manager


def test_threatcollection_api_request_failure(tmp_path: Path) -> None:
    # Prepare test data
    eh_host = 'otx.alienvault.com'
    eh_apikey = 'test_api_key'
    eh_verify_cert = True
    threatcollection_name = 'example_collection'
    file_name = 'test_file.tgz'
    file_content = b'Test content'
    verbose = False

    # Create a temporary file
    file_path = tmp_path / file_name
    with open(file_path, 'wb') as f:
        f.write(file_content)

    # Mock requests.put to return a failure response
    with patch('threat_intelligence_toolkit.requests.put') as mock_put:
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = '{"detail": "endpoint not found"}'
        mock_put.return_value = mock_response

        # Call the function and expect it to raise a ValueError
        with pytest.raises(ValueError) as excinfo:
            threatcollection_api_request(
                eh_host,
                eh_apikey,
                eh_verify_cert,
                threatcollection_name,
                file_name,
                str(file_path),
                verbose
            )

        assert 'Non-200 status code from ExtraHop API request' in str(excinfo.value)


def test_threatcollection_api_request_exception(tmp_path: Path) -> None:
    # Prepare test data
    eh_host = 'otx.alienvault.com'
    eh_apikey = 'test_api_key'
    eh_verify_cert = True
    threatcollection_name = 'example_collection'
    file_name = 'test_file.tgz'
    file_content = b'Test content'
    verbose = False

    # Create a temporary file
    file_path = tmp_path / file_name
    with open(file_path, 'wb') as f:
        f.write(file_content)

    # Mock requests.put to raise an exception
    with patch('threat_intelligence_toolkit.requests.put') as mock_put:
        mock_put.side_effect = Exception('Connection error')

        # Call the function and expect it to raise the same exception
        with pytest.raises(Exception) as excinfo:
            threatcollection_api_request(
                eh_host,
                eh_apikey,
                eh_verify_cert,
                threatcollection_name,
                file_name,
                str(file_path),
                verbose
            )

        assert 'Connection error' in str(excinfo.value)


def test_generate_stix_file_with_local_file(tmp_path: Path) -> None:
    # Prepare test data
    input_file = tmp_path / 'input.txt'
    input_content = '192.168.1.1\n10.0.0.0/24\ninvalid_ip\n#comment\n\n'
    input_file.write_text(input_content)

    list_type = 'ip'
    delimiter = '\n'
    list_name = 'TestList'
    tc_name = 'TestCollection'
    tmp_dir = tmp_path / 'output'
    tmp_dir.mkdir()
    validate = False
    verbose = False

    # Call the function
    generate_stix_file(
        str(input_file),
        list_type,
        delimiter,
        list_name,
        tc_name,
        str(tmp_dir),
        validate,
        verbose
    )

    # Check that the STIX file was created
    stix_files = list(tmp_dir.glob('*.stix'))
    assert len(stix_files) == 1

    # Optionally, read and inspect the content of the STIX file
    stix_file = stix_files[0]
    stix_content = stix_file.read_bytes()
    assert b'192.168.1.1' in stix_content
    assert b'10.0.0.0/24' in stix_content
    assert b'invalid_ip' not in stix_content  # Should be skipped
    assert b'#comment' not in stix_content    # Should be skipped


def test_generate_stix_file_with_url_input(tmp_path: Path) -> None:
    # Prepare test data
    input_file = 'http://example.com/input.txt'
    input_content = 'example.com\ninvalid_domain\n#comment\n\n'

    list_type = 'domain'
    delimiter = '\n'
    list_name = 'TestList'
    tc_name = 'TestCollection'
    tmp_dir = tmp_path / 'output'
    tmp_dir.mkdir()
    validate = False
    verbose = False

    # Mock requests.get to return the input_content
    with patch('threat_intelligence_toolkit.requests.get') as mock_get:
        mock_response = MagicMock()
        mock_response.text = input_content
        mock_get.return_value = mock_response

        # Call the function
        generate_stix_file(
            input_file,
            list_type,
            delimiter,
            list_name,
            tc_name,
            str(tmp_dir),
            validate,
            verbose
        )

    # Check that the STIX file was created
    stix_files = list(tmp_dir.glob('*.stix'))
    assert len(stix_files) == 1

    # Optionally, read and inspect the content of the STIX file
    stix_file = stix_files[0]
    stix_content = stix_file.read_bytes()
    assert b'example.com' in stix_content
    assert b'invalid_domain' in stix_content or not validate  # Included if not validating
    assert b'#comment' not in stix_content    # Should be skipped


def test_generate_stix_file_with_validation(tmp_path: Path) -> None:
    # Prepare test data
    input_file = tmp_path / 'input.txt'
    input_content = 'https://valid.url\ninvalid_url\n#comment\n\n'
    input_file.write_text(input_content)

    list_type = 'url'
    delimiter = '\n'
    list_name = 'TestList'
    tc_name = 'TestCollection'
    tmp_dir = tmp_path / 'output'
    tmp_dir.mkdir()
    validate = True
    verbose = False

    # Call the function
    generate_stix_file(
        str(input_file),
        list_type,
        delimiter,
        list_name,
        tc_name,
        str(tmp_dir),
        validate,
        verbose
    )

    # Check that the STIX file was created
    stix_files = list(tmp_dir.glob('*.stix'))
    assert len(stix_files) == 1

    # Optionally, read and inspect the content of the STIX file
    stix_file = stix_files[0]
    stix_content = stix_file.read_bytes()
    assert b'https://valid.url' in stix_content
    assert b'invalid_url' not in stix_content  # Should be skipped due to validation
    assert b'#comment' not in stix_content    # Should be skipped


def test_generate_stix_file_with_ipv6(tmp_path: Path) -> None:
    # Prepare test data
    input_file = tmp_path / 'input.txt'
    input_content = '2001:0db8:85a3:0000:0000:8a2e:0370:7334\ninvalid_ipv6\n\n'
    input_file.write_text(input_content)

    list_type = 'ip'
    delimiter = '\n'
    list_name = 'TestList'
    tc_name = 'TestCollection'
    tmp_dir = tmp_path / 'output'
    tmp_dir.mkdir()
    validate = False
    verbose = False

    # Call the function
    generate_stix_file(
        str(input_file),
        list_type,
        delimiter,
        list_name,
        tc_name,
        str(tmp_dir),
        validate,
        verbose
    )

    # Check that the STIX file was created
    stix_files = list(tmp_dir.glob('*.stix'))
    assert len(stix_files) == 1

    # Read and inspect the content of the STIX file
    stix_file = stix_files[0]
    stix_content = stix_file.read_bytes()
    assert b'2001:0db8:85a3:0000:0000:8a2e:0370:7334' in stix_content
    assert b'invalid_ipv6' not in stix_content  # Should be skipped
