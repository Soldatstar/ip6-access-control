"""
Test cases for the group_selector module.
This module contains unit tests for the following functionalities:
- Separating syscall arguments from formatted strings.
- Parsing a groups file to extract syscall numbers, parameters, and arguments.
- Matching syscalls with their corresponding parameters and arguments.
"""
from user_tool import group_selector

def test_argument_separator_valid_arguments():
    """
    Test separating valid arguments.
    """
    # Given: Raw and formatted arguments
    argument_raw = ["*", "O_RDONLY", "*"]
    argument_pretty = ["*", "O_RDONLY[flags]", "*"]

    # When: The argument_separator function is called
    result = group_selector.argument_separator(argument_raw, argument_pretty)

    # Then: The correct arguments should be extracted
    assert result == ["O_RDONLY"]

def test_argument_separator_extract_filename():
    """
    Test extracting filename from formatted arguments.
    """
    # Given: Raw and formatted arguments with a filename
    argument_raw = ["*", "'/path/to/file'", "*"]
    argument_pretty = ["*", "'/path/to/file'[filename]", "*"]

    # When: The argument_separator function is called
    result = group_selector.argument_separator(argument_raw, argument_pretty)

    # Then: The correct filename should be extracted
    assert result == ["/path/to/file"]

def test_get_question_matching_syscall_and_argument(mocker):
    """
    Test when a matching syscall and argument exist.
    """
    # Given: Mocked data for groups, syscalls, parameters, and arguments
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    # The key must be the value after '=', i.e., "critical-directories"
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})

    syscall_nr = 2
    argument = ["/root", "/boot"]  # Must be a superset of parameter values

    # When: The get_question function is called
    result = group_selector.get_question(syscall_nr, argument)

    # Then: The correct parameter should be returned
    assert result == "critical-directories"


def test_get_question_no_matching_argument(mocker):
    """
    Test when a matching syscall exists but the argument does not match.
    """
    # Given: Mocked data for groups, syscalls, parameters, and arguments
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})

    syscall_nr = 2
    argument = ["/home"]

    # When: The get_question function is called
    result = group_selector.get_question(syscall_nr, argument)

    # Then: -1 should be returned as no matching parameter is found
    assert result == -1


def test_get_question_no_arguments_required(mocker):
    """
    Test when a matching syscall exists and no arguments are required.
    """
    # Given: Mocked data for groups, syscalls, parameters, and arguments
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["no-arguments"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"no-arguments": []})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {})

    syscall_nr = 2
    argument = []

    # When: The get_question function is called
    result = group_selector.get_question(syscall_nr, argument)

    # Then: The correct parameter should be returned
    assert result == "no-arguments"


def test_get_question_no_matching_syscall(mocker):
    """
    Test when no matching syscall exists.
    """
    # Given: Mocked data for groups, syscalls, parameters, and arguments
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})

    syscall_nr = 3
    argument = ["/root"]

    # When: The get_question function is called
    result = group_selector.get_question(syscall_nr, argument)

    # Then: -1 should be returned as no matching syscall is found
    assert result == -1

import tempfile
import os
from unittest.mock import MagicMock  # <-- Add this import

def test_parse_file_parses_groups_and_parameters(tmp_path, monkeypatch):
    """
    Test parse_file parses a groups file and populates global structures.
    """
    from user_tool import group_selector

    # Reset globals before test
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()

    # Create a minimal valid groups file
    content = """
g:TestGroup {
2
d:Test question?
p:critical-param?
pathname=critical-arg
]
}
a:critical-arg
/root
/boot
)
"""
    file_path = tmp_path / "groups"
    file_path.write_text(content)

    group_selector.parse_file(str(file_path))

    # Check that the group and parameter structures are populated
    assert "TestGroup" in group_selector.GROUPS_ORDER
    assert "TestGroup" in group_selector.GROUPS_SYSCALL
    assert group_selector.GROUPS_SYSCALL["TestGroup"] == [2]
    assert group_selector.GROUPS_DEFAULT_QUESTION["TestGroup"] == "Test question?"
    assert "TestGroup" in group_selector.GROUPS_PARAMETER_ORDER
    assert group_selector.GROUPS_PARAMETER_ORDER["TestGroup"] == ["critical-param"]
    assert "critical-param" in group_selector.PARAMETERS
    assert group_selector.PARAMETERS["critical-param"] == ["pathname=critical-arg"]
    assert "critical-arg" in group_selector.ARGUMENTS
    assert set(group_selector.ARGUMENTS["critical-arg"]) == {"/root", "/boot"}

def test_parse_file_handles_missing_file(monkeypatch):
    """
    Test parse_file handles missing file gracefully.
    """
    from user_tool import group_selector

    # Reset globals before test
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()

    # Patch LOGGER to capture error
    mock_logger = MagicMock()
    monkeypatch.setattr(group_selector, "LOGGER", mock_logger)

    group_selector.parse_file("/nonexistent/file/path")
    # Should log an error
    assert mock_logger.error.called
    assert "Error parsing file" in mock_logger.error.call_args[0][0]

def test_parse_file_handles_invalid_lines(tmp_path, monkeypatch):
    """
    Test parse_file handles invalid lines and still parses valid blocks.
    """
    from user_tool import group_selector

    # Reset globals before test
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()

    # Create a groups file with some invalid lines
    content = """
g:GroupA {
2
d:Question for GroupA?
p:paramA?
pathname=argA
]
}
a:argA
/foo
/bar
)
INVALID LINE
g:GroupB {
3
}
"""
    file_path = tmp_path / "groups_invalid"
    file_path.write_text(content)

    group_selector.parse_file(str(file_path))

    # GroupA should be parsed correctly
    assert "GroupA" in group_selector.GROUPS_ORDER
    assert group_selector.GROUPS_SYSCALL["GroupA"] == [2]
    assert group_selector.GROUPS_DEFAULT_QUESTION["GroupA"] == "Question for GroupA?"
    assert group_selector.GROUPS_PARAMETER_ORDER["GroupA"] == ["paramA"]
    assert group_selector.PARAMETERS["paramA"] == ["pathname=argA"]
    assert set(group_selector.ARGUMENTS["argA"]) == {"/foo", "/bar"}
    # GroupB should also be parsed, even if minimal
    assert "GroupB" in group_selector.GROUPS_ORDER
    assert group_selector.GROUPS_SYSCALL["GroupB"] == [3]

