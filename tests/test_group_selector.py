"""
Test cases for the group_selector module.
This module contains unit tests for the following functionalities:
- Separating syscall arguments from formatted strings.
- Parsing a groups file to extract syscall numbers, parameters, and arguments.
- Matching syscalls with their corresponding parameters and arguments.
"""
import pytest
from user_tool import group_selector

@pytest.fixture
def mock_groups_file(tmp_path):
    """
    Create a mock groups file for testing.
    """
    content = """
    g:group1
        1
        2
    }
    p:parameter1
        key1=value1
        key2=value2
    ]
    a:arg1
        value1
        value2
    )
    """
    file_path = tmp_path / "groups"
    file_path.write_text(content)
    return str(file_path)

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
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})

    syscall_nr = 2
    argument = ["/root"]

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

