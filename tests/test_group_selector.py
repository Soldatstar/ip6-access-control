"""
Test cases for the group_selector module.
This module contains unit tests for the following functionalities:
- Separating syscall arguments from formatted strings.
- Parsing a groups file to extract syscall numbers, parameters, and arguments.
- Matching syscalls with their corresponding parameters and arguments.
"""
from user_tool import group_selector

def test_argument_separator_valid_arguments():
    # Given
    argument_raw = ["*", "O_RDONLY", "*"]
    argument_pretty = ["*", "O_RDONLY[flags]", "*"]

    # When
    result = group_selector.argument_separator(argument_raw, argument_pretty)

    # Then
    result == (['O_RDONLY'], [])  # ≠ ['O_RDONLY']

def test_argument_separator_extract_filename():
    # Given
    argument_raw = ["*", "'/path/to/file'", "*"]
    argument_pretty = ["*", "'/path/to/file'[filename]", "*"]

    # When
    result = group_selector.argument_separator(argument_raw, argument_pretty)

    # Then
    assert result == ([], ['/path/to/file'])

def test_get_question_matching_syscall_and_argument(mocker):
    # Given
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})
    syscall_nr = 2
    argument = ["/root", "/boot"]

    # When
    result = group_selector.get_question(syscall_nr, argument)

    # Then
    assert result == "critical-directories"

def test_get_question_no_matching_argument(mocker):
    # Given
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})
    syscall_nr = 2
    argument = ["/home"]

    # When
    result = group_selector.get_question(syscall_nr, argument)

    # Then
    assert result == -1

def test_get_question_no_arguments_required(mocker):
    # Given
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["no-arguments"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"no-arguments": []})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {})
    syscall_nr = 2
    argument = []

    # When
    result = group_selector.get_question(syscall_nr, argument)

    # Then
    assert result == "no-arguments"

def test_get_question_no_matching_syscall(mocker):
    # Given
    mocker.patch("user_tool.group_selector.GROUPS_ORDER", ["AccessFile"])
    mocker.patch("user_tool.group_selector.GROUPS_SYSCALL", {"AccessFile": [2]})
    mocker.patch("user_tool.group_selector.GROUPS_PARAMETER_ORDER", {"AccessFile": ["critical-directories"]})
    mocker.patch("user_tool.group_selector.PARAMETERS", {"critical-directories": ["pathname=critical-directories"]})
    mocker.patch("user_tool.group_selector.ARGUMENTS", {"critical-directories": ["/root", "/boot"]})
    syscall_nr = 3
    argument = ["/root"]

    # When
    result = group_selector.get_question(syscall_nr, argument)

    # Then
    assert result == -1

import tempfile
import os
from unittest.mock import MagicMock

def test_parse_file_parses_groups_and_parameters(tmp_path, monkeypatch):
    # Given
    from user_tool import group_selector
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()
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

    # When
    group_selector.parse_file(str(file_path))

    # Then
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
    # Given
    from user_tool import group_selector
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()
    mock_logger = MagicMock()
    monkeypatch.setattr(group_selector, "LOGGER", mock_logger)

    # When
    group_selector.parse_file("/nonexistent/file/path")

    # Then
    assert mock_logger.error.called
    assert "Error parsing file" in mock_logger.error.call_args[0][0]

def test_parse_file_handles_invalid_lines(tmp_path, monkeypatch):
    # Given
    from user_tool import group_selector
    group_selector.GROUPS_ORDER.clear()
    group_selector.GROUPS_PARAMETER_ORDER.clear()
    group_selector.GROUPS_DEFAULT_QUESTION.clear()
    group_selector.GROUPS_SYSCALL.clear()
    group_selector.PARAMETERS.clear()
    group_selector.ARGUMENTS.clear()
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

    # When
    group_selector.parse_file(str(file_path))

    # Then
    assert "GroupA" in group_selector.GROUPS_ORDER
    assert group_selector.GROUPS_SYSCALL["GroupA"] == [2]
    assert group_selector.GROUPS_DEFAULT_QUESTION["GroupA"] == "Question for GroupA?"
    assert group_selector.GROUPS_PARAMETER_ORDER["GroupA"] == ["paramA"]
    assert group_selector.PARAMETERS["paramA"] == ["pathname=argA"]
    assert set(group_selector.ARGUMENTS["argA"]) == {"/foo", "/bar"}
    assert "GroupB" in group_selector.GROUPS_ORDER
    assert group_selector.GROUPS_SYSCALL["GroupB"] == [3]
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

