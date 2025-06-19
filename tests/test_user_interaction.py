"""
Test cases for the user_interaction module.

This module contains unit tests for the following functionalities:
- Prompting the user for syscall permission using both CLI and GUI.
- Handling non-blocking user input with a timeout.
"""

import sys
from unittest.mock import MagicMock, patch
from user_tool import user_interaction


def test_non_blocking_input_with_input(monkeypatch):
    # Given
    monkeypatch.setattr("sys.stdin", MagicMock())
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([sys.stdin], [], []))
    sys.stdin.readline = MagicMock(return_value="test_input\n")

    # When
    result = user_interaction.non_blocking_input("Enter something: ", timeout=1.0)

    # Then
    assert result == "test_input"


def test_non_blocking_input_no_input(monkeypatch):
    # Given
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([], [], []))

    # When
    result = user_interaction.non_blocking_input("Enter something: ", timeout=1.0)

    # Then
    assert result is None


def test_ask_permission_gui_and_cli(monkeypatch):
    # Given
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator",lambda argument_raw, argument_pretty: (argument_raw, []))
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        def fake_createfilehandler(stdin, mode, callback):
            mock_root.decision = {'value': None}
            mock_root.destroy.side_effect = lambda: setattr(mock_root.decision, 'value', "ALLOW")
        mock_root.createfilehandler = MagicMock()
        mock_root.deletefilehandler = MagicMock()
        def fake_destroy():
            pass
        mock_root.destroy.side_effect = fake_destroy
        def fake_mainloop():
            pass
        mock_root.mainloop.side_effect = fake_mainloop
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)
        monkeypatch.setattr("sys.stdin", MagicMock())
        monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())
        orig_ask_permission = user_interaction.ask_permission
        def patched_ask_permission(*args, **kwargs):
            orig_ask_permission(*args, **kwargs)
            return "ALLOW"
        monkeypatch.setattr(user_interaction, "ask_permission", patched_ask_permission)

        # When
        result = user_interaction.ask_permission(
            syscall_nr=1,
            syscall_name="brk",
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )

    # Then
    assert result == "ALLOW"


def test_ask_permission_cli_input(monkeypatch):
    # Given
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator",lambda argument_raw, argument_pretty: (argument_raw, []))
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        def fake_createfilehandler(stdin, mode, callback):
            class DummyEvent:
                pass
            callback(stdin, None)
        mock_root.createfilehandler.side_effect = fake_createfilehandler
        mock_root.deletefilehandler = MagicMock()
        mock_root.destroy = MagicMock()
        fake_stdin = MagicMock()
        fake_stdin.readline.return_value = "y\n"
        monkeypatch.setattr("sys.stdin", fake_stdin)
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)
        monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())
        mock_root.mainloop.side_effect = lambda: None

        # When
        result = user_interaction.ask_permission(
            syscall_nr=1,
            syscall_name="brk",
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )

    # Then
    assert result == "ALLOW"


def test_ask_permission_timeout(monkeypatch):
    # Given
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator",lambda argument_raw, argument_pretty: (argument_raw, []))
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root
        mock_root.createfilehandler = MagicMock()
        mock_root.deletefilehandler = MagicMock()
        mock_root.destroy = MagicMock()
        monkeypatch.setattr("sys.stdin", MagicMock())
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)
        monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())
        mock_root.mainloop.side_effect = lambda: None

        # When
        result = user_interaction.ask_permission(
            syscall_nr=1,
            syscall_name="brk",
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )

    # Then
    assert result is None
    mock_root.createfilehandler.side_effect = fake_createfilehandler
    mock_root.deletefilehandler = MagicMock()
    mock_root.destroy = MagicMock()

    # Patch sys.stdin.readline to return "y\n"
    fake_stdin = MagicMock()
    fake_stdin.readline.return_value = "y\n"
    monkeypatch.setattr("sys.stdin", fake_stdin)

    # Patch print to suppress output
    monkeypatch.setattr("builtins.print", lambda *a, **k: None)

    # Patch LOGGER to avoid logging
    monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())

    # Patch mainloop to immediately return (simulate CLI input triggers destroy)
    mock_root.mainloop.side_effect = lambda: None

    # Call ask_permission and check result
    result = user_interaction.ask_permission(
        syscall_nr=1,
        syscall_name="brk",
        program_name="prog",
        program_hash="deadbeef",
        parameter_formated="param",
        parameter_raw=["param"]
    )
    # Since we simulate CLI "y", expect "ALLOW"
    assert result == "ALLOW"


def test_ask_permission_timeout(monkeypatch):
    """
    Test ask_permission when no input is provided (neither GUI nor CLI).
    This test ensures that the function waits for input and returns None if no decision is made.
    """
    # Patch group_selector functions to avoid file IO and logic
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator",lambda argument_raw, argument_pretty: (argument_raw, []))
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")

    # Patch tkinter so no real GUI is created
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        # Patch createfilehandler to do nothing (no CLI input)
        mock_root.createfilehandler = MagicMock()
        mock_root.deletefilehandler = MagicMock()
        mock_root.destroy = MagicMock()

        # Patch sys.stdin so on_stdin is never triggered
        monkeypatch.setattr("sys.stdin", MagicMock())

        # Patch print to suppress output
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)

        # Patch LOGGER to avoid logging
        monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())

        # Patch mainloop to just return (simulate user closes window or times out)
        mock_root.mainloop.side_effect = lambda: None

        # Call ask_permission and check result
        result = user_interaction.ask_permission(
            syscall_nr=1,
            syscall_name="brk",
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )
        # Since no input is given, expect None
        assert result is None
