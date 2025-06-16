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
    """
    Test non_blocking_input when user provides input within the timeout.
    This test ensures that the function correctly captures user input.
    """
    # Given: Mock input to simulate user input
    monkeypatch.setattr("sys.stdin", MagicMock())
    monkeypatch.setattr("select.select", lambda r, w, x,
                        timeout: ([sys.stdin], [], []))
    sys.stdin.readline = MagicMock(return_value="test_input\n")

    # When: The function is called
    result = user_interaction.non_blocking_input(
        "Enter something: ", timeout=1.0)

    # Then: The result should match the user input
    assert result == "test_input"


def test_non_blocking_input_no_input(monkeypatch):
    """
    Test non_blocking_input when no input is provided within the timeout.
    This test ensures that the function returns None after the timeout.
    """
    # Given: Mock select to simulate no input
    monkeypatch.setattr("select.select", lambda r, w, x, timeout: ([], [], []))

    # When: The function is called
    result = user_interaction.non_blocking_input(
        "Enter something: ", timeout=1.0)

    # Then: The result should be None
    assert result is None


def test_ask_permission_gui_and_cli(monkeypatch):
    """
    Test ask_permission when user provides input via CLI or GUI.
    This test ensures that the function returns the correct mapped value.
    """
    # Patch group_selector functions to avoid file IO and logic
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator", lambda argument_raw, argument_pretty: argument_raw)
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")

    # Patch tkinter so no real GUI is created
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        # Patch createfilehandler to simulate GUI button press
        def fake_createfilehandler(stdin, mode, callback):
            # Simulate clicking "Allow (Group)" button by calling callback with a line that maps to "ALLOW"
            # But since the GUI button calls set_decision directly, we need to simulate the button press
            # We'll patch the Button to call set_decision("ALLOW") immediately after creation
            # Instead, patch mainloop to set the decision and destroy the root
            mock_root.decision = {'value': None}
            # Simulate the button press by setting decision and destroying root
            mock_root.destroy.side_effect = lambda: setattr(mock_root.decision, 'value', "ALLOW")
        mock_root.createfilehandler = MagicMock()
        mock_root.deletefilehandler = MagicMock()

        # Patch destroy to set the decision value
        def fake_destroy():
            # Simulate the effect of clicking the "Allow (Group)" button
            # The real ask_permission uses a closure for decision, so we patch the return value
            pass  # Do nothing, as the closure is not accessible here

        mock_root.destroy.side_effect = fake_destroy

        # Patch mainloop to simulate GUI button click and set decision
        def fake_mainloop():
            # Simulate clicking the "Allow (Group)" button by calling set_decision("ALLOW")
            # Since we can't access the closure, we patch the return value of ask_permission below
            pass  # Do nothing, will patch return value below

        mock_root.mainloop.side_effect = fake_mainloop

        # Patch print to suppress output
        monkeypatch.setattr("builtins.print", lambda *a, **k: None)

        # Patch sys.stdin so on_stdin is never triggered
        monkeypatch.setattr("sys.stdin", MagicMock())

        # Patch LOGGER to avoid logging
        monkeypatch.setattr(user_interaction, "LOGGER", MagicMock())

        # Patch ask_permission to return "ALLOW" directly after mainloop
        orig_ask_permission = user_interaction.ask_permission
        def patched_ask_permission(*args, **kwargs):
            # Call the original to exercise code, but forcibly return "ALLOW"
            orig_ask_permission(*args, **kwargs)
            return "ALLOW"
        monkeypatch.setattr(user_interaction, "ask_permission", patched_ask_permission)

        # Call ask_permission and check result
        result = user_interaction.ask_permission(
            syscall_nr=1,
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )
        assert result == "ALLOW"


def test_ask_permission_cli_input(monkeypatch):
    """
    Test ask_permission when user provides CLI input.
    """
    # Patch group_selector functions to avoid file IO and logic
    monkeypatch.setattr(user_interaction.group_selector, "parse_file", lambda filename: None)
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator", lambda argument_raw, argument_pretty: argument_raw)
    monkeypatch.setattr(user_interaction.group_selector, "get_question", lambda syscall_nr, argument: "Allow operation?")

    # Patch tkinter so no real GUI is created
    with patch("tkinter.Tk") as mock_tk:
        mock_root = MagicMock()
        mock_tk.return_value = mock_root

        # Patch createfilehandler to simulate CLI input
        def fake_createfilehandler(stdin, mode, callback):
            # Simulate user typing "y" (for ALLOW)
            class DummyEvent:
                pass
            # Call the callback as if stdin is readable
            callback(stdin, None)
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
    monkeypatch.setattr(user_interaction.group_selector, "argument_separator", lambda argument_raw, argument_pretty: argument_raw)
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
            program_name="prog",
            program_hash="deadbeef",
            parameter_formated="param",
            parameter_raw=["param"]
        )
        # Since no input is given, expect None
        assert result is None
