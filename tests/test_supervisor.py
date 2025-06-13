"""
Test cases for the supervisor module.

This module contains unit tests for the following functionalities:
- Asking for permission via ZeroMQ.
"""

import json
import os
from unittest.mock import MagicMock, patch, ANY
from supervisor.supervisor import ask_for_permission_zmq, is_already_decided, prepare_arguments, setup_zmq, init_shared_list


def test_ask_for_permission_zmq():
    """
    Test asking for permission via ZeroMQ.
    This test ensures that the function sends the correct message and processes
    the response correctly.
    """
    # Given: Mock socket and input parameters
    mock_socket = MagicMock()
    syscall_name = "open"
    syscall_nr = 2
    arguments_raw = ["filename", "flags"]
    arguments_formated = ["/path/to/file", "O_RDONLY"]

    # And: Mock response from the socket
    mock_response = {
        "status": "success",
        "data": {"decision": "ALLOW"}
    }
    mock_socket.recv_multipart.return_value = [
        b'', json.dumps(mock_response).encode()]

    # When: The function is called
    with patch("supervisor.supervisor.LOGGER") as mock_logger:
        result = ask_for_permission_zmq(
            syscall_name=syscall_name,
            syscall_nr=syscall_nr,
            arguments_raw=arguments_raw,
            arguments_formated=arguments_formated,
            socket=mock_socket
        )

    # Then: The correct message should be sent
    expected_message = {
        "type": "req_decision",
        "body": {
            "program": None,  # PROGRAM_ABSOLUTE_PATH is not set in this test
            "syscall_id": syscall_nr,
            "syscall_name": syscall_name,
            "parameter_raw": arguments_raw,
            "parameter_formated": arguments_formated
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()])

    # And: The decision should be correctly returned
    assert result["decision"] == "ALLOW"

    # And: The logger should log the request
    log_calls = [call for call in mock_logger.info.call_args_list]
    assert any(
        call[0][0] == "Asking for permission for syscall: %s" and call[0][1] == syscall_name
        for call in log_calls
    )


def test_is_already_decided_true():
    """
    Test when a decision is already made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET with a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", {(2, "arg1", "arg2")}), \
         patch("supervisor.supervisor.DENY_SET", set()):
        syscall_nr = 2
        arguments = ["arg1", "arg2"]

        # When: The is_already_decided function is called
        result = is_already_decided(syscall_nr, arguments)

        # Then: It should return True
        assert result is True


def test_is_already_decided_false():
    """
    Test when no decision is made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET without a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", {(2, "arg1", "arg2")}), \
         patch("supervisor.supervisor.DENY_SET", {(3, "arg3")}):
        syscall_nr = 2
        arguments = ["arg3"]

        # When: The is_already_decided function is called
        result = is_already_decided(syscall_nr, arguments)

        # Then: It should return False
        assert result is False


def test_prepare_arguments():
    """
    Test preparing arguments from syscall arguments.
    """
    # Given: Mocked syscall arguments
    mock_syscall_args = [
        type("MockArg", (object,), {
             "name": "filename", "format": lambda: "/path/to/file"}),
        type("MockArg", (object,), {"name": "flags", "value": "O_RDONLY"}),
        type("MockArg", (object,), {"name": "mode", "value": "0777"}),
        type("MockArg", (object,), {"name": "unknown", "format": lambda: "*"})
    ]

    # When: The prepare_arguments function is called
    result = prepare_arguments(mock_syscall_args)

    # Then: The arguments should be correctly prepared
    assert result == ["/path/to/file", "O_RDONLY", "0777", "*"]


def test_init_shared_list_success(mocker):
    """
    Test initializing the shared set when the server responds successfully.
    """
    # Given: Mock socket and server response
    mock_socket = MagicMock()
    mock_response = {
        "status": "success",
        "data": {
            "allowed_syscalls": [[2, ["arg1", "arg2"]]],
            "denied_syscalls": [[3, ["arg3"]]],
            "blacklisted_ids": [2, 3]
        }
    }
    mock_socket.recv_multipart.side_effect = [
        [b'', json.dumps(mock_response).encode()]
    ]

    # Mock ALLOW_SET and DENY_SET
    mock_allow_set = mocker.patch("supervisor.supervisor.ALLOW_SET", set())
    mock_deny_set = mocker.patch("supervisor.supervisor.DENY_SET", set())
    mock_syscall_id_set = mocker.patch("supervisor.supervisor.SYSCALL_ID_SET", set())

    # When: The init_shared_list function is called
    from supervisor import supervisor
    supervisor.init_shared_list(socket=mock_socket)

    # Then: ALLOW_SET and DENY_SET should be populated correctly
    assert (2, "arg1", "arg2") in mock_allow_set
    assert (3, "arg3") in mock_deny_set
    assert mock_syscall_id_set == {2, 3}

    # And: The correct message should be sent
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None  # PROGRAM_ABSOLUTE_PATH is not set in this test
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )


def test_init_shared_list_error(mocker):
    """
    Test initializing the shared set when the server responds with an error.
    """
    # Given: Mock socket and server response
    mock_socket = MagicMock()
    mock_response = {
        "status": "error",
        "data": "Database not found"
    }
    mock_socket.recv_multipart.side_effect = [
        [b'', json.dumps(mock_response).encode()]
    ]
    mocker.patch("supervisor.supervisor.ALLOW_SET", set())
    mocker.patch("supervisor.supervisor.DENY_SET", set())

    # When: The init_shared_list function is called
    from supervisor import supervisor
    supervisor.init_shared_list(socket=mock_socket)

    # Then: ALLOW_SET and DENY_SET should remain empty
    from supervisor.supervisor import ALLOW_SET, DENY_SET
    assert ALLOW_SET == set()
    assert DENY_SET == set()

    # And: The correct message should be sent
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None  # PROGRAM_ABSOLUTE_PATH is not set in this test
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )


def test_setup_zmq(mocker):
    """
    Test setting up a ZeroMQ DEALER socket.
    """
    # Given: Mock ZeroMQ context and socket
    mock_context = mocker.patch("zmq.Context")
    mock_socket = mock_context.return_value.socket.return_value

    # When: The setup_zmq function is called
    result = setup_zmq()
    # Then: The socket should be configured and returned    mock_context.return_value.socket.assert_called_once_with(mocker.ANY)
    mock_socket.connect.assert_called_once_with("tcp://localhost:5556")
    assert result == mock_socket


import sys
import types
import builtins

import pytest


def test_main_exits_if_no_program(monkeypatch):
    """
    Test that main() exits with error if no program argument is given.
    """
    from supervisor import supervisor

    # Patch argv to simulate no program argument
    monkeypatch.setattr(supervisor, "argv", ["supervisor.py"])
    # Patch LOGGER to capture error
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)
    # Patch exit to sys.exit so it raises SystemExit
    import sys as _sys
    monkeypatch.setattr(supervisor, "exit", _sys.exit)
    # Patch print to avoid output
    monkeypatch.setattr(builtins, "print", lambda *a, **k: None)

    with pytest.raises(SystemExit):
        supervisor.main()
    mock_logger.error.assert_called_once()
    # Should log the usage error
    assert "Nutzung" in mock_logger.error.call_args[0][0]


def test_main_sets_up_and_runs(monkeypatch):
    """
    Test that main() sets up and runs the main logic with mocks.
    """
    from supervisor import supervisor

    # Patch argv to simulate a program argument
    monkeypatch.setattr(supervisor, "argv", ["supervisor.py", "dummy_prog"])
    # Patch LOGGER to capture info
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)
    # Patch set_program_path, setup_zmq, init_shared_list
    monkeypatch.setattr(supervisor, "set_program_path", MagicMock())
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "setup_zmq", MagicMock(return_value=mock_socket))
    monkeypatch.setattr(supervisor, "init_shared_list", MagicMock())
    # Patch Process, PtraceDebugger, and related methods
    mock_process = MagicMock()
    mock_child = MagicMock()
    mock_child.pid = 123
    mock_child.start = MagicMock()
    monkeypatch.setattr(supervisor, "Process", MagicMock(return_value=mock_child))
    mock_debugger = MagicMock()
    monkeypatch.setattr(supervisor, "PtraceDebugger", MagicMock(return_value=mock_debugger))
    mock_debugger.addProcess.return_value = mock_process
    mock_process.waitSignals.return_value = MagicMock()
    mock_process.syscall = MagicMock()
    mock_process.cont = MagicMock()
    # Simulate debugger.waitSyscall() returning ProcessExit after one call
    from ptrace.debugger import ProcessExit
    mock_event = MagicMock()
    mock_debugger.waitSyscall.side_effect = [mock_event, ProcessExit(mock_process)]
    # Patch handle_syscall_event to avoid actual logic
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    # Patch child.join and socket.close
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    supervisor.main()

    # Check that setup and logging happened
    mock_logger.info.assert_any_call("Starting supervisor for %s", "dummy_prog")
    supervisor.set_program_path.assert_called_once_with(relative_path="dummy_prog")
    supervisor.setup_zmq.assert_called_once()
    supervisor.init_shared_list.assert_called_once_with(socket=mock_socket)
    mock_child.start.assert_called_once()
    mock_debugger.addProcess.assert_called_once_with(pid=123, is_attached=False)
    mock_process.cont.assert_called_once()
    mock_process.waitSignals.assert_called_once()
    mock_process.syscall.assert_called()
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()


def test_main_keyboard_interrupt(monkeypatch):
    """
    Test that main() handles KeyboardInterrupt gracefully.
    """
    from supervisor import supervisor

    monkeypatch.setattr(supervisor, "argv", ["supervisor.py", "dummy_prog"])
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)
    monkeypatch.setattr(supervisor, "set_program_path", MagicMock())
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "setup_zmq", MagicMock(return_value=mock_socket))
    monkeypatch.setattr(supervisor, "init_shared_list", MagicMock())
    mock_process = MagicMock()
    mock_child = MagicMock()
    mock_child.pid = 123
    mock_child.start = MagicMock()
    monkeypatch.setattr(supervisor, "Process", MagicMock(return_value=mock_child))
    mock_debugger = MagicMock()
    monkeypatch.setattr(supervisor, "PtraceDebugger", MagicMock(return_value=mock_debugger))
    mock_debugger.addProcess.return_value = mock_process
    mock_process.waitSignals.return_value = MagicMock()
    mock_process.syscall = MagicMock()
    mock_process.cont = MagicMock()
    # Simulate KeyboardInterrupt in the loop
    mock_debugger.waitSyscall.side_effect = KeyboardInterrupt
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    supervisor.main()

    mock_logger.info.assert_any_call("Exiting supervisor...")
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()


def test_main_generic_exception(monkeypatch):
    """
    Test that main() handles generic Exception in the loop.
    """
    from supervisor import supervisor

    monkeypatch.setattr(supervisor, "argv", ["supervisor.py", "dummy_prog"])
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)
    monkeypatch.setattr(supervisor, "set_program_path", MagicMock())
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "setup_zmq", MagicMock(return_value=mock_socket))
    monkeypatch.setattr(supervisor, "init_shared_list", MagicMock())
    mock_process = MagicMock()
    mock_child = MagicMock()
    mock_child.pid = 123
    mock_child.start = MagicMock()
    monkeypatch.setattr(supervisor, "Process", MagicMock(return_value=mock_child))
    mock_debugger = MagicMock()
    monkeypatch.setattr(supervisor, "PtraceDebugger", MagicMock(return_value=mock_debugger))
    mock_debugger.addProcess.return_value = mock_process
    mock_process.waitSignals.return_value = MagicMock()
    mock_process.syscall = MagicMock()
    mock_process.cont = MagicMock()
    # Simulate Exception in the loop
    mock_debugger.waitSyscall.side_effect = RuntimeError("fail")
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    supervisor.main()

    # Accept any second argument (the exception object)
    mock_logger.error.assert_any_call("Exception in main loop: %s", ANY)
    # Optionally, check that the second argument is the exception and has the right message
    exc_arg = [call for call in mock_logger.error.call_args_list if call[0][0] == "Exception in main loop: %s"][0][0][1]
    assert isinstance(exc_arg, RuntimeError)
    assert str(exc_arg) == "fail"
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()
