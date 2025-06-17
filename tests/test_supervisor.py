"""
Test cases for the supervisor module.

This module contains unit tests for the following functionalities:
- Asking for permission via ZeroMQ.
"""

import json
import os
from unittest.mock import MagicMock, patch, ANY
from supervisor.supervisor import ask_for_permission_zmq, check_decision_made, prepare_arguments, setup_zmq, init_shared_list


def test_ask_for_permission_zmq():
    # Given
    mock_socket = MagicMock()
    syscall_name = "open"
    syscall_nr = 2
    arguments_raw = ["filename", "flags"]
    arguments_formated = ["/path/to/file", "O_RDONLY"]
    mock_response = {
        "status": "success",
        "data": {"decision": "ALLOW"}
    }
    mock_socket.recv_multipart.return_value = [
        b'', json.dumps(mock_response).encode()]

    # When
    with patch("supervisor.supervisor.LOGGER") as mock_logger:
        result = ask_for_permission_zmq(
            syscall_name=syscall_name,
            syscall_nr=syscall_nr,
            arguments_raw=arguments_raw,
            arguments_formated=arguments_formated,
            socket=mock_socket
        )

    # Then
    expected_message = {
        "type": "req_decision",
        "body": {
            "program": None,
            "syscall_id": syscall_nr,
            "syscall_name": syscall_name,
            "parameter_raw": arguments_raw,
            "parameter_formated": arguments_formated
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()])
    assert result["decision"] == "ALLOW"
    log_calls = [call for call in mock_logger.info.call_args_list]
    assert any(
        call[0][0] == "Asking for permission for syscall: %s" and call[0][1] == syscall_name
        for call in log_calls
    )


def test_check_decision_made_true_allow():
    """
    Test when a decision is already made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET with a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", {(2, "arg1", "arg2")}), \
         patch("supervisor.supervisor.DENY_SET", set()):
        syscall_nr = 2
        arguments = ["arg1", "arg2"]

        # When: The is_already_decided function is called
        allow, deny = check_decision_made(syscall_nr, arguments)

        # Then: It should return True
        assert allow is True


def test_check_decision_made_false_allow():
    """
    Test when no decision is made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET without a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", {(2, "arg1", "arg2")}), \
         patch("supervisor.supervisor.DENY_SET", {(3, "arg3")}):
        syscall_nr = 2
        arguments = ["arg3"]

        # When: The is_already_decided function is called
        allow, deny = check_decision_made(syscall_nr, arguments)

        # Then: It should return False
        assert allow is False

def test_check_decision_made_true_deny():
    """
    Test when a decision is already made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET with a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", set()), \
         patch("supervisor.supervisor.DENY_SET", {(2, "arg1", "arg2")}):
        syscall_nr = 2
        arguments = ["arg1", "arg2"]

        # When: The is_already_decided function is called
        allow, deny = check_decision_made(syscall_nr, arguments)

        # Then: It should return True
        assert deny is True


def test_check_decision_made_false_deny():
    """
    Test when no decision is made for the given syscall and arguments.
    """
    # Given: Mocked ALLOW_SET and DENY_SET without a matching decision
    with patch("supervisor.supervisor.ALLOW_SET", {(2, "arg1", "arg2")}), \
         patch("supervisor.supervisor.DENY_SET", {(3, "arg3")}):
        syscall_nr = 2
        arguments = ["arg3"]

        # When: The is_already_decided function is called
        allow, deny = check_decision_made(syscall_nr, arguments)

        # Then: It should return False
        assert deny is False


def test_prepare_arguments():
    # Given
    mock_syscall_args = [
        type("MockArg", (object,), {
             "name": "filename", "format": lambda: "/path/to/file"}),
        type("MockArg", (object,), {"name": "flags", "value": "O_RDONLY"}),
        type("MockArg", (object,), {"name": "mode", "value": "0777"}),
        type("MockArg", (object,), {"name": "unknown", "format": lambda: "*"})
    ]

    # When
    result = prepare_arguments(mock_syscall_args)

    # Then
    assert result == ["/path/to/file", "O_RDONLY", "0777", "*"]


def test_init_shared_list_success(mocker):
    # Given
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
    mock_allow_set = mocker.patch("supervisor.supervisor.ALLOW_SET", set())
    mock_deny_set = mocker.patch("supervisor.supervisor.DENY_SET", set())
    mock_syscall_id_set = mocker.patch("supervisor.supervisor.SYSCALL_ID_SET", set())

    # When
    from supervisor import supervisor
    supervisor.init_shared_list(socket=mock_socket)

    # Then
    assert (2, "arg1", "arg2") in mock_allow_set
    assert (3, "arg3") in mock_deny_set
    assert mock_syscall_id_set == {2, 3}
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )


def test_init_shared_list_error(mocker):
    # Given
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

    # When
    from supervisor import supervisor
    supervisor.init_shared_list(socket=mock_socket)

    # Then
    from supervisor.supervisor import ALLOW_SET, DENY_SET
    assert ALLOW_SET == set()
    assert DENY_SET == set()
    expected_message = {
        "type": "read_db",
        "body": {
            "program": None
        }
    }
    mock_socket.send_multipart.assert_called_once_with(
        [b'', json.dumps(expected_message).encode()]
    )


def test_setup_zmq(mocker):
    # Given
    mock_context = mocker.patch("zmq.Context")
    mock_socket = mock_context.return_value.socket.return_value

    # When
    result = setup_zmq()

    # Then
    mock_socket.connect.assert_called_once_with("tcp://localhost:5556")
    assert result == mock_socket


import sys
import types
import builtins
import pytest
from ptrace.debugger import ProcessSignal, NewProcessEvent, ProcessExit

def test_main_handle_syscall_event(monkeypatch):
    # Given
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
    dummy_event = MagicMock()
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_debugger.waitSyscall.side_effect = [dummy_event, ProcessExit(mock_process)]
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    # When
    supervisor.main()

    # Then
    supervisor.handle_syscall_event.assert_called_with(dummy_event, mock_process, mock_socket)
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_process_signal(monkeypatch):
    # Given
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
    sig = ProcessSignal(mock_process, 5)
    mock_debugger.waitSyscall.side_effect = [sig, ProcessExit(mock_process)]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    # When
    supervisor.main()

    # Then
    mock_logger.debug.assert_any_call("***SIGNAL***: %s", sig.name)
    mock_process.syscall.assert_called()
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_new_process_event(monkeypatch):
    # Given
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
    mock_newproc = MagicMock()
    mock_newproc.process.parent = mock_process
    newproc_event = NewProcessEvent(mock_newproc.process)
    mock_debugger.waitSyscall.side_effect = [newproc_event, ProcessExit(mock_process)]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    # When
    supervisor.main()

    # Then
    mock_logger.info.assert_any_call("***CHILD-PROCESS***")
    mock_process.syscall.assert_called()
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_process_exit(monkeypatch):
    # Given
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
    mock_debugger.waitSyscall.side_effect = [ProcessExit(mock_process)]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    # When
    supervisor.main()

    # Then
    mock_logger.info.assert_any_call("***PROCESS-EXECUTED***")
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_generic_exception(monkeypatch):
    # Given
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
    mock_debugger.waitSyscall.side_effect = RuntimeError("fail")
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    # When
    supervisor.main()

    # Then
    mock_logger.error.assert_any_call("Exception in main loop: %s", ANY)
    mock_logger.debug.assert_any_call("Traceback: %s", ANY)
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()


def test_handle_syscall_event_skips_non_blacklisted(monkeypatch):
    # Given
    from supervisor import supervisor
    mock_event = MagicMock()
    mock_process = MagicMock()
    mock_socket = MagicMock()
    mock_state = MagicMock()
    mock_syscall = MagicMock()
    mock_syscall.result = None
    mock_syscall.syscall = 123
    mock_syscall.arguments = []
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", set())
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())

    # When
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)

    # Then
    mock_process.syscall.assert_called_once()


def test_handle_syscall_event_already_decided(monkeypatch):
    # Given
    from supervisor import supervisor
    mock_event = MagicMock()
    mock_process = MagicMock()
    mock_socket = MagicMock()
    mock_state = MagicMock()
    mock_syscall = MagicMock()
    mock_syscall.result = None
    mock_syscall.syscall = 42
    mock_syscall.arguments = []
    mock_syscall.format.return_value = "syscall_fmt"
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {42})
    monkeypatch.setattr(supervisor, "is_already_decided", lambda syscall_nr, arguments: True)
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())

    # When
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)

    # Then
    mock_process.syscall.assert_called_once()


def test_handle_syscall_event_allow(monkeypatch):
    # Given
    from supervisor import supervisor
    mock_event = MagicMock()
    mock_process = MagicMock()
    mock_socket = MagicMock()
    mock_state = MagicMock()
    mock_syscall = MagicMock()
    mock_syscall.result = None
    mock_syscall.syscall = 99
    mock_syscall.name = "open"
    mock_syscall.arguments = []
    mock_syscall.format.return_value = "syscall_fmt"
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {99})
    monkeypatch.setattr(supervisor, "is_already_decided", lambda syscall_nr, arguments: False)
    monkeypatch.setattr(supervisor, "prepare_arguments", lambda syscall_args: [])
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())
    monkeypatch.setattr(supervisor, "ask_for_permission_zmq", lambda **kwargs: {"decision": "ALLOW", "allowed_ids": [99]})
    monkeypatch.setattr(supervisor, "ALLOW_SET", set())
    monkeypatch.setattr(supervisor, "DENY_SET", set())
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {99})

    # When
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)

    # Then
    mock_process.syscall.assert_called_once()


def test_handle_syscall_event_deny(monkeypatch):
    # Given
    from supervisor import supervisor
    mock_event = MagicMock()
    mock_process = MagicMock()
    mock_socket = MagicMock()
    mock_state = MagicMock()
    mock_syscall = MagicMock()
    mock_syscall.result = None
    mock_syscall.syscall = 88
    mock_syscall.name = "open"
    mock_syscall.arguments = []
    mock_syscall.format.return_value = "syscall_fmt"
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {88})
    monkeypatch.setattr(supervisor, "is_already_decided", lambda syscall_nr, arguments: False)
    monkeypatch.setattr(supervisor, "prepare_arguments", lambda syscall_args: [])
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())
    monkeypatch.setattr(supervisor, "ask_for_permission_zmq", lambda **kwargs: {"decision": "DENY"})
    monkeypatch.setattr(supervisor, "ALLOW_SET", set())
    monkeypatch.setattr(supervisor, "DENY_SET", set())
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {88})

    # When
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)

    # Then
    assert mock_process.setreg.called
    assert mock_process.syscall.called
    mock_syscall.syscall = 99
    mock_syscall.name = "open"
    mock_syscall.arguments = []
    mock_syscall.format.return_value = "syscall_fmt"
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall

    # Patch SYSCALL_ID_SET to contain 99
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {99})
    monkeypatch.setattr(supervisor, "is_already_decided", lambda syscall_nr, arguments: False)
    monkeypatch.setattr(supervisor, "prepare_arguments", lambda syscall_args: [])
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())
    # Patch ask_for_permission_zmq to return ALLOW
    monkeypatch.setattr(supervisor, "ask_for_permission_zmq", lambda **kwargs: {"decision": "ALLOW", "allowed_ids": [99]})
    # Patch ALLOW_SET and DENY_SET
    monkeypatch.setattr(supervisor, "ALLOW_SET", set())
    monkeypatch.setattr(supervisor, "DENY_SET", set())
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {99})

    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)
    mock_process.syscall.assert_called_once()


def test_handle_syscall_event_deny(monkeypatch):
    """
    Test handle_syscall_event when decision is DENY.
    """
    from supervisor import supervisor

    mock_event = MagicMock()
    mock_process = MagicMock()
    mock_socket = MagicMock()
    mock_state = MagicMock()
    mock_syscall = MagicMock()
    mock_syscall.result = None
    mock_syscall.syscall = 88
    mock_syscall.name = "open"
    mock_syscall.arguments = []
    mock_syscall.format.return_value = "syscall_fmt"
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = mock_syscall

    # Patch SYSCALL_ID_SET to contain 88
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {88})
    monkeypatch.setattr(supervisor, "is_already_decided", lambda syscall_nr, arguments: False)
    monkeypatch.setattr(supervisor, "prepare_arguments", lambda syscall_args: [])
    monkeypatch.setattr(supervisor, "LOGGER", MagicMock())
    # Patch ask_for_permission_zmq to return DENY
    monkeypatch.setattr(supervisor, "ask_for_permission_zmq", lambda **kwargs: {"decision": "DENY"})
    # Patch ALLOW_SET and DENY_SET
    monkeypatch.setattr(supervisor, "ALLOW_SET", set())
    monkeypatch.setattr(supervisor, "DENY_SET", set())
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {88})

    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)
    # Should call setreg and syscall for deny
    assert mock_process.setreg.called
    assert mock_process.syscall.called

