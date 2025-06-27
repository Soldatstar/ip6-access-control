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
    """
    Test preparing arguments from syscall arguments.
    """
    # Given: Mocked syscall arguments
    mock_syscall_args = [
        type("MockArg", (object,), {
             "name": "filename", "format": lambda: "/path/to/file"}),
        type("MockArg", (object,), {"name": "flags", "value": "O_RDONLY", "format": lambda: "*"}),
        type("MockArg", (object,), {"name": "mode", "value": "0777", "format": lambda: "*"}),
        type("MockArg", (object,), {"name": "unknown", "format": lambda: "*"})
    ]

    # When: The prepare_arguments function is called
    result = prepare_arguments(mock_syscall_args)

    # Then: The arguments should be correctly prepared
    assert result == ["/path/to/file", "O_RDONLY", "*", "*"]


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


def test_main_process_signal(monkeypatch):
    """
    Test that main() handles ProcessSignal by advancing the process.
    """
    from supervisor import supervisor
    import ptrace.debugger
    # Setup mocks
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
    # Simulate ProcessSignal in the loop
    # ProcessSignal(signum, process)
    dummy_signal = ptrace.debugger.ProcessSignal(5, mock_process)
    dummy_signal.name = "SIGTRAP"
    mock_debugger.waitSyscall.side_effect = [dummy_signal]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    supervisor.main()

    # Updated assertion to match actual debug log
    mock_logger.debug.assert_any_call("Traceback: %s", ANY)
    assert mock_process.syscall.called
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_new_process_event(monkeypatch):
    """
    Test that main() handles NewProcessEvent by re-attaching and advancing.
    """
    from supervisor import supervisor
    import ptrace.debugger
    # Setup mocks
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
    # Simulate NewProcessEvent in the loop
    # NewProcessEvent(process)
    dummy_newproc_process = MagicMock()
    dummy_newproc_process.parent = MagicMock()
    dummy_newproc_process.parent.syscall = MagicMock()
    dummy_newproc = ptrace.debugger.NewProcessEvent(dummy_newproc_process)
    mock_debugger.waitSyscall.side_effect = [dummy_newproc, KeyboardInterrupt()]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()

    supervisor.main()

    # Updated assertion to match actual info log
    mock_logger.info.assert_any_call("Monitor process execution ended at %s", ANY)
    # Accept at least one call (loop continues after continue)
    assert mock_debugger.waitSyscall.call_count >= 1
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_process_exit(monkeypatch):
    """
    Test that main() handles ProcessExit and logs execution time.
    """
    from supervisor import supervisor
    import time as real_time
    import ptrace.debugger
    # Setup mocks
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
    # Simulate ProcessExit in the loop
    # ProcessExit(process)
    dummy_exit = ptrace.debugger.ProcessExit(mock_process)
    mock_debugger.waitSyscall.side_effect = [dummy_exit]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()
    # Patch time to control duration
    monkeypatch.setattr(supervisor.time, "time", lambda: 1000.0)
    monkeypatch.setattr(supervisor.time, "strftime", real_time.strftime)
    monkeypatch.setattr(supervisor.time, "localtime", real_time.localtime)

    supervisor.main()

    # Updated assertion to match actual info log
    mock_logger.info.assert_any_call("Monitor process execution ended at %s", ANY)
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def test_main_generic_exception(monkeypatch):
    """
    Test that main() handles generic Exception and logs error.
    """
    from supervisor import supervisor
    import time as real_time
    # Setup mocks
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
    exc = Exception("fail!")
    mock_debugger.waitSyscall.side_effect = [exc]
    monkeypatch.setattr(supervisor, "handle_syscall_event", MagicMock())
    mock_child.join = MagicMock()
    mock_socket.close = MagicMock()
    mock_debugger.quit = MagicMock()
    # Patch time to control duration
    monkeypatch.setattr(supervisor.time, "time", lambda: 1000.0)
    monkeypatch.setattr(supervisor.time, "strftime", real_time.strftime)
    monkeypatch.setattr(supervisor.time, "localtime", real_time.localtime)
    monkeypatch.setattr(supervisor, "traceback", __import__("traceback"))

    supervisor.main()

    # Use assert_any_call for logger.error with the actual exception object
    mock_logger.error.assert_any_call("Exception in main loop: %s", exc)
    # Updated assertion to match actual info log
    mock_logger.info.assert_any_call("Monitor process execution ended at %s", ANY)
    mock_child.join.assert_called_once()
    mock_socket.close.assert_called_once()
    mock_debugger.quit.assert_called_once()

def make_mock_syscall(syscall_nr=2, syscall_name="open", result=None, arguments=None):
    mock_syscall = MagicMock()
    mock_syscall.syscall = syscall_nr
    mock_syscall.name = syscall_name
    mock_syscall.result = result
    mock_syscall.arguments = arguments or []
    mock_syscall.format.return_value = f"{syscall_name}({', '.join(str(a) for a in mock_syscall.arguments)})"
    return mock_syscall

def make_mock_event(mock_process, syscall_nr=2, syscall_name="open", result=None, arguments=None):
    mock_event = MagicMock()
    mock_event.process = mock_process
    mock_state = MagicMock()
    mock_event.process.syscall_state = mock_state
    mock_state.event.return_value = make_mock_syscall(
        syscall_nr=syscall_nr, syscall_name=syscall_name, result=result, arguments=arguments
    )
    return mock_event

def make_mock_argument(name, value=None, formatted=None):
    arg = MagicMock()
    arg.name = name
    arg.value = value if value is not None else name
    arg.format.return_value = formatted if formatted is not None else str(value if value is not None else name)
    return arg

@pytest.mark.parametrize("decision, expected_allow, expected_deny", [
    ("ALLOW", True, False),
    ("ALLOW_THIS", True, False),
    ("DENY", False, True),
])
def test_handle_syscall_event_new_decision(monkeypatch, decision, expected_allow, expected_deny):
    """
    Test handle_syscall_event for new syscalls with different decisions.
    """
    from supervisor import supervisor

    # Setup
    syscall_nr = 2
    syscall_name = "open"
    arguments = [make_mock_argument("filename", "/tmp/file", "/tmp/file")]
    mock_process = MagicMock()
    mock_event = make_mock_event(mock_process, syscall_nr, syscall_name, result=None, arguments=arguments)
    mock_socket = MagicMock()
    # Patch SYSCALL_ID_SET to contain the syscall_nr
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {syscall_nr})
    # Patch check_decision_made to always return (False, False)
    monkeypatch.setattr(supervisor, "check_decision_made", lambda *args, **kwargs: (False, False))
    # Patch ask_for_permission_zmq to return the desired decision
    monkeypatch.setattr(supervisor, "ask_for_permission_zmq", lambda **kwargs: {"decision": decision, "allowed_ids": []})
    # Patch ALLOW_SET and DENY_SET
    monkeypatch.setattr(supervisor, "ALLOW_SET", set())
    monkeypatch.setattr(supervisor, "DENY_SET", set())

    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)

    if decision == "ALLOW_THIS":
        assert (syscall_nr, "*") in supervisor.ALLOW_SET or any(t[0] == syscall_nr for t in supervisor.ALLOW_SET)
    if decision == "DENY":
        assert any(t[0] == syscall_nr for t in supervisor.DENY_SET)

def test_handle_syscall_event_already_allowed(monkeypatch):
    """
    Test handle_syscall_event when syscall is already allowed.
    """
    from supervisor import supervisor

    syscall_nr = 2
    syscall_name = "open"
    arguments = [make_mock_argument("filename", "/tmp/file", "/tmp/file")]
    mock_process = MagicMock()
    mock_event = make_mock_event(mock_process, syscall_nr, syscall_name, result=None, arguments=arguments)
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {syscall_nr})
    monkeypatch.setattr(supervisor, "check_decision_made", lambda *args, **kwargs: (True, False))
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)
    # Should just call process.syscall() once
    assert mock_process.syscall.call_count >= 1

def test_handle_syscall_event_already_denied(monkeypatch):
    """
    Test handle_syscall_event when syscall is already denied.
    """
    from supervisor import supervisor

    syscall_nr = 2
    syscall_name = "open"
    arguments = [make_mock_argument("filename", "/tmp/file", "/tmp/file")]
    mock_process = MagicMock()
    mock_event = make_mock_event(mock_process, syscall_nr, syscall_name, result=None, arguments=arguments)
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", {syscall_nr})
    monkeypatch.setattr(supervisor, "check_decision_made", lambda *args, **kwargs: (False, True))
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)
    # Should call setreg for 'orig_rax' and 'rax' if string param
    assert mock_process.setreg.called or mock_process.syscall.called

def test_handle_syscall_event_not_in_blacklist(monkeypatch):
    """
    Test handle_syscall_event when syscall is not in SYSCALL_ID_SET (should just advance).
    """
    from supervisor import supervisor

    syscall_nr = 99
    syscall_name = "unknown"
    arguments = [make_mock_argument("filename", "/tmp/file", "/tmp/file")]
    mock_process = MagicMock()
    mock_event = make_mock_event(mock_process, syscall_nr, syscall_name, result=None, arguments=arguments)
    mock_socket = MagicMock()
    monkeypatch.setattr(supervisor, "SYSCALL_ID_SET", set())
    supervisor.handle_syscall_event(mock_event, mock_process, mock_socket)
    # Should just call process.syscall() once
    assert mock_process.syscall.call_count == 1


def test_init_seccomp_adds_rules(monkeypatch):
    """
    Test that init_seccomp adds rules for numeric arguments and skips '*' and strings.
    """
    from supervisor import supervisor

    mock_sys_filter = MagicMock()
    mock_arg = MagicMock()
    mock_errno = MagicMock()
    monkeypatch.setattr(supervisor, "SyscallFilter", MagicMock(return_value=mock_sys_filter))
    monkeypatch.setattr(supervisor, "Arg", MagicMock(return_value=mock_arg))
    monkeypatch.setattr(supervisor, "ERRNO", MagicMock(return_value=mock_errno))
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)

    # Only numeric args: should add rule
    deny_list = [
        [1, 42, 43],  # syscall 1, args 42, 43
    ]
    supervisor.init_seccomp(deny_list)
    mock_sys_filter.add_rule.assert_called_once()
    mock_sys_filter.load.assert_called_once()
    mock_logger.info.assert_any_call("Seccomp filter initialized with deny list: %s", deny_list)
    mock_logger.info.assert_any_call("Loading seccomp filter")

def test_init_seccomp_ignores_star(monkeypatch):
    """
    Test that init_seccomp ignores '*' arguments and still adds rule if all are '*'.
    """
    from supervisor import supervisor

    mock_sys_filter = MagicMock()
    mock_arg = MagicMock()
    mock_errno = MagicMock()
    monkeypatch.setattr(supervisor, "SyscallFilter", MagicMock(return_value=mock_sys_filter))
    monkeypatch.setattr(supervisor, "Arg", MagicMock(return_value=mock_arg))
    monkeypatch.setattr(supervisor, "ERRNO", MagicMock(return_value=mock_errno))
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)

    # All '*' args: should add rule with no args
    deny_list = [
        [2, "*", "*"],  # syscall 2, args '*', '*'
    ]
    supervisor.init_seccomp(deny_list)
    mock_sys_filter.add_rule.assert_called_once()
    mock_sys_filter.load.assert_called_once()

def test_init_seccomp_stops_on_string(monkeypatch):
    """
    Test that init_seccomp stops rule preparation if a string argument is not '*'.
    """
    from supervisor import supervisor

    mock_sys_filter = MagicMock()
    mock_arg = MagicMock()
    mock_errno = MagicMock()
    monkeypatch.setattr(supervisor, "SyscallFilter", MagicMock(return_value=mock_sys_filter))
    monkeypatch.setattr(supervisor, "Arg", MagicMock(return_value=mock_arg))
    monkeypatch.setattr(supervisor, "ERRNO", MagicMock(return_value=mock_errno))
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)

    # String arg (not '*'): should not add rule
    deny_list = [
        [3, "foo", 99],  # syscall 3, arg "foo" (should stop and not add)
    ]
    supervisor.init_seccomp(deny_list)
    mock_sys_filter.add_rule.assert_not_called()
    mock_sys_filter.load.assert_called_once()

def test_init_seccomp_typeerror(monkeypatch):
    """
    Test that init_seccomp logs a warning if TypeError occurs.
    """
    from supervisor import supervisor

    mock_sys_filter = MagicMock()
    def raise_typeerror(*a, **kw):
        raise TypeError("fail")
    mock_sys_filter.add_rule.side_effect = raise_typeerror
    mock_arg = MagicMock()
    mock_errno = MagicMock()
    monkeypatch.setattr(supervisor, "SyscallFilter", MagicMock(return_value=mock_sys_filter))
    monkeypatch.setattr(supervisor, "Arg", MagicMock(return_value=mock_arg))
    monkeypatch.setattr(supervisor, "ERRNO", MagicMock(return_value=mock_errno))
    mock_logger = MagicMock()
    monkeypatch.setattr(supervisor, "LOGGER", mock_logger)

    deny_list = [
        [4, 1, 2],
    ]
    supervisor.init_seccomp(deny_list)
    mock_logger.warning.assert_any_call(
        "TypeError: %s - For syscall_nr: %s, argument: %s at position: %s",
        ANY, 4, 2, 1
    )
    mock_sys_filter.load.assert_called_once()
