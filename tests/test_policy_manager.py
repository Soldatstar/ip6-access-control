"""
Test cases for the policy_manager module.

This module contains unit tests for the following functionalities:
- Listing applications with known syscall policies.
- Handling cases where the policies directory is missing or empty.
- Handling invalid policy files.
"""

import json
from unittest.mock import MagicMock
from user_tool import policy_manager


def test_list_known_apps_with_policies(tmp_path, monkeypatch):
    """
    Test listing known applications with valid policies.
    This test checks if the function correctly identifies applications with valid
    policies and logs their names and hashes.
    """
    # Given: A mock POLICIES_DIR with valid policy files
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app1_dir = mock_policies_dir / "app1"
    app1_dir.mkdir()
    (app1_dir / "policy.json").write_text(json.dumps({
        "metadata": {"process_name": "App1"},
        "rules": {}
    }))
    app2_dir = mock_policies_dir / "app2"
    app2_dir.mkdir()
    (app2_dir / "policy.json").write_text(json.dumps({
        "metadata": {"process_name": "App2"},
        "rules": {}
    }))

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected messages in order
    expected_calls = [
        ("info", ("Known applications with policies:",)),
        ("info", ("- %s (Hash: %s)", "App1", "app1")),
        ("info", ("- %s (Hash: %s)", "App2", "app2"))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_no_policies_dir(monkeypatch):
    """
    Test behavior when the policies directory does not exist.
    This test ensures that the function logs a message indicating the absence
    of the policies directory.
    """
    # Given: POLICIES_DIR is set to a non-existent directory
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", "/non/existent/directory")
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected message
    expected_calls = [
        ("info", ("No policies directory found.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_empty_dir(tmp_path, monkeypatch):
    """
    Test behavior when the policies directory is empty.
    This test ensures that the function logs a message indicating no known
    applications with policies are found.
    """
    # Given: An empty mock POLICIES_DIR
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected message
    expected_calls = [
        ("info", ("No known applications with policies.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_invalid_policy_file(tmp_path, monkeypatch):
    """
    Test behavior when a policy file is invalid.
    This test ensures that the function logs a warning for invalid policy files
    while listing known applications.
    """
    # Given: A mock POLICIES_DIR with an invalid policy file
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app1_dir = mock_policies_dir / "app1"
    app1_dir.mkdir()
    (app1_dir / "policy.json").write_text("Invalid JSON")

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected messages
    expected_calls = [
        ("info", ("Known applications with policies:",)),
        ("warning", ("- %s (Invalid policy file)", "app1"))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_delete_all_policies_with_policies(tmp_path, monkeypatch):
    """
    Test deleting all policies when policies exist.
    This test ensures that all policy directories are removed and appropriate
    log messages are generated.
    """
    # Given: A mock POLICIES_DIR with policy directories
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    (mock_policies_dir / "app1").mkdir()
    (mock_policies_dir / "app2").mkdir()

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.delete_all_policies()

    # Then: The directories should be deleted, and the logger should log the deletions
    assert not any(mock_policies_dir.iterdir())  # Directory should be empty
    expected_calls = [
        ("info", ("Deleted policies for %s.", "app1")),
        ("info", ("Deleted policies for %s.", "app2")),
        ("info", ("All policies deleted.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_delete_all_policies_no_policies_dir(monkeypatch):
    """
    Test deleting all policies when the policies directory does not exist.
    This test ensures that the function logs a message indicating the absence
    of the policies directory.
    """
    # Given: POLICIES_DIR is set to a non-existent directory
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", "/non/existent/directory")
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    # When: The function is called
    policy_manager.delete_all_policies()

    # Then: The logger should be called with the expected message
    expected_calls = [
        ("info", ("No policies directory found.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_policy_class_initialization():
    """
    Test initialization of the Policy class.
    This test ensures that the Policy class correctly initializes its attributes.
    """
    # Given: Policy attributes
    path = "/path/to/program"
    hash_value = "abc123"
    syscall = 42
    decision = "ALLOW"
    user = "test_user"
    parameter = "test_parameter"

    # When: A Policy instance is created
    policy = policy_manager.Policy(path, hash_value, syscall, decision, user, parameter)

    # Then: The attributes should be correctly initialized
    assert policy.path == path
    assert policy.name == "program"
    assert policy.hash_value == hash_value
    assert policy.syscall == syscall
    assert policy.decision == decision
    assert policy.user == user
    assert policy.parameter == parameter


def test_policy_class_default_values():
    """
    Test default values of the Policy class.
    This test ensures that the Policy class assigns default values to optional attributes.
    """
    # Given: Required Policy attributes
    path = "/path/to/program"
    hash_value = "abc123"
    syscall = 42
    decision = "DENY"

    # When: A Policy instance is created without optional attributes
    policy = policy_manager.Policy(path, hash_value, syscall, decision)

    # Then: The optional attributes should have default values
    assert policy.user == "user123"
    assert policy.parameter == "parameter"


def test_save_decision_creates_new_policy_file(tmp_path, monkeypatch):
    """
    Test saving a decision creates a new policy file.
    This test ensures that a new policy file is created with the correct content
    when no existing policy file is present.
    """
    # Given: A mock POLICIES_DIR and a Policy instance
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    policy = policy_manager.Policy(
        path="/path/to/program",
        hash_value="abc123",
        syscall=42,
        decision="ALLOW",
        user="test_user",
        parameter="test_parameter"
    )

    # When: The save_decision function is called
    policy_manager.save_decision(policy)

    # Then: A new policy file should be created with the correct content
    policy_file = mock_policies_dir / "abc123" / "policy.json"
    assert policy_file.exists()

    with open(policy_file, "r", encoding="utf-8") as file:
        data = json.load(file)
        assert data["metadata"]["process_name"] == "program"
        assert data["metadata"]["process_path"] == "/path/to/program"
        assert data["metadata"]["approved_by"] == "test_user"
        assert data["rules"]["allowed_syscalls"] == [[42, "test_parameter"]]
        assert data["rules"]["denied_syscalls"] == []


def test_save_decision_updates_existing_policy_file(tmp_path, monkeypatch):
    """
    Test saving a decision updates an existing policy file.
    This test ensures that an existing policy file is updated with the new decision.
    """
    # Given: A mock POLICIES_DIR with an existing policy file
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app_dir = mock_policies_dir / "abc123"
    app_dir.mkdir()
    existing_policy = {
        "metadata": {
            "process_name": "program",
            "process_path": "/path/to/program",
            "approved_by": "test_user",
            "last_modified": None
        },
        "rules": {
            "allowed_syscalls": [[42, "test_parameter"]],
            "denied_syscalls": []
        }
    }
    policy_file = app_dir / "policy.json"
    with open(policy_file, "w", encoding="utf-8") as file:
        json.dump(existing_policy, file)

    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    policy = policy_manager.Policy(
        path="/path/to/program",
        hash_value="abc123",
        syscall=43,
        decision="DENY",
        user="test_user",
        parameter="new_parameter"
    )

    # When: The save_decision function is called
    policy_manager.save_decision(policy)

    # Then: The existing policy file should be updated with the new decision
    with open(policy_file, "r", encoding="utf-8") as file:
        data = json.load(file)
        assert data["rules"]["allowed_syscalls"] == [[42, "test_parameter"]]
        assert data["rules"]["denied_syscalls"] == [[43, "new_parameter"]]


def test_save_decision_handles_invalid_policy_file(tmp_path, monkeypatch):
    """
    Test saving a decision handles an invalid policy file.
    This test ensures that an invalid policy file is reinitialized with the new decision.
    """
    # Given: A mock POLICIES_DIR with an invalid policy file
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app_dir = mock_policies_dir / "abc123"
    app_dir.mkdir()
    policy_file = app_dir / "policy.json"
    policy_file.write_text("Invalid JSON")

    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.LOGGER", mock_logger)

    policy = policy_manager.Policy(
        path="/path/to/program",
        hash_value="abc123",
        syscall=42,
        decision="ALLOW",
        user="test_user",
        parameter="test_parameter"
    )

    # When: The save_decision function is called
    policy_manager.save_decision(policy)

    # Then: The invalid policy file should be reinitialized with the new decision
    with open(policy_file, "r", encoding="utf-8") as file:
        data = json.load(file)
        assert data["metadata"]["process_name"] == "program"
        assert data["metadata"]["process_path"] == "/path/to/program"
        assert data["metadata"]["approved_by"] == "test_user"
        assert data["rules"]["allowed_syscalls"] == [[42, "test_parameter"]]
        assert data["rules"]["denied_syscalls"] == []
