import pytest
import os
import json
import sys
from unittest.mock import MagicMock
from pathlib import Path

# Add the project root to sys.path
sys.path.append(str(Path(__file__).resolve().parent.parent))

# Delegate variables to policy_manager
from shared.logging_config import configure_logging
logger = configure_logging("test_user_tool.log", "Test-User-Tool")
from user_tool import policy_manager 


def test_list_known_apps_with_policies(tmp_path, monkeypatch):
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
    monkeypatch.setattr("user_tool.policy_manager.logger", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected messages in order
    expected_calls = [
        ("info", ("Known applications with policies:",)),
        ("info", ("- App1 (Hash: app1)",)),
        ("info", ("- App2 (Hash: app2)",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_no_policies_dir(monkeypatch):
    # Given: POLICIES_DIR is set to a non-existent directory
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", "/non/existent/directory")
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.logger", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected message
    expected_calls = [
        ("info", ("No policies directory found.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_empty_dir(tmp_path, monkeypatch):
    # Given: An empty mock POLICIES_DIR
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.logger", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected message
    expected_calls = [
        ("info", ("No known applications with policies.",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls


def test_list_known_apps_invalid_policy_file(tmp_path, monkeypatch):
    # Given: A mock POLICIES_DIR with an invalid policy file
    mock_policies_dir = tmp_path / "policies"
    mock_policies_dir.mkdir()
    app1_dir = mock_policies_dir / "app1"
    app1_dir.mkdir()
    (app1_dir / "policy.json").write_text("Invalid JSON")

    # And: Monkeypatch POLICIES_DIR and logger
    monkeypatch.setattr("user_tool.policy_manager.POLICIES_DIR", str(mock_policies_dir))
    mock_logger = MagicMock()
    monkeypatch.setattr("user_tool.policy_manager.logger", mock_logger)

    # When: The function is called
    policy_manager.list_known_apps()

    # Then: The logger should be called with the expected messages
    expected_calls = [
        ("info", ("Known applications with policies:",)),
        ("warning", ("- app1 (Invalid policy file)",))
    ]
    actual_calls = [(call[0], call[1]) for call in mock_logger.mock_calls]
    assert expected_calls == actual_calls