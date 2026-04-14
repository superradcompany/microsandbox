"""Shared fixtures for microsandbox SDK tests."""

import pytest


@pytest.fixture
def sandbox_name(request):
    """Generate a unique sandbox name for each test."""
    return f"test-{request.node.name.replace('[', '-').replace(']', '')}"
