"""Test CTF manager module."""

import pytest
from ctf.manager import ChallengeManager


def test_generate_flag():
    """Test flag generation."""
    manager = ChallengeManager.__new__(ChallengeManager)

    flag = manager.generate_flag()

    assert flag.startswith("NAVAJA{")
    assert flag.endswith("}")
    assert len(flag) > 20  # Reasonable length


def test_generate_flag_custom_prefix():
    """Test flag generation with custom prefix/suffix."""
    manager = ChallengeManager.__new__(ChallengeManager)

    flag = manager.generate_flag(prefix="CTF{", suffix="}")

    assert flag.startswith("CTF{")
    assert flag.endswith("}")


def test_hash_flag():
    """Test flag hashing."""
    manager = ChallengeManager.__new__(ChallengeManager)

    flag = "NAVAJA{test_flag_123}"
    hash1 = manager.hash_flag(flag)
    hash2 = manager.hash_flag(flag)

    # Same flag should produce same hash
    assert hash1 == hash2
    assert len(hash1) == 64  # SHA256


def test_validate_flag_correct():
    """Test flag validation with correct flag."""
    manager = ChallengeManager.__new__(ChallengeManager)

    flag = "NAVAJA{correct_flag}"
    flag_hash = manager.hash_flag(flag)

    assert manager.validate_flag(flag, flag_hash) is True


def test_validate_flag_incorrect():
    """Test flag validation with incorrect flag."""
    manager = ChallengeManager.__new__(ChallengeManager)

    flag = "NAVAJA{correct_flag}"
    flag_hash = manager.hash_flag(flag)

    assert manager.validate_flag("NAVAJA{wrong_flag}", flag_hash) is False
