"""
Project Registry Module
=======================

Cross-platform project registry for storing project name to path mappings.
Supports Windows, macOS, and Linux with platform-specific config directories.
"""

import json
import logging
import os
import stat
import sys
import tempfile
import shutil
import time
from datetime import datetime
from pathlib import Path
from typing import Any

# Module logger
logger = logging.getLogger(__name__)


# =============================================================================
# Exceptions
# =============================================================================

class RegistryError(Exception):
    """Base registry exception."""
    pass


class RegistryNotFound(RegistryError):
    """Registry file doesn't exist."""
    pass


class RegistryCorrupted(RegistryError):
    """Registry JSON is malformed."""
    pass


class RegistryPermissionDenied(RegistryError):
    """Can't read/write registry file."""
    pass


# =============================================================================
# Registry Lock (Cross-Platform)
# =============================================================================

class RegistryLock:
    """
    Context manager for registry file locking.
    Uses fcntl on Unix and msvcrt on Windows.
    """

    def __init__(self, registry_path: Path):
        self.registry_path = registry_path
        self.lock_path = registry_path.with_suffix('.lock')
        self._file = None

    def __enter__(self):
        self.lock_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.lock_path, 'w')

        try:
            if sys.platform == "win32":
                import msvcrt
                # Windows: msvcrt.LK_NBLCK is non-blocking, so we retry with backoff
                max_attempts = 10
                for attempt in range(max_attempts):
                    try:
                        msvcrt.locking(self._file.fileno(), msvcrt.LK_NBLCK, 1)
                        break  # Lock acquired
                    except OSError:
                        if attempt == max_attempts - 1:
                            raise  # Give up after max attempts
                        time.sleep(0.1 * (attempt + 1))  # Exponential backoff
            else:
                import fcntl
                fcntl.flock(self._file.fileno(), fcntl.LOCK_EX)
        except Exception as e:
            self._file.close()
            raise RegistryError(f"Could not acquire registry lock: {e}") from e

        return self

    def __exit__(self, *args):
        if self._file:
            try:
                if sys.platform != "win32":
                    import fcntl
                    fcntl.flock(self._file.fileno(), fcntl.LOCK_UN)
            finally:
                self._file.close()
                try:
                    self.lock_path.unlink(missing_ok=True)
                except Exception:
                    pass


# =============================================================================
# Registry Path Functions
# =============================================================================

def get_config_dir() -> Path:
    """
    Get the platform-specific config directory for the application.

    Returns:
        - Windows: %APPDATA%/autonomous-coder/
        - macOS: ~/Library/Application Support/autonomous-coder/
        - Linux: ~/.config/autonomous-coder/ (or $XDG_CONFIG_HOME)
    """
    if sys.platform == "win32":
        base = Path(os.getenv("APPDATA", Path.home() / "AppData" / "Roaming"))
    elif sys.platform == "darwin":
        base = Path.home() / "Library" / "Application Support"
    else:  # Linux and other Unix-like
        base = Path(os.getenv("XDG_CONFIG_HOME", Path.home() / ".config"))

    config_dir = base / "autonomous-coder"
    config_dir.mkdir(parents=True, exist_ok=True)
    return config_dir


def get_registry_path() -> Path:
    """Get the path to the projects registry file."""
    return get_config_dir() / "projects.json"


# =============================================================================
# Registry I/O Functions
# =============================================================================

def _create_empty_registry() -> dict[str, Any]:
    """Create a new empty registry structure."""
    return {
        "version": 1,
        "created_at": datetime.now().isoformat(),
        "projects": {}
    }


def load_registry(create_if_missing: bool = True) -> dict[str, Any]:
    """
    Load the registry from disk.

    Args:
        create_if_missing: If True, create a new registry if none exists.

    Returns:
        The registry dictionary.

    Raises:
        RegistryNotFound: If registry doesn't exist and create_if_missing is False.
        RegistryCorrupted: If registry JSON is malformed.
        RegistryPermissionDenied: If can't read the registry file.
    """
    registry_path = get_registry_path()

    # Case 1: File doesn't exist
    if not registry_path.exists():
        if create_if_missing:
            registry = _create_empty_registry()
            save_registry(registry)
            return registry
        else:
            raise RegistryNotFound(f"Registry not found: {registry_path}")

    # Case 2: Read the file
    try:
        content = registry_path.read_text(encoding='utf-8')
    except PermissionError as e:
        raise RegistryPermissionDenied(f"Cannot read registry: {e}") from e
    except OSError as e:
        raise RegistryError(f"Error reading registry: {e}") from e

    # Case 3: Parse JSON
    try:
        data = json.loads(content)
    except json.JSONDecodeError as e:
        # Try to recover from backup
        backup_path = registry_path.with_suffix('.json.backup')
        logger.warning("Registry corrupted, attempting recovery from backup: %s", backup_path)
        if backup_path.exists():
            try:
                backup_content = backup_path.read_text(encoding='utf-8')
                data = json.loads(backup_content)
                # Restore from backup
                shutil.copy2(backup_path, registry_path)
                logger.info("Successfully recovered registry from backup")
                return data
            except Exception as recovery_error:
                logger.error("Failed to recover from backup: %s", recovery_error)
        raise RegistryCorrupted(
            f"Registry corrupted: {e}\nBackup location: {backup_path}"
        ) from e

    # Ensure required structure
    if "projects" not in data:
        data["projects"] = {}
    if "version" not in data:
        data["version"] = 1

    return data


def save_registry(registry: dict[str, Any]) -> None:
    """
    Save the registry to disk atomically.

    Uses temp file + rename for atomic writes to prevent corruption.

    Args:
        registry: The registry dictionary to save.

    Raises:
        RegistryPermissionDenied: If can't write to the registry.
        RegistryError: If write fails for other reasons.
    """
    registry_path = get_registry_path()
    registry_path.parent.mkdir(parents=True, exist_ok=True)

    # Create backup before modification (if file exists)
    if registry_path.exists():
        backup_path = registry_path.with_suffix('.json.backup')
        try:
            shutil.copy2(registry_path, backup_path)
        except Exception as e:
            logger.warning("Failed to create registry backup: %s", e)

    # Write to temp file in same directory (ensures same filesystem for atomic rename)
    # On Windows, we must close the file before renaming it
    tmp_path = None
    try:
        # Create temp file
        fd, tmp_name = tempfile.mkstemp(suffix='.json', dir=registry_path.parent)
        tmp_path = Path(tmp_name)

        try:
            # Write content
            with os.fdopen(fd, 'w', encoding='utf-8') as tmp_file:
                json.dump(registry, tmp_file, indent=2)
                tmp_file.flush()
                os.fsync(tmp_file.fileno())
            # File is now closed, safe to rename on Windows

            # Atomic rename
            tmp_path.replace(registry_path)

            # Set restrictive permissions (owner read/write only)
            # On Windows, this is a best-effort operation
            try:
                if sys.platform != "win32":
                    registry_path.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0o600
            except Exception:
                pass  # Best effort - don't fail if permissions can't be set
        except Exception:
            if tmp_path and tmp_path.exists():
                tmp_path.unlink(missing_ok=True)
            raise
    except PermissionError as e:
        raise RegistryPermissionDenied(f"Cannot write registry: {e}") from e
    except OSError as e:
        raise RegistryError(f"Failed to write registry: {e}") from e


# =============================================================================
# Project CRUD Functions
# =============================================================================

def register_project(name: str, path: Path) -> None:
    """
    Register a new project in the registry.

    Args:
        name: The project name (unique identifier).
        path: The absolute path to the project directory.

    Raises:
        ValueError: If project name is invalid or path is not absolute.
        RegistryError: If a project with that name already exists.
    """
    # Validate name
    import re
    if not re.match(r'^[a-zA-Z0-9_-]{1,50}$', name):
        raise ValueError(
            "Invalid project name. Use only letters, numbers, hyphens, "
            "and underscores (1-50 chars)."
        )

    # Ensure path is absolute
    path = Path(path).resolve()

    with RegistryLock(get_registry_path()):
        registry = load_registry()

        if name in registry["projects"]:
            logger.warning("Attempted to register duplicate project: %s", name)
            raise RegistryError(f"Project '{name}' already exists in registry")

        # Store path as POSIX format (forward slashes) for cross-platform consistency
        registry["projects"][name] = {
            "path": path.as_posix(),
            "created_at": datetime.now().isoformat()
        }

        save_registry(registry)
        logger.info("Registered project '%s' at path: %s", name, path)


def unregister_project(name: str) -> bool:
    """
    Remove a project from the registry.

    Args:
        name: The project name to remove.

    Returns:
        True if removed, False if project wasn't found.
    """
    with RegistryLock(get_registry_path()):
        registry = load_registry()

        if name not in registry["projects"]:
            logger.debug("Attempted to unregister non-existent project: %s", name)
            return False

        del registry["projects"][name]
        save_registry(registry)
        logger.info("Unregistered project: %s", name)
        return True


def get_project_path(name: str) -> Path | None:
    """
    Look up a project's path by name.

    Args:
        name: The project name.

    Returns:
        The project Path, or None if not found.
    """
    registry = load_registry()
    project = registry["projects"].get(name)

    if project is None:
        return None

    # Convert POSIX path string back to Path object
    return Path(project["path"])


def list_registered_projects() -> dict[str, dict[str, Any]]:
    """
    Get all registered projects.

    Returns:
        Dictionary mapping project names to their info dictionaries.
    """
    registry = load_registry()
    return registry.get("projects", {})


def get_project_info(name: str) -> dict[str, Any] | None:
    """
    Get full info about a project.

    Args:
        name: The project name.

    Returns:
        Project info dictionary, or None if not found.
    """
    registry = load_registry()
    return registry["projects"].get(name)


def update_project_path(name: str, new_path: Path) -> bool:
    """
    Update a project's path (for relocating projects).

    Args:
        name: The project name.
        new_path: The new absolute path.

    Returns:
        True if updated, False if project wasn't found.
    """
    new_path = Path(new_path).resolve()

    with RegistryLock(get_registry_path()):
        registry = load_registry()

        if name not in registry["projects"]:
            return False

        registry["projects"][name]["path"] = new_path.as_posix()
        save_registry(registry)
        return True


# =============================================================================
# Validation Functions
# =============================================================================

def validate_project_path(path: Path) -> tuple[bool, str]:
    """
    Validate that a project path is accessible and writable.

    Args:
        path: The path to validate.

    Returns:
        Tuple of (is_valid, error_message).
    """
    path = Path(path).resolve()

    # Check if path exists
    if not path.exists():
        return False, f"Path does not exist: {path}"

    # Check if it's a directory
    if not path.is_dir():
        return False, f"Path is not a directory: {path}"

    # Check read permissions
    if not os.access(path, os.R_OK):
        return False, f"No read permission: {path}"

    # Check write permissions
    if not os.access(path, os.W_OK):
        return False, f"No write permission: {path}"

    return True, ""


def cleanup_stale_projects() -> list[str]:
    """
    Remove projects from registry whose paths no longer exist.

    Returns:
        List of removed project names.
    """
    removed = []

    with RegistryLock(get_registry_path()):
        registry = load_registry()
        projects = registry.get("projects", {})

        stale_names = []
        for name, info in projects.items():
            path = Path(info["path"])
            if not path.exists():
                stale_names.append(name)

        for name in stale_names:
            del projects[name]
            removed.append(name)

        if removed:
            save_registry(registry)

    return removed


def list_valid_projects() -> list[dict[str, Any]]:
    """
    List all projects that have valid, accessible paths.

    Returns:
        List of project info dicts with additional 'name' field.
    """
    registry = load_registry()
    projects = registry.get("projects", {})

    valid = []
    for name, info in projects.items():
        path = Path(info["path"])
        is_valid, _ = validate_project_path(path)
        if is_valid:
            valid.append({
                "name": name,
                "path": info["path"],
                "created_at": info.get("created_at")
            })

    return valid
