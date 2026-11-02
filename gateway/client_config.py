
"""Load PQVPN multi-client credentials from a local JSON file.

Experimental local configuration. Never commit actual credentials.
On POSIX, group/other file permissions are rejected.
"""

import json
import os
from pathlib import Path

from gateway.client_credentials import (
    ClientCredentialRegistry,
    CredentialError,
)


class ClientConfigError(ValueError):
    """Invalid or unsafe multi-client configuration."""


def _reject_duplicate_keys(pairs):
    result = {}

    for key, value in pairs:
        if key in result:
            raise ClientConfigError("Duplicate JSON key")
        result[key] = value

    return result


def load_client_config(path):
    """Return a registry populated from a validated JSON file."""
    path = Path(path)

    if not path.is_file() or path.is_symlink():
        raise ClientConfigError(
            "Configuration must be a regular non-symlink file"
        )

    stat = path.stat()

    if stat.st_size > 65536:
        raise ClientConfigError("Configuration exceeds size limit")

    if os.name == "posix" and stat.st_mode & 0o077:
        raise ClientConfigError(
            "Credential file must not be accessible by group or others"
        )

    try:
        with path.open("r", encoding="utf-8") as handle:
            data = json.load(
                handle,
                object_pairs_hook=_reject_duplicate_keys,
            )
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ClientConfigError(
            "Unable to read credential configuration"
        ) from exc

    if not isinstance(data, dict) or set(data) != {"clients"}:
        raise ClientConfigError("Invalid configuration structure")

    clients = data["clients"]

    if not isinstance(clients, list) or not clients:
        raise ClientConfigError("Client list must not be empty")

    registry = ClientCredentialRegistry()

    for entry in clients:
        if (
            not isinstance(entry, dict)
            or set(entry) != {"client_id", "psk_hex"}
        ):
            raise ClientConfigError("Invalid client entry")

        client_id = entry["client_id"]
        psk_hex = entry["psk_hex"]

        if not isinstance(psk_hex, str) or len(psk_hex) != 64:
            raise ClientConfigError("Invalid PSK encoding")

        try:
            psk = bytes.fromhex(psk_hex)
            registry.add_client(client_id, psk)
        except (ValueError, CredentialError) as exc:
            raise ClientConfigError(
                "Invalid or duplicate client credential"
            ) from exc

    return registry
