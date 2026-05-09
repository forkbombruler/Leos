"""Signed policy manifest: sign, verify, and load tamper-evident policy configs."""

from __future__ import annotations

import hashlib
import hmac
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

from .errors import PolicyConfigurationError, PolicyIntegrityError
from .policy import PolicyEngine


ALGORITHM = "hmac-sha256"


@dataclass(frozen=True)
class SignedPolicyManifest:
    policy: Dict[str, Any]
    signature: Dict[str, str]


def _canonicalize(policy_data: Mapping[str, Any]) -> bytes:
    return json.dumps(policy_data, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def sign_policy(policy_data: Mapping[str, Any], secret: str) -> SignedPolicyManifest:
    canonical = _canonicalize(policy_data)
    sig_value = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    return SignedPolicyManifest(
        policy=dict(policy_data),
        signature={"algorithm": ALGORITHM, "value": sig_value},
    )


def verify_policy_manifest(manifest: Mapping[str, Any], secret: str) -> None:
    if not isinstance(manifest, Mapping):
        raise PolicyIntegrityError("Manifest is not a JSON object")
    policy_data = manifest.get("policy")
    signature = manifest.get("signature")
    if not isinstance(policy_data, Mapping):
        raise PolicyIntegrityError("Manifest is missing 'policy'")
    if not isinstance(signature, Mapping):
        raise PolicyIntegrityError("Manifest is missing 'signature'")
    if signature.get("algorithm") != ALGORITHM:
        raise PolicyIntegrityError(f"Unsupported signature algorithm: {signature.get('algorithm')}")
    expected_sig = signature.get("value")
    if not expected_sig:
        raise PolicyIntegrityError("Signature is missing 'value'")
    canonical = _canonicalize(policy_data)
    actual_sig = hmac.new(secret.encode("utf-8"), canonical, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(actual_sig, expected_sig):
        raise PolicyIntegrityError("Policy signature verification failed — manifest may have been tampered")


def load_policy_from_file(path: Path, secret: str, *, principal: Optional[str] = None) -> PolicyEngine:
    try:
        with open(path, encoding="utf-8") as f:
            manifest = json.load(f)
    except FileNotFoundError:
        raise PolicyConfigurationError(f"Policy manifest not found: {path}")
    except json.JSONDecodeError as exc:
        raise PolicyConfigurationError(f"Invalid JSON in policy manifest: {exc}")
    verify_policy_manifest(manifest, secret)
    return PolicyEngine.from_mapping(manifest["policy"], principal=principal)


def manifest_to_json(manifest: SignedPolicyManifest) -> str:
    return json.dumps(
        {"policy": manifest.policy, "signature": manifest.signature},
        ensure_ascii=False,
        indent=2,
    ) + "\n"
