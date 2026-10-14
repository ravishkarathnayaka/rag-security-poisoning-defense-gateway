"""Unit tests for cryptographic provenance signing, key rotation, and tamper detection."""

from gateway.ingestion.provenance_signer import ProvenanceSigner


def test_provenance_signature_verification():
    signer = ProvenanceSigner(secret_key="primary-secret-key-1")
    signed = signer.sign_chunk(
        content="Important policy statement",
        doc_id="doc_100",
        chunk_id="chunk_0",
        author="secops",
    )
    meta = signed.to_dict()

    assert signer.verify_chunk("Important policy statement", meta) is True
    # Tampered content fails
    assert signer.verify_chunk("Tampered policy statement", meta) is False
    # Tampered metadata author fails
    meta_tampered = dict(meta)
    meta_tampered["author"] = "attacker"
    assert signer.verify_chunk("Important policy statement", meta_tampered) is False


def test_provenance_key_rotation_support():
    old_key = "legacy-secret-2025"
    new_key = "current-secret-2026"

    old_signer = ProvenanceSigner(secret_key=old_key)
    signed_old = old_signer.sign_chunk(
        content="Historical archived knowledge",
        doc_id="archive_1",
        chunk_id="c_0",
    )

    # Rotated signer includes old key in previous_keys
    rotated_signer = ProvenanceSigner(secret_key=new_key, previous_keys=[old_key])
    assert rotated_signer.verify_chunk("Historical archived knowledge", signed_old.to_dict()) is True

    # Unknown key fails
    unauthorized_signer = ProvenanceSigner(secret_key=new_key, previous_keys=["unrelated-key"])
    assert unauthorized_signer.verify_chunk("Historical archived knowledge", signed_old.to_dict()) is False
