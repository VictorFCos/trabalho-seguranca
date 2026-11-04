"""
test_hashes.py - Testes de handshake_hash e admin_hash:
1. Validar que handshake_hash tem exatamente 32 bytes.
2. Validar que qualquer campo alterado em handshake_hash produz um hash diferente.
3. Validar que admin_hash tem exatamente 32 bytes.
4. Validar que qualquer campo alterado em admin_hash (tipo, salt, seq, payload) produz um hash diferente.
"""

import os
import protocol
from protocol import FrameType, handshake_hash, admin_hash


def run_tests():
    # -------------------------------------------------------------
    # 1. Testes de handshake_hash
    # -------------------------------------------------------------
    pk_s = b"\x30\x82\x01\x22" + os.urandom(60)
    pk_c = os.urandom(32)
    client_id = os.urandom(16)
    salt = os.urandom(16)

    h_base = handshake_hash(pk_s, pk_c, client_id, salt)
    assert len(h_base) == 32
    print("✓ Teste 1.1 (handshake_hash produz 32 bytes): SUCESSO")

    # Modificar pk_s
    pk_s_mod = pk_s[:-1] + bytes([pk_s[-1] ^ 0x01])
    assert handshake_hash(pk_s_mod, pk_c, client_id, salt) != h_base

    # Modificar pk_c
    pk_c_mod = pk_c[:-1] + bytes([pk_c[-1] ^ 0x01])
    assert handshake_hash(pk_s, pk_c_mod, client_id, salt) != h_base

    # Modificar client_id
    cid_mod = client_id[:-1] + bytes([client_id[-1] ^ 0x01])
    assert handshake_hash(pk_s, pk_c, cid_mod, salt) != h_base

    # Modificar salt
    salt_mod = salt[:-1] + bytes([salt[-1] ^ 0x01])
    assert handshake_hash(pk_s, pk_c, client_id, salt_mod) != h_base

    print("✓ Teste 1.2 (handshake_hash sensível a alterações em qualquer campo): SUCESSO")

    # -------------------------------------------------------------
    # 2. Testes de admin_hash
    # -------------------------------------------------------------
    frame_type = FrameType.PEER_JOINED
    salt_dest = os.urandom(16)
    seq = 0
    payload = b"payload_administrativo"

    h_adm_base = admin_hash(frame_type, salt_dest, seq, payload)
    assert len(h_adm_base) == 32
    print("✓ Teste 2.1 (admin_hash produz 32 bytes): SUCESSO")

    # Modificar frame_type
    assert admin_hash(FrameType.PEER_LEFT, salt_dest, seq, payload) != h_adm_base

    # Modificar salt_dest
    salt_dest_mod = salt_dest[:-1] + bytes([salt_dest[-1] ^ 0x01])
    assert admin_hash(frame_type, salt_dest_mod, seq, payload) != h_adm_base

    # Modificar seq (de 0 para 1)
    assert admin_hash(frame_type, salt_dest, 1, payload) != h_adm_base

    # Modificar payload
    assert admin_hash(frame_type, salt_dest, seq, payload + b"!") != h_adm_base

    print("✓ Teste 2.2 (admin_hash sensível a tipo, salt, seq e payload): SUCESSO")

    print("\nTodos os testes de hashes passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
