"""
test_admin_messages.py - Testes de mensagens administrativas (PEER_JOINED, PEER_LEFT, ERROR):
1. Construtores de payload:
   - PEER_JOINED: 64 bytes
   - PEER_LEFT: 16 bytes
   - ERROR: 1 byte
2. Tamanho dos corpos empacotados com assinatura RSA 2048 (256B):
   - PEER_JOINED: exatamente 331 bytes
   - PEER_LEFT: exatamente 283 bytes
   - ERROR: exatamente 268 bytes
3. Desempacotamento via parse_admin (roundtrip exato dos campos).
4. Rejeição de frames com bytes sobrando ou faltando.
"""

import os
import protocol
from protocol import (
    FrameType,
    ErrorCode,
    ProtocolError,
    build_peer_joined_payload,
    build_peer_left_payload,
    build_error_payload,
    pack_admin,
    parse_admin,
)


def run_tests():
    sample_cid = os.urandom(16)
    sample_pk = os.urandom(32)
    sample_salt = os.urandom(16)
    sample_sig_rsa2048 = os.urandom(256)  # 256 bytes para chave de 2048 bits
    seq = 42

    # -------------------------------------------------------------
    # 1. PEER_JOINED
    # -------------------------------------------------------------
    p_joined = build_peer_joined_payload(sample_cid, sample_pk, sample_salt)
    assert len(p_joined) == 64, f"Payload PEER_JOINED esperado 64 bytes, obtido {len(p_joined)}"

    body_joined = pack_admin(FrameType.PEER_JOINED, p_joined, seq, sample_sig_rsa2048)
    assert len(body_joined) == 331, f"Corpo PEER_JOINED esperado 331 bytes, obtido {len(body_joined)}"
    print(f"✓ Teste 1 (PEER_JOINED): payload={len(p_joined)}B, corpo total={len(body_joined)}B (331)")

    parsed_joined = parse_admin(body_joined)
    assert parsed_joined.type == FrameType.PEER_JOINED
    assert parsed_joined.payload == p_joined
    assert parsed_joined.seq == seq
    assert parsed_joined.signature == sample_sig_rsa2048

    # -------------------------------------------------------------
    # 2. PEER_LEFT
    # -------------------------------------------------------------
    p_left = build_peer_left_payload(sample_cid)
    assert len(p_left) == 16, f"Payload PEER_LEFT esperado 16 bytes, obtido {len(p_left)}"

    body_left = pack_admin(FrameType.PEER_LEFT, p_left, seq, sample_sig_rsa2048)
    assert len(body_left) == 283, f"Corpo PEER_LEFT esperado 283 bytes, obtido {len(body_left)}"
    print(f"✓ Teste 2 (PEER_LEFT): payload={len(p_left)}B, corpo total={len(body_left)}B (283)")

    parsed_left = parse_admin(body_left)
    assert parsed_left.type == FrameType.PEER_LEFT
    assert parsed_left.payload == p_left
    assert parsed_left.seq == seq
    assert parsed_left.signature == sample_sig_rsa2048

    # -------------------------------------------------------------
    # 3. ERROR
    # -------------------------------------------------------------
    p_err = build_error_payload(ErrorCode.PEER_OFFLINE)
    assert len(p_err) == 1, f"Payload ERROR esperado 1 byte, obtido {len(p_err)}"

    body_err = pack_admin(FrameType.ERROR, p_err, seq, sample_sig_rsa2048)
    assert len(body_err) == 268, f"Corpo ERROR esperado 268 bytes, obtido {len(body_err)}"
    print(f"✓ Teste 3 (ERROR): payload={len(p_err)}B, corpo total={len(body_err)}B (268)")

    parsed_err = parse_admin(body_err)
    assert parsed_err.type == FrameType.ERROR
    assert parsed_err.payload == p_err
    assert parsed_err.payload[0] == ErrorCode.PEER_OFFLINE
    assert parsed_err.seq == seq
    assert parsed_err.signature == sample_sig_rsa2048

    # -------------------------------------------------------------
    # 4. Rejeição de sobras ou faltas
    # -------------------------------------------------------------
    # Frame com byte extra no final
    try:
        parse_admin(body_err + b"\x00")
        assert False, "Deveria falhar com byte extra"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 4.1 (parse_admin rejeita byte extra): SUCESSO")

    # Frame com byte a menos no final
    try:
        parse_admin(body_err[:-1])
        assert False, "Deveria falhar com byte faltando"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 4.2 (parse_admin rejeita truncamento): SUCESSO")

    # Tipo não administrativo (ex: CLIENT_HELLO)
    try:
        parse_admin(bytes([FrameType.CLIENT_HELLO]) + os.urandom(300))
        assert False, "Deveria rejeitar tipo não administrativo"
    except ProtocolError as e:
        assert e.code == ErrorCode.UNKNOWN_TYPE
        print("✓ Teste 4.3 (parse_admin rejeita tipo não administrativo): SUCESSO")

    print("\nTodos os testes de mensagens administrativas passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
