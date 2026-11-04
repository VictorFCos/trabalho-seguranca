"""
test_data.py - Testes do frame DATA:
1. build_nonce (12B: 4B IV + 8B seq) e build_aad (40B: 16B sender + 16B recipient + 8B seq).
2. Corpo mínimo com exatamente 70 bytes: aceito por pack_data, parse_data e peek_ids.
3. Corpo máximo com exatamente 4165 bytes: aceito por pack_data, parse_data e peek_ids.
4. Corpo com 69 bytes (1 a menos que o mínimo): rejeitado com FRAMING_INVALID.
5. Corpo com 4166 bytes (1 a mais que o máximo): rejeitado com FRAME_TOO_LARGE.
6. peek_ids recupera com precisão (sender, recipient).
"""

import os
import struct
import protocol
from protocol import (
    DATA_HEADER_LEN,
    DATA_MIN_LEN,
    DATA_MAX_LEN,
    FrameType,
    ErrorCode,
    ProtocolError,
    build_nonce,
    build_aad,
    pack_data,
    parse_data,
    peek_ids,
)


def run_tests():
    sample_iv = os.urandom(4)
    sample_seq = 100
    sample_sender = os.urandom(16)
    sample_recipient = os.urandom(16)

    # -------------------------------------------------------------
    # 1. Testes de build_nonce e build_aad
    # -------------------------------------------------------------
    nonce = build_nonce(sample_iv, sample_seq)
    assert len(nonce) == 12
    assert nonce[:4] == sample_iv
    assert struct.unpack(">Q", nonce[4:])[0] == sample_seq
    print("✓ Teste 1.1 (build_nonce 12 bytes): SUCESSO")

    aad = build_aad(sample_sender, sample_recipient, sample_seq)
    assert len(aad) == 40
    assert aad[:16] == sample_sender
    assert aad[16:32] == sample_recipient
    assert struct.unpack(">Q", aad[32:40])[0] == sample_seq
    print("✓ Teste 1.2 (build_aad 40 bytes): SUCESSO")

    # -------------------------------------------------------------
    # 2. Teste com tamanho mínimo: 70 bytes (53 header + 17 payload mínimo)
    # -------------------------------------------------------------
    # 1B plaintext + 16B tag = 17B ciphertext_and_tag
    min_cipher = os.urandom(17)
    body_min = pack_data(nonce, sample_sender, sample_recipient, sample_seq, min_cipher)
    assert len(body_min) == 70 == DATA_MIN_LEN

    parsed_min = parse_data(body_min)
    assert parsed_min.nonce == nonce
    assert parsed_min.sender_id == sample_sender
    assert parsed_min.recipient_id == sample_recipient
    assert parsed_min.seq == sample_seq
    assert parsed_min.ciphertext_and_tag == min_cipher

    s_id, r_id = peek_ids(body_min)
    assert s_id == sample_sender
    assert r_id == sample_recipient
    print(f"✓ Teste 2 (Corpo mínimo de {DATA_MIN_LEN} bytes aceito): SUCESSO")

    # -------------------------------------------------------------
    # 3. Teste com tamanho máximo: 4165 bytes (53 header + 4112 payload máximo)
    # -------------------------------------------------------------
    # 4096B max plaintext + 16B tag = 4112B ciphertext_and_tag
    max_cipher = os.urandom(4112)
    body_max = pack_data(nonce, sample_sender, sample_recipient, sample_seq, max_cipher)
    assert len(body_max) == 4165 == DATA_MAX_LEN

    parsed_max = parse_data(body_max)
    assert parsed_max.nonce == nonce
    assert parsed_max.sender_id == sample_sender
    assert parsed_max.recipient_id == sample_recipient
    assert parsed_max.seq == sample_seq
    assert parsed_max.ciphertext_and_tag == max_cipher

    s_id_max, r_id_max = peek_ids(body_max)
    assert s_id_max == sample_sender
    assert r_id_max == sample_recipient
    print(f"✓ Teste 3 (Corpo máximo de {DATA_MAX_LEN} bytes aceito): SUCESSO")

    # -------------------------------------------------------------
    # 4. Teste com 69 bytes (1 a menos que o mínimo) -> Rejeitado
    # -------------------------------------------------------------
    cipher_69 = os.urandom(16)  # 53 + 16 = 69
    try:
        pack_data(nonce, sample_sender, sample_recipient, sample_seq, cipher_69)
        assert False, "pack_data deveria rejeitar 69 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    body_69 = body_min[:-1]
    assert len(body_69) == 69
    try:
        parse_data(body_69)
        assert False, "parse_data deveria rejeitar 69 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID

    try:
        peek_ids(body_69)
        assert False, "peek_ids deveria rejeitar 69 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
    print("✓ Teste 4 (Corpo de 69 bytes rejeitado com FRAMING_INVALID): SUCESSO")

    # -------------------------------------------------------------
    # 5. Teste com 4166 bytes (1 a mais que o máximo) -> Rejeitado
    # -------------------------------------------------------------
    cipher_4166 = os.urandom(4113)  # 53 + 4113 = 4166
    try:
        pack_data(nonce, sample_sender, sample_recipient, sample_seq, cipher_4166)
        assert False, "pack_data deveria rejeitar 4166 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAME_TOO_LARGE

    body_4166 = body_max + b"\x00"
    assert len(body_4166) == 4166
    try:
        parse_data(body_4166)
        assert False, "parse_data deveria rejeitar 4166 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAME_TOO_LARGE

    try:
        peek_ids(body_4166)
        assert False, "peek_ids deveria rejeitar 4166 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAME_TOO_LARGE
    print("✓ Teste 5 (Corpo de 4166 bytes rejeitado com FRAME_TOO_LARGE): SUCESSO")

    print("\nTodos os testes de DATA passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
