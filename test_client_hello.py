"""
test_client_hello.py - Testes de pack_client_hello e parse_client_hello:
1. Ida e volta (roundtrip) com dados válidos: tamanho exatamente 49 bytes.
2. Rejeição de tamanhos diferentes de 49 (48 bytes, 50 bytes, vazio).
3. Rejeição de tipo diferente de 0x01.
4. Validação na montagem (pack com tamanhos de chaves incorretos).
"""

import os
import protocol
from protocol import (
    CLIENT_HELLO_LEN,
    FrameType,
    ErrorCode,
    ProtocolError,
    pack_client_hello,
    parse_client_hello,
)


def run_tests():
    # -------------------------------------------------------------
    # 1. Teste de ida e volta (roundtrip)
    # -------------------------------------------------------------
    sample_client_id = os.urandom(16)
    sample_pk = os.urandom(32)

    packed = pack_client_hello(sample_client_id, sample_pk)
    assert len(packed) == CLIENT_HELLO_LEN == 49
    assert packed[0] == FrameType.CLIENT_HELLO

    hello = parse_client_hello(packed)
    assert hello.client_id == sample_client_id
    assert hello.pk_client == sample_pk
    # Permite desempacotamento de tupla
    cid, pk = hello
    assert cid == sample_client_id
    assert pk == sample_pk
    print("✓ Teste 1 (Roundtrip CLIENT_HELLO 49 bytes): SUCESSO")

    # -------------------------------------------------------------
    # 2. Rejeição de tamanhos incorretos
    # -------------------------------------------------------------
    # 48 bytes (1 a menos)
    try:
        parse_client_hello(packed[:48])
        assert False, "Deveria falhar com 48 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.1 (Tamanho 48 bytes rejeitado): SUCESSO")

    # 50 bytes (1 a mais)
    try:
        parse_client_hello(packed + b"\x00")
        assert False, "Deveria falhar com 50 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.2 (Tamanho 50 bytes rejeitado): SUCESSO")

    # Buffer vazio
    try:
        parse_client_hello(b"")
        assert False, "Deveria falhar com buffer vazio"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.3 (Buffer vazio rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 3. Rejeição de tipo incorreto
    # -------------------------------------------------------------
    wrong_type_data = bytes([FrameType.SERVER_HELLO]) + packed[1:]
    assert len(wrong_type_data) == 49
    try:
        parse_client_hello(wrong_type_data)
        assert False, "Deveria falhar com tipo != 0x01"
    except ProtocolError as e:
        assert e.code == ErrorCode.UNKNOWN_TYPE
        print("✓ Teste 3 (Tipo incorreto != 0x01 rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 4. Validação na montagem (pack)
    # -------------------------------------------------------------
    try:
        pack_client_hello(b"id_curto", sample_pk)
        assert False, "Deveria falhar com client_id inválido"
    except ProtocolError:
        print("✓ Teste 4.1 (pack rejeita client_id != 16B): SUCESSO")

    try:
        pack_client_hello(sample_client_id, b"pk_curta")
        assert False, "Deveria falhar com pk_client inválida"
    except ProtocolError:
        print("✓ Teste 4.2 (pack rejeita pk_client != 32B): SUCESSO")

    print("\nTodos os testes de CLIENT_HELLO passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
