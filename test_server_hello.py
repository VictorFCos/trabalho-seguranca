"""
test_server_hello.py - Testes de pack_server_hello e parse_server_hello:
1. Ida e volta (roundtrip) com dados válidos (salt 16B e 3 campos variáveis).
2. Frame com 1 byte a mais no final (rejeitado por sobra).
3. Frame com 1 byte a menos no final (rejeitado por truncamento).
4. Frame com menos de 23 bytes (mínimo absoluto).
5. Frame com tipo diferente de 0x02.
6. Validação na montagem (pack com salt != 16B).
"""

import os
import protocol
from protocol import (
    SERVER_HELLO_MIN_LEN,
    FrameType,
    ErrorCode,
    ProtocolError,
    pack_server_hello,
    parse_server_hello,
)


def run_tests():
    # Dados de exemplo
    sample_salt = os.urandom(16)
    sample_pk_s = b"\x30\x82\x01\x22" + os.urandom(60)     # simulação DER pk_S
    sample_cert = b"\x30\x82\x02\x40" + os.urandom(120)    # simulação DER cert
    sample_sig = os.urandom(256)                            # simulação RSA 2048 sig

    # -------------------------------------------------------------
    # 1. Teste de ida e volta (roundtrip)
    # -------------------------------------------------------------
    packed = pack_server_hello(sample_salt, sample_pk_s, sample_cert, sample_sig)
    assert packed[0] == FrameType.SERVER_HELLO
    assert len(packed) >= SERVER_HELLO_MIN_LEN

    hello = parse_server_hello(packed)
    assert hello.salt_srv == sample_salt
    assert hello.pk_server == sample_pk_s
    assert hello.server_cert == sample_cert
    assert hello.signature == sample_sig
    print("✓ Teste 1 (Roundtrip SERVER_HELLO): SUCESSO")

    # -------------------------------------------------------------
    # 2. Frame com 1 byte a mais no final (sobra)
    # -------------------------------------------------------------
    with_extra_byte = packed + b"\xff"
    try:
        parse_server_hello(with_extra_byte)
        assert False, "Deveria rejeitar frame com byte extra"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2 (Frame com 1 byte a mais rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 3. Frame com 1 byte a menos no final (truncado)
    # -------------------------------------------------------------
    with_missing_byte = packed[:-1]
    try:
        parse_server_hello(with_missing_byte)
        assert False, "Deveria rejeitar frame com byte a menos"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 3 (Frame com 1 byte a menos rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 4. Frame com menos de 23 bytes (mínimo absoluto)
    # -------------------------------------------------------------
    try:
        parse_server_hello(bytes([FrameType.SERVER_HELLO]) + os.urandom(21))  # 22 bytes
        assert False, "Deveria rejeitar frame com 22 bytes"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 4 (Frame com 22 bytes < 23 rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 5. Frame com tipo diferente de 0x02
    # -------------------------------------------------------------
    wrong_type = bytes([FrameType.CLIENT_HELLO]) + packed[1:]
    try:
        parse_server_hello(wrong_type)
        assert False, "Deveria rejeitar tipo != 0x02"
    except ProtocolError as e:
        assert e.code == ErrorCode.UNKNOWN_TYPE
        print("✓ Teste 5 (Tipo diferente de 0x02 rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 6. Validação do tamanho do salt_srv na montagem
    # -------------------------------------------------------------
    try:
        pack_server_hello(b"salt_invalido", sample_pk_s, sample_cert, sample_sig)
        assert False, "Deveria rejeitar salt != 16B"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 6 (pack rejeita salt != 16B): SUCESSO")

    print("\nTodos os testes de SERVER_HELLO passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
