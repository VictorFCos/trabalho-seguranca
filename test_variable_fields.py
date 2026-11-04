"""
test_variable_fields.py - Testes de pack_field e unpack_field:
1. Ida e volta (roundtrip): campo com dados normais, binários e vazio.
2. Múltiplos campos sequenciais (verificando o avanço correto do offset).
3. Buffers truncados: menos de 2 bytes para ler tamanho, e tamanho declarado maior que os dados disponíveis.
"""

import struct
import protocol
from protocol import pack_field, unpack_field, ProtocolError, ErrorCode


def run_tests():
    # -------------------------------------------------------------
    # 1. Teste de ida e volta (roundtrip)
    # -------------------------------------------------------------
    # Caso 1: Dados normais
    data1 = b"Chave Publica DER de Teste"
    packed1 = pack_field(data1)
    assert len(packed1) == 2 + len(data1)
    unpacked1, next_offset1 = unpack_field(packed1, 0)
    assert unpacked1 == data1
    assert next_offset1 == len(packed1)
    print("✓ Teste 1.1 (Roundtrip dados normais): SUCESSO")

    # Caso 2: Campo vazio (0 bytes de dados)
    data_empty = b""
    packed_empty = pack_field(data_empty)
    assert packed_empty == b"\x00\x00"
    unpacked_empty, next_offset_empty = unpack_field(packed_empty, 0)
    assert unpacked_empty == b""
    assert next_offset_empty == 2
    print("✓ Teste 1.2 (Roundtrip campo vazio): SUCESSO")

    # Caso 3: Múltiplos campos concatenados em sequência
    field_a = b"Primeiro Campo"
    field_b = b"Segundo Campo de Teste"
    field_c = bytes(range(256))  # binário arbitrário
    buffer = pack_field(field_a) + pack_field(field_b) + pack_field(field_c)

    res_a, off = unpack_field(buffer, 0)
    res_b, off = unpack_field(buffer, off)
    res_c, off = unpack_field(buffer, off)

    assert res_a == field_a
    assert res_b == field_b
    assert res_c == field_c
    assert off == len(buffer)
    print("✓ Teste 1.3 (Roundtrip múltiplos campos sequenciais): SUCESSO")

    # -------------------------------------------------------------
    # 2. Testes de buffers truncados
    # -------------------------------------------------------------
    # Caso 2.1: Menos de 2 bytes disponíveis no buffer
    try:
        unpack_field(b"\x00", 0)
        assert False, "Deveria ter lançado ProtocolError"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.1 (Buffer menor que 2 bytes rejeitado): SUCESSO")

    # Caso 2.2: Offset apontando para além do buffer
    try:
        unpack_field(b"\x00\x0512345", offset=7)
        assert False, "Deveria ter lançado ProtocolError"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.2 (Offset além do fim rejeitado): SUCESSO")

    # Caso 2.3: Prefixo declara tamanho maior que o buffer restante
    # Declarando 10 bytes (0x000A), mas fornecendo apenas 4 bytes
    truncated_buf = struct.pack(">H", 10) + b"1234"
    try:
        unpack_field(truncated_buf, 0)
        assert False, "Deveria ter lançado ProtocolError"
    except ProtocolError as e:
        assert e.code == ErrorCode.FRAMING_INVALID
        print("✓ Teste 2.3 (Prefixo maior que os bytes restantes rejeitado): SUCESSO")

    print("\nTodos os testes de campos variáveis passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
