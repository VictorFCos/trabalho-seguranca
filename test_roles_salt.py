"""
test_roles_salt.py - Testes de papéis do par (i_am_a) e derivação determinística do salt (pair_salt):
1. Testar que com dois IDs diferentes, os dois lados chegam exatamente ao mesmo salt_par.
2. Testar ordenação lexicográfica byte a byte.
3. Testar rejeição de IDs iguais (my_id == peer_id).
4. Testar consistência com múltiplos pares aleatórios.
"""

import os
import protocol
from protocol import (
    ProtocolError,
    i_am_a,
    pair_salt,
)


def run_tests():
    # -------------------------------------------------------------
    # 1. Teste determinístico com dois clientes: Cliente 1 e Cliente 2
    # -------------------------------------------------------------
    # Criamos dois IDs garantindo que id_1 < id_2
    id_1 = b"\x01" + os.urandom(15)
    id_2 = b"\x02" + os.urandom(15)

    salt_1 = os.urandom(16)
    salt_2 = os.urandom(16)

    # Perspectiva do Cliente 1
    assert i_am_a(id_1, id_2) is True
    salt_conhecido_por_1 = pair_salt(id_1, id_2, salt_1, salt_2)

    # Perspectiva do Cliente 2
    assert i_am_a(id_2, id_1) is False
    salt_conhecido_por_2 = pair_salt(id_2, id_1, salt_2, salt_1)

    # Ambos os lados DEVEM convergir para o salt do Cliente 1 (menor ID)
    assert salt_conhecido_por_1 == salt_conhecido_por_2 == salt_1
    print("✓ Teste 1 (Ambos os lados convergem para o mesmo salt do participante A): SUCESSO")

    # -------------------------------------------------------------
    # 2. Teste de consistência em múltiplos pares aleatórios
    # -------------------------------------------------------------
    for _ in range(50):
        id_a = os.urandom(16)
        id_b = os.urandom(16)
        if id_a == id_b:
            continue

        salt_a = os.urandom(16)
        salt_b = os.urandom(16)

        # Lado A calculando
        s_from_a = pair_salt(id_a, id_b, salt_a, salt_b)
        # Lado B calculando
        s_from_b = pair_salt(id_b, id_a, salt_b, salt_a)

        assert s_from_a == s_from_b
        # Deve ser o salt de quem for menor
        if id_a < id_b:
            assert s_from_a == salt_a
            assert i_am_a(id_a, id_b) is True
            assert i_am_a(id_b, id_a) is False
        else:
            assert s_from_a == salt_b
            assert i_am_a(id_a, id_b) is False
            assert i_am_a(id_b, id_a) is True

    print("✓ Teste 2 (50 iterações aleatórias convergiram perfeitamente): SUCESSO")

    # -------------------------------------------------------------
    # 3. Teste de rejeição quando my_id == peer_id
    # -------------------------------------------------------------
    same_id = os.urandom(16)
    try:
        i_am_a(same_id, same_id)
        assert False, "Deveria rejeitar IDs idênticos"
    except ProtocolError:
        print("✓ Teste 3.1 (i_am_a rejeita IDs iguais): SUCESSO")

    try:
        pair_salt(same_id, same_id, salt_1, salt_2)
        assert False, "Deveria rejeitar IDs idênticos"
    except ProtocolError:
        print("✓ Teste 3.2 (pair_salt rejeita IDs iguais): SUCESSO")

    print("\nTodos os testes de papéis do par e salt passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
