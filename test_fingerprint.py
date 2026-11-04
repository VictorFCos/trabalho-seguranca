"""
test_fingerprint.py - Testes da função fingerprint:
1. Retorna string de exatamente 16 caracteres hexadecimais.
2. Determinismo: mesma chave produz sempre o mesmo fingerprint.
3. Sensibilidade: chaves com 1 bit de diferença produzem fingerprints completamente distintos.
4. Compatibilidade com objetos de chave X25519 e RSA.
"""

import hashlib
import os
from cryptography.hazmat.primitives.asymmetric import x25519, rsa
import protocol
from protocol import fingerprint, public_key_der


def run_tests():
    # -------------------------------------------------------------
    # 1. Teste de formato básico (16 caracteres hexadecimais)
    # -------------------------------------------------------------
    sample_pk = os.urandom(32)
    fp = fingerprint(sample_pk)

    assert isinstance(fp, str)
    assert len(fp) == 16, f"Esperado 16 caracteres, obtido {len(fp)}"
    # Valida se é hexadecimal válido
    int(fp, 16)

    # Confere cálculo manual
    expected_fp = hashlib.sha256(sample_pk).hexdigest()[:16]
    assert fp == expected_fp
    print(f"✓ Teste 1 (Formato e exatidão): SUCESSO (fp={fp})")

    # -------------------------------------------------------------
    # 2. Teste de determinismo e sensibilidade a 1 bit
    # -------------------------------------------------------------
    fp_repetido = fingerprint(sample_pk)
    assert fp == fp_repetido

    sample_pk_mod = sample_pk[:-1] + bytes([sample_pk[-1] ^ 0x01])
    fp_mod = fingerprint(sample_pk_mod)
    assert fp != fp_mod
    print("✓ Teste 2 (Determinismo e sensibilidade a 1 bit): SUCESSO")

    # -------------------------------------------------------------
    # 3. Teste com objetos de chave X25519 e RSA
    # -------------------------------------------------------------
    # Chave X25519
    sk_x = x25519.X25519PrivateKey.generate()
    pk_x = sk_x.public_key()
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    pk_x_raw = pk_x.public_bytes(Encoding.Raw, PublicFormat.Raw)

    fp_from_obj = fingerprint(pk_x_raw)
    assert len(fp_from_obj) == 16
    print(f"✓ Teste 3.1 (Chave pública X25519 raw): SUCESSO (fp={fp_from_obj})")

    # Chave RSA
    sk_rsa = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pk_rsa = sk_rsa.public_key()
    fp_rsa = fingerprint(pk_rsa)
    assert len(fp_rsa) == 16
    print(f"✓ Teste 3.2 (Chave pública RSA): SUCESSO (fp={fp_rsa})")

    print("\nTodos os testes de fingerprint passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
