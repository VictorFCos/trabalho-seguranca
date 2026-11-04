"""
test_rsa_pss.py - Testes de sign_digest, verify_digest e public_key_der:
1. Gerar chave RSA 2048.
2. Conferir que o DER da chave pública tem exatamente 294 bytes.
3. Assinar e verificar com sucesso (retorna True).
4. Conferir que verificar passando a chave em bytes DER também retorna True.
5. Alterar 1 bit do digest H e conferir que verify_digest retorna False sem lançar exceção.
6. Alterar 1 bit da assinatura e conferir que verify_digest retorna False.
"""

import os
from cryptography.hazmat.primitives.asymmetric import rsa
import protocol
from protocol import public_key_der, sign_digest, verify_digest


def run_tests():
    # 1. Gerar chave RSA 2048
    print("Gerando par de chaves RSA 2048 bits para teste...")
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pub_key = private_key.public_key()

    # 2. Conferir que o DER tem exatamente 294 bytes
    der = public_key_der(pub_key)
    assert len(der) == 294, f"Esperado 294 bytes, obtido {len(der)}"
    print(f"✓ Teste 1 (DER SubjectPublicKeyInfo tem exatamente 294 bytes): SUCESSO (len={len(der)})")

    # 3. Assinar e verificar
    digest_h = os.urandom(32)
    sig = sign_digest(private_key, digest_h)
    assert len(sig) == 256  # 2048 bits = 256 bytes

    # Verificação usando objeto RSAPublicKey
    valido_obj = verify_digest(pub_key, sig, digest_h)
    assert valido_obj is True
    print("✓ Teste 2 (Assinatura e verificação com RSAPublicKey): SUCESSO")

    # 4. Verificação usando bytes DER diretamente
    valido_der = verify_digest(der, sig, digest_h)
    assert valido_der is True
    print("✓ Teste 3 (Verificação passando chave pública em bytes DER): SUCESSO")

    # 5. Alterar 1 bit de H -> deve falhar retornando False (sem propagar InvalidSignature)
    digest_h_corrompido = digest_h[:-1] + bytes([digest_h[-1] ^ 0x01])
    invalido_h = verify_digest(pub_key, sig, digest_h_corrompido)
    assert invalido_h is False
    print("✓ Teste 4 (Digest H com 1 bit alterado retorna False): SUCESSO")

    # 6. Alterar 1 bit da assinatura -> deve falhar retornando False
    sig_corrompida = sig[:-1] + bytes([sig[-1] ^ 0x01])
    invalido_sig = verify_digest(pub_key, sig_corrompida, digest_h)
    assert invalido_sig is False
    print("✓ Teste 5 (Assinatura com 1 bit alterado retorna False): SUCESSO")

    print("\nTodos os testes de assinatura RSA-PSS passaram com sucesso!")


if __name__ == "__main__":
    run_tests()
