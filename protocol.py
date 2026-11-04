"""
protocol.py - Definições de constantes, estruturas e utilitários do protocolo.
Versão direta conforme PROTOCOLO_DIRETO.md.
"""

from enum import IntEnum

# ==========================================
# CONSTANTES DE TAMANHO (em bytes)
# ==========================================
MAX_FRAME = 8192

ID_LEN = 16         # client_id, sender_id, recipient_id (UUID v4 binário)
PK_LEN = 32         # Chave pública X25519 raw
SALT_LEN = 16       # salt_srv
NONCE_LEN = 12      # IV_base (4B) + seq_no (8B)
SEQ_LEN = 8         # Contador monotônico 64-bit
KEY_LEN = 16        # Chave simétrica AES-128
TAG_LEN = 16        # Tag de autenticação AES-GCM
MAX_PLAINTEXT = 4096
PSS_SALT_LEN = 32   # Salt interno do RSA-PSS

# ==========================================
# CÓDIGOS DE TIPO DE FRAME
# ==========================================
class FrameType(IntEnum):
    CLIENT_HELLO = 0x01
    SERVER_HELLO = 0x02
    DATA         = 0x03
    PEER_JOINED  = 0x04
    PEER_LEFT    = 0x05
    ERROR        = 0x06

# ==========================================
# CÓDIGOS DE ERRO (usados no frame ERROR)
# ==========================================
class ErrorCode(IntEnum):
    FRAMING_INVALID = 0x01  # Framing inválido
    FRAME_TOO_LARGE = 0x02  # Frame grande demais
    UNKNOWN_TYPE    = 0x03  # Tipo desconhecido
    PEER_OFFLINE    = 0x04  # Destinatário offline

# ==========================================
# CÁLCULO DOS LIMITES DO FRAME DATA
# Formato: [03][nonce 12][sender 16][recipient 16][seq 8][ciphertext + tag 16]
# ==========================================
# 1B (código do tipo DATA) + NONCE_LEN (12) + sender (16) + recipient (16) + seq (8)
DATA_HEADER_LEN = 1 + NONCE_LEN + (2 * ID_LEN) + SEQ_LEN

# Plaintext mínimo = 1 byte (+ TAG_LEN)
DATA_MIN_LEN = DATA_HEADER_LEN + 1 + TAG_LEN

# Plaintext máximo = MAX_PLAINTEXT (+ TAG_LEN)
DATA_MAX_LEN = DATA_HEADER_LEN + MAX_PLAINTEXT + TAG_LEN


if __name__ == "__main__":
    print(f"DATA_HEADER_LEN: {DATA_HEADER_LEN}")
    print(f"DATA_MIN_LEN:    {DATA_MIN_LEN}")
    print(f"DATA_MAX_LEN:    {DATA_MAX_LEN}")
