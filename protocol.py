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


# ==========================================
# EXCEÇÕES DO PROTOCOLO
# ==========================================
class ConnectionClosed(Exception):
    """Disparada quando o socket fecha ou atinge EOF durante uma leitura."""
    pass


class ProtocolError(Exception):
    """
    Disparada em caso de violação das regras do protocolo.
    Carrega uma mensagem e um código numérico de erro (ErrorCode).
    
    ATENÇÃO: De acordo com a política de segurança, a mensagem NUNCA deve 
    conter chaves privadas, segredos (Z), salt, nonce ou conteúdo de mensagens.
    """
    def __init__(self, message: str, code: ErrorCode | int | None = None):
        super().__init__(message)
        self.message = message
        self.code = code

    def __str__(self) -> str:
        if self.code is not None:
            code_repr = self.code.name if hasattr(self.code, "name") else f"0x{self.code:02x}"
            return f"[{code_repr}] {self.message}"
        return self.message


if __name__ == "__main__":
    print(f"DATA_HEADER_LEN: {DATA_HEADER_LEN}")
    print(f"DATA_MIN_LEN:    {DATA_MIN_LEN}")
    print(f"DATA_MAX_LEN:    {DATA_MAX_LEN}")

    # Teste das exceções
    err = ProtocolError("Framing inválido recebido", ErrorCode.FRAMING_INVALID)
    assert isinstance(err, Exception)
    assert err.code == ErrorCode.FRAMING_INVALID
    assert str(err) == "[FRAMING_INVALID] Framing inválido recebido"

    closed = ConnectionClosed("Conexão fechada pelo peer")
    assert isinstance(closed, Exception)
    print("Testes de exceções: OK")

