"""
protocol.py - Definições de constantes, estruturas e utilitários do protocolo.
Versão direta conforme PROTOCOLO_DIRETO.md.
"""

import asyncio
from enum import IntEnum
import struct
from typing import NamedTuple

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

# aqui fica as exceções: ConnectionClosed sera usada quando uma conexão cair ou for encerrada. protocolerro; sera usada quando queremos encalpsular uma mensagem clara e regra de quando ela foi descumprida
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


# ==========================================
# CAMPOS VARIÁVEIS
# Formato: [2B tamanho big-endian (>H)][bytes]
# ==========================================
def pack_field(data: bytes) -> bytes:
    """Serializa um campo variável adicionando prefixo de 2 bytes big-endian (>H)."""
    if len(data) > 0xFFFF:
        raise ProtocolError("Campo excede o tamanho máximo de 65535 bytes", ErrorCode.FRAMING_INVALID)
    return struct.pack(">H", len(data)) + data


def unpack_field(buffer: bytes, offset: int = 0) -> tuple[bytes, int]:
    """
    Lê um campo variável a partir de offset em buffer.
    Retorna (dados_do_campo, novo_offset).
    Rejeita buffers truncados com ProtocolError(FRAMING_INVALID).
    """
    if offset + 2 > len(buffer):
        raise ProtocolError("Buffer insuficiente para ler tamanho do campo variável", ErrorCode.FRAMING_INVALID)

    (field_len,) = struct.unpack_from(">H", buffer, offset)
    new_offset = offset + 2 + field_len

    if new_offset > len(buffer):
        raise ProtocolError("Buffer truncado: tamanho do campo excede bytes restantes", ErrorCode.FRAMING_INVALID)

    field_data = buffer[offset + 2 : new_offset]
    return field_data, new_offset


#funções encode_frame: valida se o tamanho esta dentro dos limites; send_frame: escreve o frame do socket e aguarda o envio; 
#frame e recv_frame: 
class Frame(NamedTuple):
    type: int
    payload: bytes

    @property
    def body(self) -> bytes:
        """Corpo completo do frame (tipo + campos)."""
        return bytes([self.type]) + self.payload


def encode_frame(frame_type: int | FrameType | bytes, payload: bytes = b"") -> bytes:
    """
    Empacota um frame com prefixo de tamanho de 4 bytes big-endian.
    Aceita (frame_type, payload) ou bytes já contendo [tipo + campos].
    """
    if isinstance(frame_type, (bytes, bytearray)):
        body = bytes(frame_type)
    else:
        body = bytes([int(frame_type)]) + payload

    n = len(body)
    if n == 0:
        raise ProtocolError("Tamanho do frame não pode ser 0", ErrorCode.FRAMING_INVALID)
    if n > MAX_FRAME:
        raise ProtocolError(
            f"Frame excede tamanho máximo ({n} > {MAX_FRAME})",
            ErrorCode.FRAME_TOO_LARGE,
        )

    return struct.pack(">I", n) + body


async def send_frame(
    writer: asyncio.StreamWriter,
    frame_type_or_bytes: int | FrameType | bytes,
    payload: bytes = b"",
) -> None:
    """Envia um frame no formato [4B tamanho big-endian][1B tipo][campos]."""
    try:
        if isinstance(frame_type_or_bytes, (bytes, bytearray)) and payload == b"":
            # Se já for um frame pré-codificado com prefixo de 4 bytes correspondente
            if len(frame_type_or_bytes) >= 4:
                (expected_len,) = struct.unpack(">I", frame_type_or_bytes[:4])
                if expected_len == len(frame_type_or_bytes) - 4:
                    raw_data = bytes(frame_type_or_bytes)
                else:
                    raw_data = encode_frame(frame_type_or_bytes)
            else:
                raw_data = encode_frame(frame_type_or_bytes)
        else:
            raw_data = encode_frame(frame_type_or_bytes, payload)

        writer.write(raw_data)
        await writer.drain()
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante envio do frame") from e


async def recv_frame(reader: asyncio.StreamReader) -> Frame:
    """
    Lê o prefixo de 4 bytes, valida o tamanho antes de ler o corpo,
    e lê exatamente n bytes. Converte IncompleteReadError em ConnectionClosed.
    """
    # 1. Lê os 4 bytes do tamanho do frame
    try:
        len_bytes = await reader.readexactly(4)
    except asyncio.IncompleteReadError as e:
        raise ConnectionClosed("Conexão encerrada durante leitura do tamanho do frame") from e
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante leitura do tamanho do frame") from e

    (n,) = struct.unpack(">I", len_bytes)

    # 2. Valida o tamanho ANTES de alocar/ler o corpo
    if n == 0:
        raise ProtocolError("Tamanho do frame inválido (0)", ErrorCode.FRAMING_INVALID)
    if n > MAX_FRAME:
        raise ProtocolError(
            f"Frame excede MAX_FRAME ({n} > {MAX_FRAME})",
            ErrorCode.FRAME_TOO_LARGE,
        )

    # 3. Lê exatamente n bytes do corpo
    try:
        body = await reader.readexactly(n)
    except asyncio.IncompleteReadError as e:
        raise ConnectionClosed("Conexão truncada durante leitura do corpo do frame") from e
    except (ConnectionResetError, BrokenPipeError) as e:
        raise ConnectionClosed("Conexão perdida durante leitura do corpo do frame") from e

    frame_type = body[0]
    payload = body[1:]
    return Frame(type=frame_type, payload=payload)



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

