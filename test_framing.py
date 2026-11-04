"""
test_framing.py - Testes de framing do protocolo em asyncio:
1. Frame normal (envio e recebimento com sucesso).
2. Frame grande demais (tamanho MAX_FRAME + 1 rejeitado antes de ler corpo).
3. Conexão fechada no meio (lança ConnectionClosed).
"""

import asyncio
import struct
import protocol
from protocol import FrameType, ErrorCode, ProtocolError, ConnectionClosed, MAX_FRAME


async def run_tests():
    # -------------------------------------------------------------
    # 1. Teste de Frame Normal
    # -------------------------------------------------------------
    received_frames = []

    async def handle_normal(reader, writer):
        try:
            frame = await protocol.recv_frame(reader)
            received_frames.append(frame)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_normal, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    await protocol.send_frame(client_writer, FrameType.CLIENT_HELLO, b"teste de payload")
    client_writer.close()
    await client_writer.wait_closed()
    server.close()
    await server.wait_closed()

    assert len(received_frames) == 1
    assert received_frames[0].type == FrameType.CLIENT_HELLO
    assert received_frames[0].payload == b"teste de payload"
    print("✓ Teste 1 (Frame normal): SUCESSO")

    # -------------------------------------------------------------
    # 2. Teste de Frame Maior que MAX_FRAME (MAX_FRAME + 1)
    # -------------------------------------------------------------
    caught_large_error = []

    async def handle_large(reader, writer):
        try:
            await protocol.recv_frame(reader)
        except ProtocolError as e:
            caught_large_error.append(e)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_large, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    # Envia 4 bytes de tamanho indicando MAX_FRAME + 1 (sem precisar mandar o corpo)
    client_writer.write(struct.pack(">I", MAX_FRAME + 1))
    await client_writer.drain()
    # Aguarda o servidor processar e fechar
    await client_reader.read()
    client_writer.close()
    await client_writer.wait_closed()
    server.close()
    await server.wait_closed()

    assert len(caught_large_error) == 1
    assert caught_large_error[0].code == ErrorCode.FRAME_TOO_LARGE
    print("✓ Teste 2 (Frame MAX_FRAME + 1 rejeitado): SUCESSO")

    # -------------------------------------------------------------
    # 3. Teste de Conexão Fechada no Meio
    # -------------------------------------------------------------
    caught_closed_error = []

    async def handle_incomplete(reader, writer):
        try:
            await protocol.recv_frame(reader)
        except ConnectionClosed as e:
            caught_closed_error.append(e)
        finally:
            writer.close()
            await writer.wait_closed()

    server = await asyncio.start_server(handle_incomplete, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    client_reader, client_writer = await asyncio.open_connection("127.0.0.1", port)
    # Envia cabeçalho dizendo que o corpo tem 20 bytes, mas fecha a conexão abruptamente
    client_writer.write(struct.pack(">I", 20))
    client_writer.write(b"incompleto")  # apenas 10 bytes enviados em vez de 20
    await client_writer.drain()
    client_writer.close()
    await client_writer.wait_closed()

    # Aguarda o servidor capturar o erro
    await asyncio.sleep(0.05)
    server.close()
    await server.wait_closed()

    assert len(caught_closed_error) == 1
    assert isinstance(caught_closed_error[0], ConnectionClosed)
    print("✓ Teste 3 (Conexão fechada no meio disparou ConnectionClosed): SUCESSO")

    print("\nTodos os testes de framing passaram com sucesso!")


if __name__ == "__main__":
    asyncio.run(run_tests())
