"""Two programs talk over an encrypted channel and prove to each other who they are.

Run from the repository root: python examples/authenticated_echo.py
"""

import asyncio

from hybride_pq import KeyPair, SecureChannel

TIMEOUT = 10  # seconds; never let a silent peer hold a connection open forever


async def main() -> None:
    # In real life each side has its own key and knows the other's public key in
    # advance (a config file, a QR code, a fingerprint read out over the phone).
    server_keys, client_keys = KeyPair.generate(), KeyPair.generate()

    async def handle(reader, writer):
        channel = await asyncio.wait_for(SecureChannel.respond(reader, writer), TIMEOUT)
        try:
            # raises if someone sits in between or the client holds another key
            await asyncio.wait_for(
                channel.authenticate(server_keys, client_keys.public_bytes()), TIMEOUT
            )
            await channel.send(b"echo: " + await channel.recv())
        finally:
            await channel.close()

    server = await asyncio.start_server(handle, "127.0.0.1", 0)
    port = server.sockets[0].getsockname()[1]

    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    channel = await asyncio.wait_for(SecureChannel.initiate(reader, writer), TIMEOUT)
    await asyncio.wait_for(channel.authenticate(client_keys, server_keys.public_bytes()), TIMEOUT)
    print("authenticated, session id", channel.session_id.hex()[:16], "...")
    await channel.send(b"hello, post-quantum world")
    print((await channel.recv()).decode())
    await channel.close()

    server.close()
    await server.wait_closed()


if __name__ == "__main__":
    asyncio.run(main())
