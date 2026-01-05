import argparse
import logging
import asyncio
import re

logger = logging.getLogger(__name__)

HELLO_MSG = b'SEGGER SystemView V3.32.00\x00\x00\x00\x00\x00\x00'


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog='svproxy',
        description='Bridge non-J-Link probes with SystemView.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--bind', type=str, default='127.0.0.1', help='bind address')
    parser.add_argument('--port', type=int, default=19111, help='port number')
    parser.add_argument('--openocd', type=str, default='127.0.0.1', help='OpenOCD address')
    parser.add_argument('--tcl-port', type=int, default=6666, help='OpenOCD Tcl RPC port')
    parser.add_argument('--search-addr', type=lambda x: int(x, 0), default='0x20000000', help='RTT search address')
    parser.add_argument('--search-size', type=lambda x: int(x, 0), default='0xFFFFFFFF', help='RTT search range')
    return parser.parse_args()


class TclRPC:
    def __init__(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        self.reader = reader
        self.writer = writer

    async def __call__(self, cmd: str) -> str:
        self.writer.write(cmd.encode('ascii') + b'\x1a')
        await self.writer.drain()
        data = await self.reader.readuntil(b'\x1a')
        return data.strip(b'\x1a').decode('ascii')


class SystemViewProxy:
    def __init__(self, openocd: str, tcl_port: int, search_addr: int, search_size: int) -> None:
        self.openocd = openocd
        self.tcl_port = tcl_port
        self.search_addr = search_addr
        self.search_size = search_size

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        client_info = ':'.join(map(str, writer.get_extra_info("peername")))
        logger.info(f'Accepted connection from {client_info}.')

        logger.info(f'Waiting for handshake request from {client_info}.')
        await reader.readexactly(len(HELLO_MSG))
        logger.info(f'Handshake with {client_info} successful.')
        writer.write(HELLO_MSG)
        await writer.drain()

        logger.info('Connecting OpenOCD Tcl RPC server.')
        try:
            tcl_reader, tcl_writer = await asyncio.open_connection(self.openocd, self.tcl_port)
        except ConnectionRefusedError:
            logger.error('Cannot connect to OpenOCD: Connection refused.')
            writer.close()
            await writer.wait_closed()
            return

        logger.info('OpenOCD Tcl RPC server connected.')

        tcl_rpc = TclRPC(tcl_reader, tcl_writer)

        logger.info('Setup RTT.')
        await tcl_rpc('init')
        await tcl_rpc(f'rtt setup 0x{self.search_addr:08X} 0x{self.search_size:08X} "SEGGER RTT"')
        await tcl_rpc('rtt polling_interval 1')
        await tcl_rpc('rtt start')

        logger.info('Search for SystemView RTT channel.')
        match = re.search(r'(\d+):\sSysView', await tcl_rpc('rtt channels'))

        if not match:
            logger.error('Could not find SystemView RTT channel.')
            tcl_writer.close()
            writer.close()
            await asyncio.gather(tcl_writer.wait_closed(), writer.wait_closed())
            return

        channel = int(match[1])
        logger.info(f'Found SystemView RTT channel: {channel}')

        rtt_port = 9000 + channel
        logger.info(f'Start RTT server on port {rtt_port}.')
        await tcl_rpc(f'rtt server start {rtt_port} {channel}')

        logger.info('Connecting to RTT server.')
        rtt_reader, rtt_writer = await asyncio.open_connection(self.openocd, rtt_port)
        logger.info('RTT server connected.')

        logger.info('Detect target CPU type.')
        cpu_type = await tcl_rpc('[target current] cget -type')
        logger.info(f'Target CPU type: {cpu_type}.')
        if cpu_type == 'cortex_m':
            logger.info('Enable DWT counter.')
            await tcl_rpc('mww 0xe000edfc 0x01000000')
            await tcl_rpc('mww 0xe0001000 1')

        async def rtt_to_system_view() -> None:
            while True:
                data = await rtt_reader.read(4096)
                if not data:
                    logger.error('Cannot read from RTT server.')
                    break
                writer.write(data)
                await writer.drain()

        async def system_view_to_rtt() -> None:
            while True:
                try:
                    num_bytes = await reader.readexactly(1)
                    data = await reader.readexactly(num_bytes[0])
                    rtt_writer.write(data)
                    await rtt_writer.drain()
                except asyncio.IncompleteReadError:
                    logger.error('Cannot read from SystemView.')
                    break

        tasks = (
            asyncio.create_task(rtt_to_system_view()),
            asyncio.create_task(system_view_to_rtt()),
        )

        logger.info(f'Relaying packets between RTT server and SystemView.')

        try:
            done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            for task in pending:
                task.cancel()
            await asyncio.gather(*pending, return_exceptions=True)
        finally:
            rtt_writer.close()
            tcl_writer.close()
            writer.close()
            await asyncio.gather(rtt_writer.wait_closed(), tcl_writer.wait_closed(), writer.wait_closed())

        logger.info(f'Disconnected from {client_info}')


async def main(args: argparse.Namespace) -> None:
    proxy = SystemViewProxy(args.openocd, args.tcl_port, args.search_addr, args.search_size)
    server = await asyncio.start_server(proxy.handle_connection, args.bind, args.port)
    logger.info(f'Listening on {args.bind}:{args.port}.')
    async with server:
        await server.serve_forever()


if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO, format='[%(levelname)s] %(message)s')
    try:
        asyncio.run(main(parse_args()))
    except KeyboardInterrupt:
        pass
