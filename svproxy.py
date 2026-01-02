import argparse
import logging
import socket
import selectors
import re

logger = logging.getLogger(__name__)

HELLO_MSG = b'SEGGER SystemView V3.32.00\x00\x00\x00\x00\x00\x00'


def parse_args():
    parser = argparse.ArgumentParser(
        prog='svproxy',
        description='Bridge non-J-Link probes with SystemView.',
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    parser.add_argument('--bind', type=str, default='localhost', help='bind address')
    parser.add_argument('--port', type=int, default=19111, help='port number')
    parser.add_argument('--openocd', type=str, default='localhost', help='OpenOCD address')
    parser.add_argument('--tcl-port', type=int, default=6666, help='OpenOCD Tcl RPC port')
    return parser.parse_args()


def format_sock_name(addr):
    return f'{addr[0]}:{addr[1]}'


def tcl_rpc(sock, cmd):
    sock.sendall(cmd.encode('ascii') + b'\x1a')
    buff = bytearray()
    while True:
        chunk = sock.recv(4096)
        if chunk.endswith(b'\x1a'):
            buff.extend(chunk[:-1])
            break
        buff.extend(chunk)
    return buff.decode('ascii')


def start_rtt(openocd, tcl_port):
    logger.info(f'Connecting OpenOCD Tcl RPC server.')
    tcl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    try:
        tcl_sock.connect((openocd, tcl_port))
    except ConnectionRefusedError:
        tcl_sock.close()
        logger.error('Cannot connect to OpenOCD: Connection refused.')
        return None

    tcl_sock.settimeout(1.0)
    tcl_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    logger.info('OpenOCD Tcl RPC server Connected.')

    try:
        logger.info('Initialize target.')
        tcl_rpc(tcl_sock, 'init')

        logger.info('Enable DWT Counter on target.')
        tcl_rpc(tcl_sock, 'mww 0xe000edfc 0x01000000')
        tcl_rpc(tcl_sock, 'mww 0xe0001000 1')

        logger.info('Setup RTT.')
        tcl_rpc(tcl_sock, 'rtt setup 0x20000000 0xC000 "SEGGER RTT"')
        tcl_rpc(tcl_sock, 'rtt polling_interval 1')
        tcl_rpc(tcl_sock, 'rtt start')

        logger.info('Search for SystemView RTT channel.')
        match = re.search(r'(\d+):\sSysView', tcl_rpc(tcl_sock, 'rtt channels'))
        if not match:
            logger.error('Could not find SystemView RTT channel.')
            tcl_sock.close()
            return None
        channel = int(match[1])
        logger.info(f'Found SystemView RTT channel: {channel}')

        rtt_port = 9000 + channel
        logger.info(f'Start RTT channel on {openocd}:{rtt_port}.')
        tcl_rpc(tcl_sock, f'rtt server start {rtt_port} {channel}')

        logger.info('Connecting to RTT server.')
        rtt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        rtt_sock.connect((openocd, rtt_port))
        rtt_sock.setblocking(False)
        rtt_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        logger.info('RTT Connected.')
    finally:
        tcl_sock.close()

    return rtt_sock


def main():
    args = parse_args()

    rtt_sock = start_rtt(args.openocd, args.tcl_port)
    if not rtt_sock:
        return

    conn_socks = {}
    outgoing = {rtt_sock: bytearray()}
    running = True

    sel = selectors.DefaultSelector()

    def close_conn(conn):
        logger.info(f'Disconnect from {format_sock_name(conn.getpeername())}.')
        del conn_socks[conn]
        del outgoing[conn]
        sel.unregister(conn)
        conn.close()

    def accept(sock, mask):
        conn, addr = sock.accept()
        logger.info(f'Accepted connection from {format_sock_name(conn.getpeername())}.')
        conn.setblocking(False)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn_socks[conn] = -1
        outgoing[conn] = bytearray()
        sel.register(conn, selectors.EVENT_READ, handshake)
        logger.info(f'Waiting for handshake request from {format_sock_name(conn.getpeername())}.')

    def handshake(conn, mask):
        read_num = -conn_socks[conn] - 1
        data = conn.recv(len(HELLO_MSG) - read_num)
        if data:
            read_num += len(data)
            if read_num == len(HELLO_MSG):
                logger.info(f'Handshake with {format_sock_name(conn.getpeername())} successful.')
                conn_socks[conn] = 0
                outgoing[conn] = bytearray(HELLO_MSG)
                sel.unregister(conn)
                sel.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, handle_conn)
            else:
                conn_socks[conn] = -read_num - 1
        else:
            close_conn(conn)

    def handle_rtt(sock, mask):
        nonlocal outgoing, running
        if mask & selectors.EVENT_READ:
            data = sock.recv(4096)
            if data:
                for conn in conn_socks:
                    if conn_socks[conn] < 0:
                        continue
                    if outgoing[conn]:
                        outgoing[conn].extend(data)
                    else:
                        send_num = conn.send(data)
                        outgoing[conn].extend(data[send_num:])
            else:
                logger.error('Cannot read from OpenOCD RTT port.')
                running = False
        if mask & selectors.EVENT_WRITE:
            if outgoing[sock]:
                send_num = sock.send(outgoing[sock])
                outgoing[sock] = outgoing[sock][send_num:]

    def handle_conn(conn, mask):
        nonlocal outgoing
        if mask & selectors.EVENT_READ:
            data = conn.recv(4096)
            if data:
                num_bytes = conn_socks[conn]
                read_ptr = 0
                while read_ptr < len(data):
                    if num_bytes == 0:
                        num_bytes = data[read_ptr]
                        read_ptr += 1
                    else:
                        read_num = min(num_bytes, len(data) - read_ptr)
                        if outgoing[rtt_sock]:
                            outgoing[rtt_sock].extend(data[read_ptr:read_ptr + read_num])
                        else:
                            send_num = rtt_sock.send(data[read_ptr:read_ptr + read_num])
                            outgoing[rtt_sock].extend(data[read_ptr + send_num:read_ptr + read_num])
                        num_bytes -= read_num
                        read_ptr += read_num
                conn_socks[conn] = num_bytes
            else:
                close_conn(conn)
                return
        if mask & selectors.EVENT_WRITE:
            if outgoing[conn]:
                send_num = conn.send(outgoing[conn])
                outgoing[conn] = outgoing[conn][send_num:]

    def serve_forever():
        server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_sock.bind((args.bind, args.port))
        server_sock.listen()
        server_sock.setblocking(False)
        logger.info(f'Listening on {format_sock_name(server_sock.getsockname())}.')

        sel.register(server_sock, selectors.EVENT_READ, accept)
        sel.register(rtt_sock, selectors.EVENT_READ | selectors.EVENT_WRITE, handle_rtt)

        try:
            while running:
                events = sel.select()
                for key, mask in events:
                    callback = key.data
                    callback(key.fileobj, mask)
        finally:
            for sock in conn_socks:
                close_conn(sock)
            sel.unregister(server_sock)
            sel.unregister(rtt_sock)
            server_sock.close()
            rtt_sock.close()

    try:
        serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='[%(levelname)s] %(message)s'
    )
    main()
