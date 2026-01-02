import socket
import selectors
import re


HELLO_MSG = b'SEGGER SystemView V3.32.00\x00\x00\x00\x00\x00\x00'


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


def start_rtt(tcl_sock):
    tcl_rpc(tcl_sock, 'init')

    tcl_rpc(tcl_sock, 'mww 0xe000edfc 0x01000000')
    tcl_rpc(tcl_sock, 'mww 0xe0001000 1')

    tcl_rpc(tcl_sock, 'rtt setup 0x20000000 0xC000 "SEGGER RTT"')
    tcl_rpc(tcl_sock, 'rtt polling_interval 1')
    tcl_rpc(tcl_sock, 'rtt start')

    channel = int(re.search(r'(\d+):\sSysView', tcl_rpc(tcl_sock, 'rtt channels'))[1])
    rtt_port = 9000 + channel
    tcl_rpc(tcl_sock, f'rtt server start {rtt_port} {channel}')

    rtt_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    rtt_sock.connect(('localhost', rtt_port))
    rtt_sock.setblocking(False)
    rtt_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    return rtt_sock


def main():
    tcl_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcl_sock.connect(('localhost', 6666))
    tcl_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

    rtt_sock = start_rtt(tcl_sock)

    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.bind(('localhost', 19111))
    listen_sock.listen()
    listen_sock.setblocking(False)

    conn_socks = {}
    outgoing = {rtt_sock: bytearray()}
    running = True

    sel = selectors.DefaultSelector()

    def close_conn(conn):
        del conn_socks[conn]
        del outgoing[conn]
        sel.unregister(conn)
        conn.close()

    def accept(sock, mask):
        conn, addr = sock.accept()
        conn.setblocking(False)
        conn.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        conn_socks[conn] = -1
        outgoing[conn] = bytearray()
        sel.register(conn, selectors.EVENT_READ, hand_shake)

    def hand_shake(conn, mask):
        read_num = -conn_socks[conn] - 1
        data = conn.recv(len(HELLO_MSG) - read_num)
        if data:
            read_num += len(data)
            if read_num == len(HELLO_MSG):
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
        sel.register(listen_sock, selectors.EVENT_READ, accept)
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
            sel.unregister(listen_sock)
            sel.unregister(rtt_sock)
            listen_sock.close()
            rtt_sock.close()
            tcl_sock.close()

    try:
        serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
