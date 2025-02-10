import socket
import struct  # <-- NEW for packing/unpacking
import hashlib

########################################
# ADDED CODE: Wire protocol constants
########################################
VERSION = 1
OP_CREATE         = 1
OP_LOGIN          = 2
OP_LIST_ACCOUNTS  = 3
OP_SEND           = 4
OP_READ           = 5
OP_DELETE_MESSAGE = 6
OP_DELETE_ACCOUNT = 7
OP_LOGOUT         = 8
OP_QUIT           = 9

HEADER_SIZE = 5  # version(1), op_type(1), seq_num(1), payload_len(2)

def hash_password(password):
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

########################################
# NEW: Build/parse packet
########################################
def build_header(version, op_type, seq_num, payload_len):
    return struct.pack("!BBBH", version, op_type, seq_num, payload_len)

def parse_header(data):
    version, op_type, seq_num, payload_len = struct.unpack("!BBBH", data)
    return version, op_type, seq_num, payload_len

########################################
# NEW: send_packet() / recv_packet()
########################################
def send_packet(sock, op_type, seq_num, payload_str):
    # Encode payload as UTF-8
    payload_bytes = payload_str.encode('utf-8')
    header = build_header(VERSION, op_type, seq_num, len(payload_bytes))
    packet = header + payload_bytes
    sock.sendall(packet)

def recv_packet(sock):
    """
    Read the 5-byte header, then read the payload.
    Return (op_type, seq_num, payload_str) or None if connection closed.
    """
    # Read exactly 5 bytes for the header
    header = read_exactly(sock, HEADER_SIZE)
    if not header:
        return None

    version, op_type, seq_num, payload_len = parse_header(header)
    if version != VERSION:
        print("[CLIENT] Received incompatible version. Closing.")
        return None

    if payload_len > 0:
        payload = read_exactly(sock, payload_len)
        if not payload:
            return None
        payload_str = payload.decode('utf-8')
    else:
        payload_str = ""

    return op_type, seq_num, payload_str

def read_exactly(sock, n):
    """Helper to read exactly n bytes from sock or return None if not possible."""
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None  # connection closed
        buf += chunk
    return buf

########################################
# We'll keep a global seq_num to track requests
########################################
seq_num = 0

def main():
    global seq_num
    print("=== Simple Chat Client (Binary Protocol) ===")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect(("127.0.0.1", 12345))
    print("[CLIENT] Connected to the server. Type 'help' for commands.")

    try:
        while True:
            cmd_line = input(">> ").strip()
            if not cmd_line:
                continue
            parts = cmd_line.split()
            cmd = parts[0].upper()

            if cmd == "HELP":
                print("""Commands:
1) CREATE <username> <password>
2) LOGIN <username> <password>
3) LIST ACCOUNTS [page_size page_num]
4) SEND <recipient> <message>
5) READ [count]
6) DELETE MESSAGE <id1> [<id2> ...]
7) DELETE ACCOUNT
8) LOGOUT
9) QUIT
""")
                continue

            seq_num = (seq_num + 1) % 256  # keep seq_num in 0..255

            if cmd == "CREATE":
                if len(parts) < 3:
                    print("[CLIENT] Usage: CREATE <username> <password>")
                    continue
                username = parts[1]
                password = " ".join(parts[2:])
                pwhash = hash_password(password)
                payload_str = f"{username}|{pwhash}"
                send_packet(sock, OP_CREATE, seq_num, payload_str)
                handle_response(sock)

            elif cmd == "LOGIN":
                if len(parts) < 3:
                    print("[CLIENT] Usage: LOGIN <username> <password>")
                    continue
                username = parts[1]
                password = " ".join(parts[2:])
                pwhash = hash_password(password)
                payload_str = f"{username}|{pwhash}"
                send_packet(sock, OP_LOGIN, seq_num, payload_str)
                handle_response(sock)

            elif cmd == "LIST":
                if len(parts) >= 3 and parts[1].upper() == "ACCOUNTS":
                    page_size = 10
                    page_num = 1
                    if len(parts) == 4:
                        page_size = int(parts[2])
                        page_num = int(parts[3])
                    elif len(parts) == 3:
                        page_size = int(parts[2])
                    payload_str = f"{page_size}|{page_num}"
                    send_packet(sock, OP_LIST_ACCOUNTS, seq_num, payload_str)
                    handle_response(sock)
                else:
                    print("[CLIENT] Usage: LIST ACCOUNTS [<page_size> <page_num>]")

            elif cmd == "SEND":
                if len(parts) < 3:
                    print("[CLIENT] Usage: SEND <recipient> <message>")
                    continue
                recipient = parts[1]
                message = " ".join(parts[2:])
                payload_str = f"{recipient}|{message}"
                send_packet(sock, OP_SEND, seq_num, payload_str)
                handle_response(sock)

            elif cmd == "READ":
                count = 5
                if len(parts) == 2:
                    count = int(parts[1])
                payload_str = str(count)
                send_packet(sock, OP_READ, seq_num, payload_str)
                handle_response(sock)

            elif cmd == "DELETE":
                if len(parts) < 2:
                    print("[CLIENT] Usage: DELETE MESSAGE <ids...> or DELETE ACCOUNT")
                    continue
                subcmd = parts[1].upper()
                if subcmd == "MESSAGE":
                    if len(parts) < 3:
                        print("[CLIENT] Usage: DELETE MESSAGE <id1> [<id2> ...]")
                        continue
                    ids = parts[2:]
                    payload_str = ",".join(ids)
                    send_packet(sock, OP_DELETE_MESSAGE, seq_num, payload_str)
                    handle_response(sock)
                elif subcmd == "ACCOUNT":
                    send_packet(sock, OP_DELETE_ACCOUNT, seq_num, "")
                    handle_response(sock)
                else:
                    print("[CLIENT] Unknown DELETE subcommand.")
            
            elif cmd == "LOGOUT":
                send_packet(sock, OP_LOGOUT, seq_num, "")
                handle_response(sock)

            elif cmd == "QUIT":
                send_packet(sock, OP_QUIT, seq_num, "")
                handle_response(sock)
                print("[CLIENT] Quitting.")
                break

            else:
                print("[CLIENT] Unknown command. Type 'help' for a list of commands.")

    except KeyboardInterrupt:
        print("[CLIENT] Exiting (Ctrl+C).")
    finally:
        sock.close()

def handle_response(sock):
    """
    After sending a request, we read one response packet (op_type, seq, payload).
    We'll just print the payload.
    """
    resp = recv_packet(sock)
    if not resp:
        print("[CLIENT] No response or disconnected.")
        return
    op_type, seq, payload_str = resp
    print(f"[CLIENT] Response (op={op_type}, seq={seq}): {payload_str}")


if __name__ == "__main__":
    main()
