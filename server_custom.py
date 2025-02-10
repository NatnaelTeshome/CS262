import selectors
import socket
import struct  # <-- NEW: For packing/unpacking binary data
import hashlib

########################################
# ADDED CODE: Define our wire protocol constants
########################################
VERSION = 1

# Operation types (just examples; you can reorder or add more as desired)
OP_CREATE         = 1
OP_LOGIN          = 2
OP_LIST_ACCOUNTS  = 3
OP_SEND           = 4
OP_READ           = 5
OP_DELETE_MESSAGE = 6
OP_DELETE_ACCOUNT = 7
OP_LOGOUT         = 8
OP_QUIT           = 9

# We'll define a small mapping op -> string just for debug/logging
OP_NAMES = {
    OP_CREATE:         "CREATE",
    OP_LOGIN:          "LOGIN",
    OP_LIST_ACCOUNTS:  "LIST_ACCOUNTS",
    OP_SEND:           "SEND",
    OP_READ:           "READ",
    OP_DELETE_MESSAGE: "DELETE_MESSAGE",
    OP_DELETE_ACCOUNT: "DELETE_ACCOUNT",
    OP_LOGOUT:         "LOGOUT",
    OP_QUIT:           "QUIT"
}

HEADER_SIZE = 5  # Version(1) + OpType(1) + SeqNum(1) + PayloadLen(2)

########################################
# In-memory data structures (unchanged)
########################################
accounts = {}
global_message_id = 0  # Increments for every new message

HOST = '127.0.0.1'
PORT = 12345

def get_unread_count(username):
    user_info = accounts.get(username, {})
    msgs = user_info.get("messages", [])
    return sum(1 for m in msgs if not m["read"])

########################################
# NEW: Helper functions for the new wire protocol
########################################
def build_header(version: int, op_type: int, seq_num: int, payload_len: int) -> bytes:
    """
    Pack the 5-byte header in the format:
      version (1 byte)
      op_type (1 byte)
      seq_num (1 byte)
      payload_len (2 bytes, big-endian)
    """
    return struct.pack("!BBBH", version, op_type, seq_num, payload_len)

def parse_header(header_data: bytes):
    """
    Unpack the 5-byte header; returns (version, op_type, seq_num, payload_len).
    """
    version, op_type, seq_num, payload_len = struct.unpack("!BBBH", header_data)
    return version, op_type, seq_num, payload_len


########################################
# ClientState (MODIFIED to handle binary packets)
########################################
class ClientState:
    def __init__(self, sock):
        self.sock = sock
        self.addr = sock.getpeername()

        # Instead of a single in_buffer of text lines, we store raw bytes
        self.in_buffer = b""  # <-- changed to bytes
        self.out_buffer = []  # List of byte-strings to send

        self.current_user = None

        # NEW: Keep track of where we are in parsing
        self.expected_header = True
        self.header_bytes_needed = HEADER_SIZE
        self.current_header = b""
        self.payload_bytes_needed = 0

    def queue_packet(self, packet: bytes):
        """Add a fully constructed packet (header+payload) to be sent."""
        self.out_buffer.append(packet)

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


########################################
# ChatServer with selectors (MODIFIED)
########################################
class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()

    def start(self):
        lsock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        lsock.bind((self.host, self.port))
        lsock.listen()
        lsock.setblocking(False)

        self.selector.register(lsock, selectors.EVENT_READ, data=None)
        print(f"[SERVER] Listening on {self.host}:{self.port} (binary protocol)")

        try:
            while True:
                events = self.selector.select(timeout=None)
                for key, mask in events:
                    if key.data is None:
                        # Accept new connection
                        self.accept_connection(key.fileobj)
                    else:
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("[SERVER] Shutting down via KeyboardInterrupt.")
        finally:
            self.selector.close()

    def accept_connection(self, sock):
        conn, addr = sock.accept()
        print(f"[SERVER] Accepted connection from {addr}")
        conn.setblocking(False)
        client_state = ClientState(conn)
        self.selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=client_state)

    def service_connection(self, key, mask):
        sock = key.fileobj
        client_state = key.data

        if mask & selectors.EVENT_READ:
            self.read_from_client(client_state)

        if mask & selectors.EVENT_WRITE:
            self.write_to_client(client_state)

    ########################################
    # NEW / MODIFIED: read / parse binary
    ########################################
    def read_from_client(self, client_state):
        try:
            data = client_state.sock.recv(4096)
        except ConnectionResetError:
            self.disconnect_client(client_state)
            return

        if data:
            client_state.in_buffer += data
            self.process_incoming_data(client_state)
        else:
            # No data means the client closed
            self.disconnect_client(client_state)

    def process_incoming_data(self, client_state):
        """
        We repeatedly parse either:
         - The 5-byte header if we expect it
         - The payload if we have the header
        """
        while True:
            if client_state.expected_header:
                # Check if we have enough bytes for the header
                if len(client_state.in_buffer) < HEADER_SIZE:
                    break  # wait for more data
                header = client_state.in_buffer[:HEADER_SIZE]
                client_state.in_buffer = client_state.in_buffer[HEADER_SIZE:]

                # parse it
                version, op_type, seq_num, payload_len = parse_header(header)

                # (Optional) check version
                if version != VERSION:
                    # We can forcibly disconnect or ignore. For now, just ignore.
                    print(f"[SERVER] Incompatible version {version}, expected {VERSION}. Disconnecting client.")
                    self.disconnect_client(client_state)
                    return

                client_state.expected_header = False
                client_state.payload_bytes_needed = payload_len
                client_state.current_op_type = op_type
                client_state.current_seq_num = seq_num

            else:
                # We need to read the payload
                if len(client_state.in_buffer) < client_state.payload_bytes_needed:
                    break  # not enough data yet

                payload = client_state.in_buffer[:client_state.payload_bytes_needed]
                client_state.in_buffer = client_state.in_buffer[client_state.payload_bytes_needed:]

                # We have a complete packet
                self.handle_packet(client_state, client_state.current_op_type,
                                   client_state.current_seq_num, payload)

                # Reset to read next header
                client_state.expected_header = True
                client_state.payload_bytes_needed = 0

    ########################################
    # NEW: handle_packet (replaces JSON logic)
    ########################################
    def handle_packet(self, client_state, op_type, seq_num, payload):
        # We'll interpret the payload as UTF-8 text with arguments separated by '|'.
        # For example:
        #   CREATE => "username|hashed_password"
        #   LOGIN => "username|hashed_password"
        #   ...
        # You can define a more robust serialization as needed.
        payload_str = payload.decode('utf-8')

        # Debug
        op_name = OP_NAMES.get(op_type, f"UNKNOWN({op_type})")
        print(f"[SERVER] Received op={op_name}, seq={seq_num}, payload='{payload_str}' from {client_state.addr}")

        # Dispatch
        if op_type == OP_CREATE:
            parts = payload_str.split("|", 1)
            if len(parts) < 2:
                self.send_error(client_state, op_type, seq_num, "Bad CREATE payload.")
            else:
                username, pass_hash = parts
                self.handle_create(client_state, op_type, seq_num, username, pass_hash)

        elif op_type == OP_LOGIN:
            parts = payload_str.split("|", 1)
            if len(parts) < 2:
                self.send_error(client_state, op_type, seq_num, "Bad LOGIN payload.")
            else:
                username, pass_hash = parts
                self.handle_login(client_state, op_type, seq_num, username, pass_hash)

        elif op_type == OP_LIST_ACCOUNTS:
            # optional: "page_size|page_num" or just empty
            parts = payload_str.split("|")
            try:
                page_size = int(parts[0]) if len(parts) > 0 and parts[0] else 10
                page_num = int(parts[1]) if len(parts) > 1 and parts[1] else 1
            except ValueError:
                page_size = 10
                page_num = 1
            self.handle_list_accounts(client_state, op_type, seq_num, page_size, page_num)

        elif op_type == OP_SEND:
            # payload: "recipient|message"
            parts = payload_str.split("|", 1)
            if len(parts) < 2:
                self.send_error(client_state, op_type, seq_num, "Bad SEND payload.")
            else:
                recipient, message = parts
                self.handle_send(client_state, op_type, seq_num, recipient, message)

        elif op_type == OP_READ:
            # payload: "count"
            if payload_str.strip():
                try:
                    count = int(payload_str.strip())
                except ValueError:
                    count = 5
            else:
                count = 5
            self.handle_read(client_state, op_type, seq_num, count)

        elif op_type == OP_DELETE_MESSAGE:
            # payload: "id1,id2,id3..."
            if payload_str.strip():
                try:
                    message_ids = [int(x) for x in payload_str.split(",")]
                except ValueError:
                    message_ids = []
            else:
                message_ids = []
            self.handle_delete_message(client_state, op_type, seq_num, message_ids)

        elif op_type == OP_DELETE_ACCOUNT:
            self.handle_delete_account(client_state, op_type, seq_num)

        elif op_type == OP_LOGOUT:
            self.handle_logout(client_state, op_type, seq_num)

        elif op_type == OP_QUIT:
            # respond, then disconnect
            self.send_success(client_state, op_type, seq_num, "Connection closed.")
            self.disconnect_client(client_state)

        else:
            self.send_error(client_state, op_type, seq_num, f"Unknown op_type {op_type}")

    ########################################
    # Write out any pending data
    ########################################
    def write_to_client(self, client_state):
        while client_state.out_buffer:
            packet = client_state.out_buffer.pop(0)
            try:
                client_state.sock.sendall(packet)
            except BlockingIOError:
                client_state.out_buffer.insert(0, packet)
                break
            except BrokenPipeError:
                self.disconnect_client(client_state)
                break

    ########################################
    # Utility: send success/error
    ########################################
    def send_success(self, client_state, op_type, seq_num, message: str):
        payload_bytes = message.encode('utf-8')
        header = build_header(VERSION, op_type, seq_num, len(payload_bytes))
        packet = header + payload_bytes
        client_state.queue_packet(packet)

    def send_error(self, client_state, op_type, seq_num, error_msg: str):
        self.send_success(client_state, op_type, seq_num, "ERROR: " + error_msg)

    ########################################
    # Command Handlers (similar logic as before)
    ########################################
    def handle_create(self, client_state, op_type, seq_num, username, password_hash):
        if not username or not password_hash:
            self.send_error(client_state, op_type, seq_num, "Username or password not provided.")
            return

        if username in accounts:
            if accounts[username]["password_hash"] == password_hash:
                client_state.current_user = username
                unread = get_unread_count(username)
                msg = f"User '{username}' already exists. Logged in. Unread: {unread}"
                self.send_success(client_state, op_type, seq_num, msg)
            else:
                self.send_error(client_state, op_type, seq_num, "User exists but incorrect password.")
        else:
            accounts[username] = {
                "password_hash": password_hash,
                "messages": []
            }
            client_state.current_user = username
            msg = f"New account '{username}' created and logged in."
            self.send_success(client_state, op_type, seq_num, msg)

    def handle_login(self, client_state, op_type, seq_num, username, password_hash):
        if not username or not password_hash:
            self.send_error(client_state, op_type, seq_num, "No username or password.")
            return

        if username not in accounts:
            self.send_error(client_state, op_type, seq_num, "No such user.")
        else:
            if accounts[username]["password_hash"] == password_hash:
                client_state.current_user = username
                unread = get_unread_count(username)
                msg = f"Logged in as '{username}'. Unread: {unread}"
                self.send_success(client_state, op_type, seq_num, msg)
            else:
                self.send_error(client_state, op_type, seq_num, "Incorrect password.")

    def handle_list_accounts(self, client_state, op_type, seq_num, page_size, page_num):
        if client_state.current_user is None:
            self.send_error(client_state, op_type, seq_num, "Please log in first.")
            return

        all_accounts = sorted(accounts.keys())
        total_accounts = len(all_accounts)
        start_index = (page_num - 1) * page_size
        end_index = start_index + page_size
        page_accounts = all_accounts[start_index:end_index] if start_index < total_accounts else []

        # We'll return them as "total_accounts|acc1,acc2,acc3..."
        resp_str = f"{total_accounts}|{','.join(page_accounts)}"
        self.send_success(client_state, op_type, seq_num, resp_str)

    def handle_send(self, client_state, op_type, seq_num, recipient, content):
        if client_state.current_user is None:
            self.send_error(client_state, op_type, seq_num, "Please log in first.")
            return
        if not recipient or not content:
            self.send_error(client_state, op_type, seq_num, "Recipient or content not provided.")
            return
        if recipient not in accounts:
            self.send_error(client_state, op_type, seq_num, "Recipient does not exist.")
            return

        global global_message_id
        global_message_id += 1
        message = {
            "id": global_message_id,
            "sender": client_state.current_user,
            "content": content,
            "read": False
        }
        accounts[recipient]["messages"].append(message)

        self.send_success(client_state, op_type, seq_num, f"Message sent to '{recipient}': {content}")

    def handle_read(self, client_state, op_type, seq_num, count):
        if client_state.current_user is None:
            self.send_error(client_state, op_type, seq_num, "Please log in first.")
            return
        user_msgs = accounts[client_state.current_user]["messages"]
        unread_msgs = [m for m in user_msgs if not m["read"]]
        to_read = unread_msgs[:count]

        for m in to_read:
            m["read"] = True

        # We'll respond with something like:
        #   "id1:sender:content;id2:sender2:content2|remaining_unread"
        #   i.e. separate messages by ';', fields by ':', final '|' plus remaining
        msgs_str_parts = []
        for msg in to_read:
            part = f"{msg['id']}:{msg['sender']}:{msg['content']}"
            msgs_str_parts.append(part)
        read_str = ";".join(msgs_str_parts)
        remaining_unread = len(unread_msgs) - len(to_read)
        resp_str = f"{read_str}|{remaining_unread}"
        self.send_success(client_state, op_type, seq_num, resp_str)

    def handle_delete_message(self, client_state, op_type, seq_num, message_ids):
        if client_state.current_user is None:
            self.send_error(client_state, op_type, seq_num, "Please log in first.")
            return

        user_msgs = accounts[client_state.current_user]["messages"]
        before_count = len(user_msgs)
        user_msgs = [m for m in user_msgs if m["id"] not in message_ids]
        after_count = len(user_msgs)
        accounts[client_state.current_user]["messages"] = user_msgs

        deleted_count = before_count - after_count
        self.send_success(client_state, op_type, seq_num, f"Deleted {deleted_count} messages.")

    def handle_delete_account(self, client_state, op_type, seq_num):
        if client_state.current_user is None:
            self.send_error(client_state, op_type, seq_num, "Please log in first.")
            return
        user = client_state.current_user
        del accounts[user]
        client_state.current_user = None
        self.send_success(client_state, op_type, seq_num, f"Account '{user}' deleted.")

    def handle_logout(self, client_state, op_type, seq_num):
        if client_state.current_user:
            user = client_state.current_user
            client_state.current_user = None
            self.send_success(client_state, op_type, seq_num, f"User '{user}' logged out.")
        else:
            self.send_error(client_state, op_type, seq_num, "No user is logged in.")

    def disconnect_client(self, client_state):
        print(f"[SERVER] Disconnecting {client_state.addr}")
        try:
            self.selector.unregister(client_state.sock)
        except Exception:
            pass
        client_state.close()


if __name__ == "__main__":
    server = ChatServer(HOST, PORT)
    server.start()
