import selectors
import socket
import json
import hashlib


with open("config.json", "r") as file:
    config = json.load(file)

HOST = config["HOST"]
PORT = config["PORT"]

# In-memory database
accounts = {}
# Example structure:
#   accounts = {
#       "alice": {
#           "password_hash": "...",
#           "messages": [
#               {"id": 1, "sender": "bob", "content": "Hello", "read": False},
#               ...
#           ]
#       },
#       ...
#   }

# Increments for every new message
global_message_id = 0  

def get_unread_count(username):
    """Return number of unread messages for a user."""
    user_info = accounts.get(username, {})
    msgs = user_info.get("messages", [])
    return sum(1 for m in msgs if not m["read"])

class ClientState:
    """
    Holds per-client buffering, partial reads, etc.
    Also tracks which user is currently logged in (if any).
    """
    def __init__(self, sock):
        self.sock = sock
        self.addr = sock.getpeername()
        self.in_buffer = ""     # buffer for incoming data
        self.out_buffer = []    # list of strings to send out
        self.current_user = None

    def queue_message(self, message_str):
        """Queue a message (string) to be written to the client."""
        self.out_buffer.append(message_str)

    def close(self):
        """Close this client's connection."""
        try:
            self.sock.close()
        except OSError:
            pass

# The main chat server
class ChatServer:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.selector = selectors.DefaultSelector()

    def start(self):
        """Set up the listening socket and start the event loop."""
        listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listen_sock.bind((self.host, self.port))
        listen_sock.listen()
        listen_sock.setblocking(False)

        self.selector.register(listen_sock, selectors.EVENT_READ, data=None)

        print(f"[SERVER] Listening on {self.host}:{self.port} (selectors-based)")
        try:
            while True:
                events = self.selector.select(timeout=None)  # Blocking call; returns list of (key, mask)
                for key, mask in events:
                    # Check if the event is from the listening socket
                    if key.data is None:
                        self.accept_connection(key.fileobj)
                    # The event is from clients
                    else:
                        self.service_connection(key, mask)
        except KeyboardInterrupt:
            print("[SERVER] Shutting down server (CTRL+C).")
        finally:
            self.selector.close()

    def accept_connection(self, sock):
        """Accept a new incoming client connection."""
        conn, addr = sock.accept()
        print(f"[SERVER] Accepted connection from {addr}")
        conn.setblocking(False)
        client_state = ClientState(conn)
        # Register this client socket for both read and write events and client state as data (will be used for id)
        self.selector.register(conn, selectors.EVENT_READ | selectors.EVENT_WRITE, data=client_state)

    def service_connection(self, key, mask):
        """Handle read/write events for a connected client."""
        sock = key.fileobj
        client_state = key.data

        # Ready for read
        if mask & selectors.EVENT_READ:
            self.read_from_client(client_state)

        # Ready for write 
        if mask & selectors.EVENT_WRITE:
            self.write_to_client(client_state)

    def read_from_client(self, client_state):
        """Non-blocking read from the client socket; handle partial lines and parse JSON commands."""
        data = client_state.sock.recv(1024)
        if data:
            client_state.in_buffer += data.decode('utf-8')
            # Separate the commands: in the client side, each JSON request is separated by a new line
            while True:
                if "\n" in client_state.in_buffer:
                    line, remainder = client_state.in_buffer.split("\n", 1)
                    client_state.in_buffer = remainder
                    line = line.strip()
                    if line:
                        self.process_command(client_state, line)
                else:
                    break
        else:
            self.disconnect_client(client_state)

    def write_to_client(self, client_state):
        """Write any queued responses to the client socket."""
        while client_state.out_buffer:
            # Send the first queued message
            message_str = client_state.out_buffer.pop(0)
            try:
                client_state.sock.sendall(message_str.encode('utf-8'))
            except Exception:
                self.disconnect_client(client_state)
                break

    def process_command(self, client_state, line):
        """
        Parse the command (expected to be JSON), handle it, and queue a response.
        For example: {"action": "CREATE", "username": "alice", "password_hash": "..."}
        """
        try:
            request = json.loads(line)
        except json.JSONDecodeError:
            self.send_response(client_state, success=False, message="Invalid request (not valid JSON).")
            return

        action = request.get("action", "").upper()

        if action == "CREATE":
            self.handle_create(client_state, request)
        elif action == "LOGIN":
            self.handle_login(client_state, request)
        elif action == "LIST_ACCOUNTS":
            self.handle_list_accounts(client_state, request)
        elif action == "SEND":
            self.handle_send(client_state, request)
        elif action == "READ":
            self.handle_read(client_state, request)
        elif action == "DELETE_MESSAGE":
            self.handle_delete_message(client_state, request)
        elif action == "DELETE_ACCOUNT":
            self.handle_delete_account(client_state)
        elif action == "LOGOUT":
            self.handle_logout(client_state)
        # Change this when integrating with the GUI
        elif action == "QUIT":
            self.send_response(client_state, success=True, message="Connection closed.")
            self.disconnect_client(client_state)
        else:
            self.send_response(client_state, success=False, message=f"Unknown action: {action}")

    def send_response(self, client_state, success=True, message="", data=None):
        """
        Queue a JSON response to the client's out_buffer.
        We'll append a '\n' so the client can read line by line.
        """
        resp = {
            "success": success,
            "message": message
        }
        if data is not None:
            resp["data"] = data
        resp_str = json.dumps(resp) + "\n"
        client_state.queue_message(resp_str)

    # Create
    # Accounts exists

    def handle_create(self, client_state, request):
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False, message="Username or password not provided.")
            return

        if username in accounts:
            if accounts[username]["password_hash"] == password_hash:
                # Log in
                client_state.current_user = username
                unread = get_unread_count(username)
                msg = (f"User '{username}' already exists. "
                       f"Logged in successfully. Unread messages: {unread}.")
                self.send_response(client_state, success=True, message=msg)
            else:
                self.send_response(client_state, success=False,
                                   message="User exists but password is incorrect.")
        else:
            # Create new account
            accounts[username] = {
                "password_hash": password_hash,
                "messages": []
            }
            client_state.current_user = username
            msg = f"New account '{username}' created and logged in."
            self.send_response(client_state, success=True, message=msg)

    # Login
    def handle_login(self, client_state, request):
        username = request.get("username", "")
        password_hash = request.get("password_hash", "")

        if not username or not password_hash:
            self.send_response(client_state, success=False, message="Username or password not provided.")
            return

        if username not in accounts:
            self.send_response(client_state, success=False, message="No such user.")
        else:
            if accounts[username]["password_hash"] == password_hash:
                client_state.current_user = username
                unread = get_unread_count(username)
                msg = f"Logged in as '{username}'. Unread messages: {unread}."
                self.send_response(client_state, success=True, message=msg)
            else:
                self.send_response(client_state, success=False, message="Incorrect password.")

    # List accounts
    def handle_list_accounts(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="Please log in first.")
            return

        page_size = request.get("page_size", 10)
        page_num = request.get("page_num", 1)

        all_accounts = sorted(accounts.keys())
        total_accounts = len(all_accounts)

        start_index = (page_num - 1) * page_size
        end_index = start_index + page_size

        if start_index >= total_accounts:
            page_accounts = []
        else:
            page_accounts = all_accounts[start_index:end_index]

        response_data = {
            "total_accounts": total_accounts,
            "accounts": page_accounts
        }
        self.send_response(client_state, success=True, data=response_data)

    # Send message
    def handle_send(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="Please log in first.")
            return

        recipient = request.get("recipient", "")
        content = request.get("content", "").strip()
        if not recipient or not content:
            self.send_response(client_state, success=False, message="Recipient or content not provided.")
            return

        if recipient not in accounts:
            self.send_response(client_state, success=False, message="Recipient does not exist.")
            return

        global global_message_id
        global_message_id += 1
        new_msg = {
            "id": global_message_id,
            "sender": client_state.current_user,
            "content": content,
            "read": False
        }
        accounts[recipient]["messages"].append(new_msg)

        msg = f"Message sent to '{recipient}': {content}"
        self.send_response(client_state, success=True, message=msg)

    # Read message/ with indexing
    def handle_read(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="Please log in first.")
            return

        count = request.get("count", 5)
        user_msgs = accounts[client_state.current_user]["messages"]
        unread_msgs = [m for m in user_msgs if not m["read"]]

        to_read = unread_msgs[:count]
        for m in to_read:
            m["read"] = True

        response_data = {
            "read_messages": to_read,
            "remaining_unread": len(unread_msgs) - len(to_read)
        }
        self.send_response(client_state, success=True, data=response_data)

    # Delete message
    def handle_delete_message(self, client_state, request):
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="Please log in first.")
            return

        # Helps take care if there are multiple messages or one
        message_ids = request.get("message_ids", [])
        if not isinstance(message_ids, list):
            message_ids = [message_ids]

        user_msgs = accounts[client_state.current_user]["messages"]
        before_count = len(user_msgs)
        user_msgs = [m for m in user_msgs if m["id"] not in message_ids]
        after_count = len(user_msgs)
        accounts[client_state.current_user]["messages"] = user_msgs

        deleted_count = before_count - after_count
        msg = f"Deleted {deleted_count} messages."
        self.send_response(client_state, success=True, message=msg)

    # Delete account
    def handle_delete_account(self, client_state):
        if client_state.current_user is None:
            self.send_response(client_state, success=False, message="Please log in first.")
            return

        username = client_state.current_user
        del accounts[username]
        self.send_response(client_state, success=True, message=f"Account '{username}' deleted.")
        client_state.current_user = None

    # Logout
    def handle_logout(self, client_state):
        if client_state.current_user is not None:
            user = client_state.current_user
            client_state.current_user = None
            self.send_response(client_state, success=True,
                               message=f"User '{user}' logged out.")
        else:
            self.send_response(client_state, success=False,
                               message="No user is currently logged in.")

    def disconnect_client(self, client_state):
        """
        Unregister and close the client socket. 
        This effectively ends the session with that client.
        """
        print(f"[SERVER] Disconnecting {client_state.addr}")
        self.selector.unregister(client_state.sock)
        client_state.close()

########################################
# Entry point
########################################

if __name__ == "__main__":
    server = ChatServer(HOST, PORT)
    server.start()
