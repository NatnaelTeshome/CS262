import socket
import json
import hashlib

HOST = '127.0.0.1'
PORT = 12345

def hash_password(password):
    """Return a SHA-256 hex digest for the given password."""
    return hashlib.sha256(password.encode('utf-8')).hexdigest()

def send_request(sock, payload):
    """Send a JSON payload to the server and return the server response."""
    # We send the request, followed by a newline, exactly as the server expects
    sock.sendall((json.dumps(payload) + "\n").encode('utf-8'))

    # Read response (assuming only one JSON response per request)
    response_data = sock.recv(4096).decode('utf-8').strip()
    if not response_data:
        return None
    try:
        response = json.loads(response_data)
    except json.JSONDecodeError:
        response = {"success": False, "message": "Invalid response from server."}
    return response

def print_response(response):
    """Helper function to nicely print the server response."""
    if response is None:
        print("[CLIENT] No response from server.")
        return

    success = response.get("success", False)
    message = response.get("message", "")
    data = response.get("data", None)

    status = "SUCCESS" if success else "ERROR"
    print(f"[CLIENT] {status}: {message}")

    if data is not None:
        print(f"[CLIENT] Data: {data}")

def main():
    print("=== Simple Chat Client (Updated) ===")
    print(f"Connecting to server at {HOST}:{PORT}...\n")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((HOST, PORT))
        print("[CLIENT] Connected to the server. Type commands. Type 'help' for guidance.\n")

        while True:
            user_input = input(">> ").strip()
            if not user_input:
                continue

            if user_input.lower() == "help":
                print("""Available commands:
1) CREATE <username> <password>
2) LOGIN <username> <password>
3) LIST ACCOUNTS [<page_size> <page_num>]
4) SEND <recipient> <message>
5) READ [PARTNER <username>] [<page_size> <page_num>]
   - If PARTNER <username> is omitted, returns unread messages (paginated)
   - If PARTNER <username> is provided, returns conversation with that user
6) DELETE MESSAGE <id1> [<id2> ...]
7) DELETE ACCOUNT
8) LOGOUT
9) QUIT
""")
                continue

            parts = user_input.split()
            cmd = parts[0].upper()

            if cmd == "CREATE":
                if len(parts) < 3:
                    print("[CLIENT] Usage: CREATE <username> <password>")
                    continue
                username = parts[1]
                password = " ".join(parts[2:])
                password_hash = hash_password(password)
                payload = {
                    "action": "CREATE",
                    "username": username,
                    "password_hash": password_hash
                }
                resp = send_request(s, payload)
                print_response(resp)

            elif cmd == "LOGIN":
                if len(parts) < 3:
                    print("[CLIENT] Usage: LOGIN <username> <password>")
                    continue
                username = parts[1]
                password = " ".join(parts[2:])
                password_hash = hash_password(password)
                payload = {
                    "action": "LOGIN",
                    "username": username,
                    "password_hash": password_hash
                }
                resp = send_request(s, payload)
                print_response(resp)

            elif cmd == "LIST":
                # LIST ACCOUNTS [<page_size> <page_num>]
                if len(parts) >= 2 and parts[1].upper() == "ACCOUNTS":
                    page_size = 10
                    page_num = 1
                    if len(parts) == 4:
                        page_size = int(parts[2])
                        page_num = int(parts[3])
                    elif len(parts) == 3:
                        page_size = int(parts[2])

                    payload = {
                        "action": "LIST_ACCOUNTS",
                        "page_size": page_size,
                        "page_num": page_num
                    }
                    resp = send_request(s, payload)
                    print_response(resp)
                else:
                    print("[CLIENT] Usage: LIST ACCOUNTS [<page_size> <page_num>]")

            elif cmd == "SEND":
                if len(parts) < 3:
                    print("[CLIENT] Usage: SEND <recipient> <message>")
                    continue
                recipient = parts[1]
                message = " ".join(parts[2:])
                payload = {
                    "action": "SEND",
                    "recipient": recipient,
                    "content": message
                }
                resp = send_request(s, payload)
                print_response(resp)

            elif cmd == "READ":
                #  Two forms:
                #    - READ PARTNER <username> [page_size] [page_num]
                #    - READ [page_size] [page_num]
                if len(parts) >= 2 and parts[1].upper() == "PARTNER":
                    # READ PARTNER <username> [page_size] [page_num]
                    if len(parts) < 3:
                        print("[CLIENT] Usage: READ PARTNER <username> [<page_size> <page_num>]")
                        continue
                    partner = parts[2]
                    page_size = 5
                    page_num = 1
                    if len(parts) >= 4:
                        page_size = int(parts[3])
                    if len(parts) >= 5:
                        page_num = int(parts[4])

                    payload = {
                        "action": "READ",
                        "chat_partner": partner,
                        "page_size": page_size,
                        "page_num": page_num
                    }
                    resp = send_request(s, payload)
                    print_response(resp)

                else:
                    # READ [page_size] [page_num]  => unread from all
                    page_size = 5
                    page_num = 1
                    if len(parts) >= 2:
                        page_size = int(parts[1])
                    if len(parts) >= 3:
                        page_num = int(parts[2])

                    payload = {
                        "action": "READ",
                        "page_size": page_size,
                        "page_num": page_num
                    }
                    resp = send_request(s, payload)
                    print_response(resp)

            elif cmd == "DELETE":
                # DELETE MESSAGE <id1> [<id2> ...] or DELETE ACCOUNT
                if len(parts) < 2:
                    print("[CLIENT] Usage: DELETE MESSAGE <id1> [<id2> ...] or DELETE ACCOUNT")
                    continue
                sub_cmd = parts[1].upper()

                if sub_cmd == "MESSAGE":
                    if len(parts) < 3:
                        print("[CLIENT] Usage: DELETE MESSAGE <id1> [<id2> ...]")
                        continue
                    message_ids = [int(x) for x in parts[2:]]
                    payload = {
                        "action": "DELETE_MESSAGE",
                        "message_ids": message_ids
                    }
                    resp = send_request(s, payload)
                    print_response(resp)
                elif sub_cmd == "ACCOUNT":
                    payload = {
                        "action": "DELETE_ACCOUNT"
                    }
                    resp = send_request(s, payload)
                    print_response(resp)
                else:
                    print("[CLIENT] Usage: DELETE MESSAGE <id1> [<id2> ...] or DELETE ACCOUNT")

            elif cmd == "LOGOUT":
                payload = {"action": "LOGOUT"}
                resp = send_request(s, payload)
                print_response(resp)

            elif cmd == "QUIT":
                payload = {"action": "QUIT"}
                resp = send_request(s, payload)
                print_response(resp)
                print("[CLIENT] Quitting the client.")
                break

            else:
                print("[CLIENT] Unknown command. Type 'help' for available commands.")

if __name__ == "__main__":
    main()
