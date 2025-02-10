import socket
import threading
import hashlib
import json

# Global data structures (in-memory)
# Format:
#   accounts = {
#       username: {
#           "password_hash": <str>,
#           "messages": [
#               {
#                   "id": <int>,
#                   "sender": <str>,
#                   "content": <str>,
#                   "read": <bool>
#               },
#               ...
#           ]
#       },
#       ...
#   }
accounts = {}
# Simple incremental message ID generator
global_message_id = 0
lock = threading.Lock()

HOST = '127.0.0.1'  # localhost
PORT = 12345       # Server port


def get_unread_count(username):
    """Return number of unread messages for a user."""
    user_info = accounts.get(username, {})
    msgs = user_info.get("messages", [])
    count_unread = sum(1 for m in msgs if not m["read"])
    return count_unread


def handle_client_connection(client_socket, address):
    """
    Handle the client session: read commands, process them, respond.
    We'll keep track of whether the user is logged in, and to which account.
    """
    print(f"[SERVER] New connection from {address}")
    current_user = None  # track which user is logged in on this socket

    try:
        while True:
            data = client_socket.recv(4096).decode('utf-8').strip()
            if not data:
                # Client closed connection
                break

            # We expect the client to send a command in JSON format
            # e.g. {"action": "CREATE", "username": "bob", "password_hash": "..."}
            try:
                request = json.loads(data)
            except json.JSONDecodeError:
                send_response(client_socket, success=False, message="Invalid request format (not JSON).")
                continue

            action = request.get("action", "").upper()

            if action == "CREATE":
                # Create or reuse account if user name exists
                username = request.get("username", "")
                password_hash = request.get("password_hash", "")

                if not username or not password_hash:
                    send_response(client_socket, success=False, message="Username or password not provided.")
                    continue

                with lock:
                    if username in accounts:
                        # If account exists, check if password matches
                        if accounts[username]["password_hash"] == password_hash:
                            # Log in
                            current_user = username
                            unread = get_unread_count(username)
                            msg = (f"User '{username}' already exists. "
                                   f"Logged in successfully. Unread messages: {unread}.")
                            send_response(client_socket, success=True, message=msg)
                        else:
                            send_response(client_socket, success=False,
                                          message="User exists but password is incorrect.")
                    else:
                        # Create new account
                        accounts[username] = {
                            "password_hash": password_hash,
                            "messages": []
                        }
                        current_user = username
                        msg = f"New account '{username}' created and logged in."
                        send_response(client_socket, success=True, message=msg)

            elif action == "LOGIN":
                username = request.get("username", "")
                password_hash = request.get("password_hash", "")
                if not username or not password_hash:
                    send_response(client_socket, success=False, message="Username or password not provided.")
                    continue

                with lock:
                    if username not in accounts:
                        send_response(client_socket, success=False, message="No such user.")
                    else:
                        if accounts[username]["password_hash"] == password_hash:
                            current_user = username
                            unread = get_unread_count(username)
                            msg = f"Logged in as '{username}'. Unread messages: {unread}."
                            send_response(client_socket, success=True, message=msg)
                        else:
                            send_response(client_socket, success=False, message="Incorrect password.")

            elif action == "LIST_ACCOUNTS":
                # Must be logged in
                if current_user is None:
                    send_response(client_socket, success=False, message="Please log in first.")
                    continue

                page_size = request.get("page_size", 10)
                page_num = request.get("page_num", 1)

                with lock:
                    # Convert accounts dict keys into a list
                    all_accounts = list(accounts.keys())
                    total_accounts = len(all_accounts)
                    # Sort accounts alphabetically just for consistent listing
                    all_accounts.sort()

                    start_index = (page_num - 1) * page_size
                    end_index = start_index + page_size

                    if start_index >= total_accounts:
                        # No accounts in this page
                        page_accounts = []
                    else:
                        page_accounts = all_accounts[start_index:end_index]

                    response_data = {
                        "total_accounts": total_accounts,
                        "accounts": page_accounts
                    }
                send_response(client_socket, success=True, data=response_data)

            elif action == "SEND":
                # Must be logged in
                if current_user is None:
                    send_response(client_socket, success=False, message="Please log in first.")
                    continue

                recipient = request.get("recipient", "")
                content = request.get("content", "").strip()
                if not recipient or not content:
                    send_response(client_socket, success=False, message="Recipient or content not provided.")
                    continue

                with lock:
                    if recipient not in accounts:
                        send_response(client_socket, success=False, message="Recipient does not exist.")
                        continue

                    global global_message_id
                    global_message_id += 1

                    # Create a new message
                    message = {
                        "id": global_message_id,
                        "sender": current_user,
                        "content": content,
                        "read": False
                    }
                    # Append to recipient's mailbox
                    accounts[recipient]["messages"].append(message)

                msg = f"Message sent to '{recipient}': {content}"
                send_response(client_socket, success=True, message=msg)

            elif action == "READ":
                # Must be logged in
                if current_user is None:
                    send_response(client_socket, success=False, message="Please log in first.")
                    continue

                # Number of unread messages to deliver
                count = request.get("count", 5)

                with lock:
                    user_msgs = accounts[current_user]["messages"]
                    unread_msgs = [m for m in user_msgs if not m["read"]]

                    # Take up to 'count' unread messages
                    to_read = unread_msgs[:count]
                    # Mark them as read
                    for m in to_read:
                        m["read"] = True

                    # Prepare response
                    response_data = {
                        "read_messages": to_read,
                        "remaining_unread": len(unread_msgs) - len(to_read)
                    }
                send_response(client_socket, success=True, data=response_data)

            elif action == "DELETE_MESSAGE":
                # Must be logged in
                if current_user is None:
                    send_response(client_socket, success=False, message="Please log in first.")
                    continue

                message_ids = request.get("message_ids", [])
                if not isinstance(message_ids, list):
                    message_ids = [message_ids]

                with lock:
                    user_msgs = accounts[current_user]["messages"]
                    # Filter out any messages that match those IDs
                    before_count = len(user_msgs)
                    user_msgs = [m for m in user_msgs if m["id"] not in message_ids]
                    after_count = len(user_msgs)
                    accounts[current_user]["messages"] = user_msgs

                deleted_count = before_count - after_count
                msg = f"Deleted {deleted_count} messages."
                send_response(client_socket, success=True, message=msg)

            elif action == "DELETE_ACCOUNT":
                # Must be logged in
                if current_user is None:
                    send_response(client_socket, success=False, message="Please log in first.")
                    continue

                with lock:
                    # Remove the account entirely
                    del accounts[current_user]
                send_response(client_socket, success=True,
                              message=f"Account '{current_user}' deleted.")
                # After deleting the account, log the user out
                current_user = None

            elif action == "LOGOUT":
                if current_user is not None:
                    send_response(client_socket, success=True,
                                  message=f"User '{current_user}' logged out.")
                    current_user = None
                else:
                    send_response(client_socket, success=False, message="No user is currently logged in.")

            elif action == "QUIT":
                # Terminate the session
                send_response(client_socket, success=True, message="Connection closed.")
                break

            else:
                send_response(client_socket, success=False, message="Unknown action.")
    except Exception as e:
        print(f"[SERVER] Exception in client handler: {e}")
    finally:
        client_socket.close()
        print(f"[SERVER] Connection closed from {address}")


def send_response(client_socket, success=True, message="", data=None):
    """Send a JSON response to the client."""
    resp = {
        "success": success,
        "message": message
    }
    if data is not None:
        resp["data"] = data
    resp_str = json.dumps(resp)
    client_socket.sendall((resp_str + "\n").encode('utf-8'))


def start_server():
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_socket.bind((HOST, PORT))
    server_socket.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}")

    try:
        while True:
            client_sock, addr = server_socket.accept()
            client_thread = threading.Thread(target=handle_client_connection,
                                             args=(client_sock, addr),
                                             daemon=True)
            client_thread.start()
    except KeyboardInterrupt:
        print("[SERVER] Shutting down server.")
    finally:
        server_socket.close()


if __name__ == "__main__":
    start_server()
