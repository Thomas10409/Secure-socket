import os
import uuid
import socket
import cbor2 as cbor

from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import serialization

host = "0.0.0.0"
port = 12345
server_id = None

if not os.path.exists("./data"):
    os.mkdir("./data")

if not os.path.exists("./data/clients"):
    os.mkdir("./data/clients")
    
if not os.path.exists("./data/setting"):
    os.mkdir("./data/setting")

if not os.path.exists("./data/setting/setting.cbor"):
    setting = {
        "server_id": str(uuid.uuid4())
    }
    with open("./data/setting/setting.cbor", "wb") as f:
        f.write(cbor.dumps(setting))

if not os.path.exists("private_key.pem"):
    if os.path.exists("public_key.pem"):
        os.remove("public_key.pem")
    print("Generating new Ed25519 key pair...")
    pri_key = ed25519.Ed25519PrivateKey.generate()
    pub_key = pri_key.public_key()
    with open("private_key.pem", "wb") as f:
        f.write(
            pri_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.OpenSSH,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    with open("public_key.pem", "wb") as f:
        f.write(
            pub_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )

if not os.path.exists("public_key.pem"):
    print("Generating new Ed25519 key pair...")
    with open("private_key.pem", "rb") as f:
        pri_key = serialization.load_pem_private_key(f.read(), password=None)
    pub_key = pri_key.public_key()
    
    with open("public_key.pem", "wb") as f:
        f.write(
            pub_key.public_bytes(
                encoding=serialization.Encoding.OpenSSH,
                format=serialization.PublicFormat.OpenSSH,
            )
        )
        
with open("./data/setting/setting.cbor", "rb") as f:
    setting = cbor.loads(f.read())
    server_id = setting["server_id"]
    print(f"Server ID: {server_id}")

with open("private_key.pem", "rb") as f:
    pri_key = serialization.load_pem_private_key(f.read(), password=None)
    
with open("public_key.pem", "rb") as f:
    pub_key = serialization.load_ssh_public_key(f.read())
    
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))
print(f"Server listening on {host}:{port}")

while True:
    server.listen(1)
    conn, addr = server.accept()
    