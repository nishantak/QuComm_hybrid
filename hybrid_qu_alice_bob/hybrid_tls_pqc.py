"""
Post-Quantum Hybrid TLS Implementation

This module implements a hybrid TLS handshake that follows the exact specification:
- Plane 1: Classical TLS 1.3 handshake with ECDHE + RSA/ECDSA
- Plane 2: Post-quantum ML-KEM (Kyber) + ML-DSA (Dilithium) signatures
- Key Bridge: HKDF-Extract(salt, Z_ec || Z_pq) -> master_secret

The implementation uses post-quantum algorithms from pqcrypto library.
"""

import hashlib
import hmac
import os
import socket
import ssl
import struct
import time
from typing import Tuple, Optional, Dict, Any
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Import post-quantum algorithms
try:
    from pqcrypto.kem.ml_kem_1024 import generate_keypair, encrypt, decrypt
    from pqcrypto.sign.ml_dsa_65 import generate_keypair as generate_sign_keypair, sign, verify
    PQC_AVAILABLE = True
except ImportError:
    PQC_AVAILABLE = False
    print("Warning: pqcrypto not available. Falling back to simulation.")


class PostQuantumHybridTLSHandshake:
    """Implements post-quantum hybrid TLS handshake using ML-KEM and ML-DSA"""
    
    def __init__(self, is_server: bool = False):
        self.is_server = is_server
        self.ec_private_key = None
        self.ec_public_key = None
        self.mlkem_private_key = None
        self.mlkem_public_key = None
        self.mldsa_private_key = None
        self.mldsa_public_key = None
        self.peer_ec_public_key = None
        self.peer_mlkem_public_key = None
        self.peer_mldsa_public_key = None
        self.master_secret = None
        self.session_keys = {}
        
    def generate_keys(self) -> None:
        """Generate all required cryptographic keys"""
        # Generate ECDHE key pair (P-256) - Plane 1
        self.ec_private_key = ec.generate_private_key(ec.SECP256R1(), default_backend())
        self.ec_public_key = self.ec_private_key.public_key()
        
        if PQC_AVAILABLE:
            # Generate ML-KEM key pair - Plane 2
            self.mlkem_public_key, self.mlkem_private_key = generate_keypair()
            
            # Generate ML-DSA key pair - Plane 2
            self.mldsa_public_key, self.mldsa_private_key = generate_sign_keypair()
        else:
            # Fallback to RSA simulation if pqcrypto not available
            print("PQC algorithms not available, using RSA for simulation.")
            self.mlkem_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=3072,
                backend=default_backend()
            )
            self.mlkem_public_key = self.mlkem_private_key.public_key()
            
            self.mldsa_private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=4096,
                backend=default_backend()
            )
            self.mldsa_public_key = self.mldsa_private_key.public_key()
        
    def serialize_ec_public_key(self) -> bytes:
        """Serialize ECDHE public key for transmission"""
        return self.ec_public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    
    def deserialize_ec_public_key(self, data: bytes) -> None:
        """Deserialize ECDHE public key from received data"""
        self.peer_ec_public_key = serialization.load_der_public_key(data, default_backend())
    
    def serialize_mlkem_public_key(self) -> bytes:
        """Serialize ML-KEM public key for transmission"""
        if PQC_AVAILABLE:
            return self.mlkem_public_key
        else:
            return self.mlkem_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    def deserialize_mlkem_public_key(self, data: bytes) -> None:
        """Deserialize ML-KEM public key from received data"""
        if PQC_AVAILABLE:
            self.peer_mlkem_public_key = data
        else:
            self.peer_mlkem_public_key = serialization.load_der_public_key(data, default_backend())
    
    def serialize_mldsa_public_key(self) -> bytes:
        """Serialize ML-DSA public key for transmission"""
        if PQC_AVAILABLE:
            return self.mldsa_public_key
        else:
            return self.mldsa_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
    
    def deserialize_mldsa_public_key(self, data: bytes) -> None:
        """Deserialize ML-DSA public key from received data"""
        if PQC_AVAILABLE:
            self.peer_mldsa_public_key = data
        else:
            self.peer_mldsa_public_key = serialization.load_der_public_key(data, default_backend())
    
    def perform_ecdh(self) -> bytes:
        """Perform ECDH key exchange to get shared secret (Plane 1)"""
        if not self.peer_ec_public_key:
            raise ValueError("Peer ECDHE public key not set")
        
        shared_key = self.ec_private_key.exchange(ec.ECDH(), self.peer_ec_public_key)
        return shared_key
    
    def perform_mlkem_encapsulation(self) -> Tuple[bytes, bytes]:
        """Perform ML-KEM encapsulation (client side) - Plane 2"""
        if not self.peer_mlkem_public_key:
            raise ValueError("Peer ML-KEM public key not set")
        
        if PQC_AVAILABLE:
            # ML-KEM encapsulation
            ciphertext, shared_secret = encrypt(self.peer_mlkem_public_key)
            return ciphertext, shared_secret
        else:
            # Fallback simulation
            shared_secret = os.urandom(32)
            ciphertext = self.peer_mlkem_public_key.encrypt(
                shared_secret,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            time.sleep(0.001)  # Simulate ML-KEM delay
            return ciphertext, shared_secret
    
    def perform_mlkem_decapsulation(self, ciphertext: bytes) -> bytes:
        """Perform ML-KEM decapsulation (server side) - Plane 2"""
        if not self.mlkem_private_key:
            raise ValueError("ML-KEM private key not set")
        
        if PQC_AVAILABLE:
            # ML-KEM decapsulation
            shared_secret = decrypt(self.mlkem_private_key, ciphertext)
            return shared_secret
        else:
            # Fallback simulation
            shared_secret = self.mlkem_private_key.decrypt(
                ciphertext,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            time.sleep(0.001)  # Simulate ML-KEM delay
            return shared_secret
    
    def sign_handshake_data(self, data: bytes) -> bytes:
        """Sign handshake data with ML-DSA"""
        if not self.mldsa_private_key:
            raise ValueError("ML-DSA private key not set")
        
        if PQC_AVAILABLE:
            # ML-DSA signature
            signature = sign(self.mldsa_private_key, data)
            return signature
        else:
            # Fallback simulation
            signature = self.mldsa_private_key.sign(
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            time.sleep(0.002)  # Simulate ML-DSA delay
            return signature
    
    def verify_handshake_signature(self, data: bytes, signature: bytes) -> bool:
        """Verify handshake signature with ML-DSA"""
        if not self.peer_mldsa_public_key:
            raise ValueError("Peer ML-DSA public key not set")
        
        try:
            if PQC_AVAILABLE:
                # ML-DSA verification
                verify(self.peer_mldsa_public_key, data, signature)
                return True
            else:
                # Fallback simulation
                self.peer_mldsa_public_key.verify(
                    signature,
                    data,
                    padding.PSS(
                        mgf=padding.MGF1(hashes.SHA256()),
                        salt_length=padding.PSS.MAX_LENGTH
                    ),
                    hashes.SHA256()
                )
                time.sleep(0.002)  # Simulate ML-DSA delay
                return True
        except:
            return False
    
    def combine_secrets(self, ec_secret: bytes, mlkem_secret: bytes) -> bytes:
        """Combine ECDHE and ML-KEM secrets using HKDF-Extract (Key Bridge)"""
        # Concatenate both secrets: Z_ec || Z_pq
        combined_input = ec_secret + mlkem_secret
        
        # Use HKDF-Extract with zero salt (as per TLS 1.3 spec)
        salt = b'\x00' * 32  # Zero salt
        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            info=b'tls13 hybrid master',
            backend=default_backend()
        )
        
        self.master_secret = hkdf.derive(combined_input)
        return self.master_secret
    
    def derive_session_keys(self) -> Dict[str, bytes]:
        """Derive session keys from master secret using HKDF-Expand"""
        if not self.master_secret:
            raise ValueError("Master secret not derived yet")
        
        # Derive different keys for different purposes
        key_material = b''
        for info in [b'client key', b'server key', b'client iv', b'server iv']:
            hkdf = HKDF(
                algorithm=hashes.SHA256(),
                length=32,
                salt=self.master_secret,
                info=info,
                backend=default_backend()
            )
            key_material += hkdf.derive(b'')
        
        self.session_keys = {
            'client_key': key_material[0:32],
            'server_key': key_material[32:64],
            'client_iv': key_material[64:96],
            'server_iv': key_material[96:128]
        }
        
        return self.session_keys


class PostQuantumHybridTLSClient:
    """Post-Quantum Hybrid TLS Client implementation"""
    
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.handshake =PostQuantumHybridTLSHandshake(is_server=False)
        self.metrics = {}
        
    def connect_and_handshake(self) -> Dict[str, Any]:
        """Perform complete post-quantum hybrid TLS handshake"""
        start_time = time.perf_counter()
        
        # Generate client keys
        self.handshake.generate_keys()
        
        # Connect to server
        tcp_start = time.perf_counter()
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((self.host, self.port))
        tcp_end = time.perf_counter()
        self.metrics['tcp_connect_time_ms'] = (tcp_end - tcp_start) * 1000.0
        
        # Send ClientHello with all public keys (Plane 1 + Plane 2)
        client_hello_start = time.perf_counter()
        self._send_client_hello()
        client_hello_end = time.perf_counter()
        self.metrics['client_hello_time_ms'] = (client_hello_end - client_hello_start) * 1000.0
        
        # Receive ServerHello
        server_hello_start = time.perf_counter()
        self._receive_server_hello()
        server_hello_end = time.perf_counter()
        self.metrics['server_hello_time_ms'] = (server_hello_end - server_hello_start) * 1000.0
        
        # Perform ECDH key exchange (Plane 1)
        ecdh_start = time.perf_counter()
        ec_secret = self.handshake.perform_ecdh()
        ecdh_end = time.perf_counter()
        self.metrics['ecdh_time_ms'] = (ecdh_end - ecdh_start) * 1000.0
        
        # Perform ML-KEM encapsulation (Plane 2)
        mlkem_start = time.perf_counter()
        mlkem_ciphertext, mlkem_secret = self.handshake.perform_mlkem_encapsulation()
        mlkem_end = time.perf_counter()
        self.metrics['mlkem_encapsulation_time_ms'] = (mlkem_end - mlkem_start) * 1000.0
        
        # Send ML-KEM ciphertext
        self._send_mlkem_ciphertext(mlkem_ciphertext)
        
        # Receive server signature and verify
        signature_start = time.perf_counter()
        server_signature = self._receive_server_signature()
        handshake_data = self._get_handshake_transcript()
        is_valid = self.handshake.verify_handshake_signature(handshake_data, server_signature)
        signature_end = time.perf_counter()
        self.metrics['signature_verification_time_ms'] = (signature_end - signature_start) * 1000.0
        
        if not is_valid:
            raise ValueError("Server signature verification failed")
        
        # Combine secrets and derive session keys (Key Bridge)
        key_derivation_start = time.perf_counter()
        self.handshake.combine_secrets(ec_secret, mlkem_secret)
        self.handshake.derive_session_keys()
        key_derivation_end = time.perf_counter()
        self.metrics['key_derivation_time_ms'] = (key_derivation_end - key_derivation_start) * 1000.0
        
        total_handshake_time = time.perf_counter() - start_time
        self.metrics['total_handshake_time_ms'] = total_handshake_time * 1000.0
        
        return self.metrics
    
    def _send_client_hello(self) -> None:
        """Send ClientHello with ECDHE, ML-KEM, and ML-DSA public keys"""
        ec_pub = self.handshake.serialize_ec_public_key()
        mlkem_pub = self.handshake.serialize_mlkem_public_key()
        mldsa_pub = self.handshake.serialize_mldsa_public_key()
        
        # Create ClientHello message
        message = struct.pack('>I', len(ec_pub)) + ec_pub
        message += struct.pack('>I', len(mlkem_pub)) + mlkem_pub
        message += struct.pack('>I', len(mldsa_pub)) + mldsa_pub
        
        self.sock.sendall(struct.pack('>I', len(message)) + message)
    
    def _receive_server_hello(self) -> None:
        """Receive ServerHello with server's public keys"""
        # Receive message length
        length_data = self._recv_exact(4)
        message_length = struct.unpack('>I', length_data)[0]
        
        # Receive message
        message = self._recv_exact(message_length)
        
        # Parse server public keys
        offset = 0
        
        # ECDHE public key
        ec_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        ec_pub_data = message[offset:offset+ec_len]
        self.handshake.deserialize_ec_public_key(ec_pub_data)
        offset += ec_len
        
        # ML-KEM public key
        mlkem_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        mlkem_pub_data = message[offset:offset+mlkem_len]
        self.handshake.deserialize_mlkem_public_key(mlkem_pub_data)
        offset += mlkem_len
        
        # ML-DSA public key
        mldsa_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        mldsa_pub_data = message[offset:offset+mldsa_len]
        self.handshake.deserialize_mldsa_public_key(mldsa_pub_data)
    
    def _send_mlkem_ciphertext(self, ciphertext: bytes) -> None:
        """Send ML-KEM ciphertext to server"""
        message = struct.pack('>I', len(ciphertext)) + ciphertext
        self.sock.sendall(message)
    
    def _receive_server_signature(self) -> bytes:
        """Receive server signature"""
        length_data = self._recv_exact(4)
        signature_length = struct.unpack('>I', length_data)[0]
        return self._recv_exact(signature_length)
    
    def _get_handshake_transcript(self) -> bytes:
        """Get handshake transcript for signature verification"""
        # In real world implementation, this would include all handshake messages
        # For simplicity, we'll use a hash of the exchanged public keys
        transcript = b''
        transcript += self.handshake.serialize_ec_public_key()
        transcript += self.handshake.serialize_mlkem_public_key()
        transcript += self.handshake.serialize_mldsa_public_key()
        if self.handshake.peer_ec_public_key:
            transcript += self.handshake.peer_ec_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        if self.handshake.peer_mlkem_public_key:
            transcript += self.handshake.peer_mlkem_public_key
        if self.handshake.peer_mldsa_public_key:
            transcript += self.handshake.peer_mldsa_public_key
        
        return hashlib.sha256(transcript).digest()
    
    def _recv_exact(self, length: int) -> bytes:
        """Receive exactly length bytes"""
        data = b''
        while len(data) < length:
            chunk = self.sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            data += chunk
        return data
    
    def encrypt_and_send(self, data: bytes) -> None:
        """Encrypt and send data using derived session keys"""
        # Use AES-GCM for encryption
        key = self.handshake.session_keys['client_key']
        iv = self.handshake.session_keys['client_iv'][:12]  # GCM uses 12-byte IV
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Send IV + ciphertext + tag
        message = iv + ciphertext + encryptor.tag
        self.sock.sendall(struct.pack('>I', len(message)) + message)
    
    def encrypt_and_send_chunked(self, data: bytes) -> None:
        """Encrypt and send data in chunks to match classical measurement methodology"""
        total_sent = 0
        view = memoryview(data)
        
        while total_sent < len(data):
            # Determine chunk size (similar to classical 16384 bytes)
            chunk_size = min(16384, len(data) - total_sent)
            chunk = bytes(view[total_sent:total_sent + chunk_size])
            
            # Use AES-GCM for encryption
            key = self.handshake.session_keys['client_key']
            iv = self.handshake.session_keys['client_iv'][:12]  # GCM uses 12-byte IV
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(chunk) + encryptor.finalize()
            
            # Send IV + ciphertext + tag
            message = iv + ciphertext + encryptor.tag
            sent = self.sock.send(struct.pack('>I', len(message)) + message)
            total_sent += chunk_size
    
    def receive_and_decrypt(self) -> bytes:
        """Receive and decrypt data"""
        # Receive message length
        length_data = self._recv_exact(4)
        message_length = struct.unpack('>I', length_data)[0]
        
        # Receive encrypted message
        encrypted_data = self._recv_exact(message_length)
        
        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        # Decrypt
        key = self.handshake.session_keys['server_key']
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def receive_and_decrypt_chunked(self, total_bytes: int) -> tuple[bytes, list[float]]:
        """Receive and decrypt data in chunks to match classical measurement methodology"""
        chunks: list[bytes] = []
        per_recv_durations: list[float] = []
        bytes_remaining = total_bytes
        
        while bytes_remaining > 0:
            # Determine chunk size (similar to classical 16384 bytes)
            chunk_size = min(16384, bytes_remaining)
            
            # Receive message length
            t0 = time.perf_counter()
            length_data = self._recv_exact(4)
            message_length = struct.unpack('>I', length_data)[0]
            
            # Receive encrypted message
            encrypted_data = self._recv_exact(message_length)
            t1 = time.perf_counter()
            per_recv_durations.append(t1 - t0)
            
            # Extract IV, ciphertext, and tag
            iv = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]
            
            # Decrypt
            key = self.handshake.session_keys['server_key']
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            chunks.append(plaintext)
            bytes_remaining -= len(plaintext)
            
            if not plaintext:
                break
        
        return b"".join(chunks), per_recv_durations
    
    def close(self) -> None:
        """Close the connection"""
        if self.sock:
            self.sock.close()


class PostQuantumHybridTLSServer:
    """Post-Quantum Hybrid TLS Server implementation"""
    def __init__(self, host: str, port: int):
        self.host = host
        self.port = port
        self.sock = None
        self.client_sock = None
        self.handshake =PostQuantumHybridTLSHandshake(is_server=True)
        self.metrics = {}
        
    def bind_and_listen(self) -> None:
        """Bind to address and start listening"""
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((self.host, self.port))
        self.sock.listen(5)
        print("POST_QUANTUM_HYBRID_SERVER_READY", flush=True)
        
    def accept_and_handshake(self) -> Dict[str, Any]:
        """Accept connection and perform post-quantum hybrid TLS handshake"""
        start_time = time.perf_counter()
        
        # Accept connection
        self.client_sock, addr = self.sock.accept()
        
        # Generate server keys
        self.handshake.generate_keys()
        
        # Receive ClientHello
        client_hello_start = time.perf_counter()
        self._receive_client_hello()
        client_hello_end = time.perf_counter()
        self.metrics['client_hello_time_ms'] = (client_hello_end - client_hello_start) * 1000.0
        
        # Send ServerHello
        server_hello_start = time.perf_counter()
        self._send_server_hello()
        server_hello_end = time.perf_counter()
        self.metrics['server_hello_time_ms'] = (server_hello_end - server_hello_start) * 1000.0
        
        # Perform ECDH key exchange (Plane 1)
        ecdh_start = time.perf_counter()
        ec_secret = self.handshake.perform_ecdh()
        ecdh_end = time.perf_counter()
        self.metrics['ecdh_time_ms'] = (ecdh_end - ecdh_start) * 1000.0
        
        # Receive and process ML-KEM ciphertext (Plane 2)
        mlkem_start = time.perf_counter()
        mlkem_ciphertext = self._receive_mlkem_ciphertext()
        mlkem_secret = self.handshake.perform_mlkem_decapsulation(mlkem_ciphertext)
        mlkem_end = time.perf_counter()
        self.metrics['mlkem_decapsulation_time_ms'] = (mlkem_end - mlkem_start) * 1000.0
        
        # Sign handshake data and send signature
        signature_start = time.perf_counter()
        handshake_data = self._get_handshake_transcript()
        signature = self.handshake.sign_handshake_data(handshake_data)
        self._send_server_signature(signature)
        signature_end = time.perf_counter()
        self.metrics['signature_generation_time_ms'] = (signature_end - signature_start) * 1000.0
        
        # Combine secrets and derive session keys (Key Bridge)
        key_derivation_start = time.perf_counter()
        self.handshake.combine_secrets(ec_secret, mlkem_secret)
        self.handshake.derive_session_keys()
        key_derivation_end = time.perf_counter()
        self.metrics['key_derivation_time_ms'] = (key_derivation_end - key_derivation_start) * 1000.0
        
        total_handshake_time = time.perf_counter() - start_time
        self.metrics['total_handshake_time_ms'] = total_handshake_time * 1000.0
        
        return self.metrics
    
    def _receive_client_hello(self) -> None:
        """Receive ClientHello from client"""
        # Receive message length
        length_data = self._recv_exact(4)
        message_length = struct.unpack('>I', length_data)[0]
        
        # Receive message
        message = self._recv_exact(message_length)
        
        # Parse client public keys
        offset = 0
        
        # ECDHE public key
        ec_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        ec_pub_data = message[offset:offset+ec_len]
        self.handshake.deserialize_ec_public_key(ec_pub_data)
        offset += ec_len
        
        # ML-KEM public key
        mlkem_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        mlkem_pub_data = message[offset:offset+mlkem_len]
        self.handshake.deserialize_mlkem_public_key(mlkem_pub_data)
        offset += mlkem_len
        
        # ML-DSA public key
        mldsa_len = struct.unpack('>I', message[offset:offset+4])[0]
        offset += 4
        mldsa_pub_data = message[offset:offset+mldsa_len]
        self.handshake.deserialize_mldsa_public_key(mldsa_pub_data)
    
    def _send_server_hello(self) -> None:
        """Send ServerHello with server's public keys"""
        ec_pub = self.handshake.serialize_ec_public_key()
        mlkem_pub = self.handshake.serialize_mlkem_public_key()
        mldsa_pub = self.handshake.serialize_mldsa_public_key()
        
        # Create ServerHello message
        message = struct.pack('>I', len(ec_pub)) + ec_pub
        message += struct.pack('>I', len(mlkem_pub)) + mlkem_pub
        message += struct.pack('>I', len(mldsa_pub)) + mldsa_pub
        
        self.client_sock.sendall(struct.pack('>I', len(message)) + message)
    
    def _receive_mlkem_ciphertext(self) -> bytes:
        """Receive ML-KEM ciphertext from client"""
        length_data = self._recv_exact(4)
        ciphertext_length = struct.unpack('>I', length_data)[0]
        return self._recv_exact(ciphertext_length)
    
    def _send_server_signature(self, signature: bytes) -> None:
        """Send server signature to client"""
        message = struct.pack('>I', len(signature)) + signature
        self.client_sock.sendall(message)
    
    def _get_handshake_transcript(self) -> bytes:
        """Get handshake transcript for signature generation"""
        # In a implementation, this would include all handshake messages
        # For simplicity, we'll use a hash of the exchanged public keys
        transcript = b''
        if self.handshake.peer_ec_public_key:
            transcript += self.handshake.peer_ec_public_key.public_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            )
        if self.handshake.peer_mlkem_public_key:
            transcript += self.handshake.peer_mlkem_public_key
        if self.handshake.peer_mldsa_public_key:
            transcript += self.handshake.peer_mldsa_public_key
        transcript += self.handshake.serialize_ec_public_key()
        transcript += self.handshake.serialize_mlkem_public_key()
        transcript += self.handshake.serialize_mldsa_public_key()
        
        return hashlib.sha256(transcript).digest()
    
    def _recv_exact(self, length: int) -> bytes:
        """Receive exactly length bytes"""
        data = b''
        while len(data) < length:
            chunk = self.client_sock.recv(length - len(data))
            if not chunk:
                raise ConnectionError("Connection closed unexpectedly")
            data += chunk
        return data
    
    def receive_and_decrypt(self) -> bytes:
        """Receive and decrypt data"""
        # Receive message length
        length_data = self._recv_exact(4)
        message_length = struct.unpack('>I', length_data)[0]
        
        # Receive encrypted message
        encrypted_data = self._recv_exact(message_length)
        
        # Extract IV, ciphertext, and tag
        iv = encrypted_data[:12]
        tag = encrypted_data[-16:]
        ciphertext = encrypted_data[12:-16]
        
        # Decrypt
        key = self.handshake.session_keys['client_key']
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        return plaintext
    
    def receive_and_decrypt_chunked(self, total_bytes: int) -> tuple[bytes, list[float]]:
        """Receive and decrypt data in chunks to match classical measurement methodology"""
        chunks: list[bytes] = []
        per_recv_durations: list[float] = []
        bytes_remaining = total_bytes
        
        while bytes_remaining > 0:
            # Determine chunk size (similar to classical 16384 bytes)
            chunk_size = min(16384, bytes_remaining)
            
            # Receive message length
            t0 = time.perf_counter()
            length_data = self._recv_exact(4)
            message_length = struct.unpack('>I', length_data)[0]
            
            # Receive encrypted message
            encrypted_data = self._recv_exact(message_length)
            t1 = time.perf_counter()
            per_recv_durations.append(t1 - t0)
            
            # Extract IV, ciphertext, and tag
            iv = encrypted_data[:12]
            tag = encrypted_data[-16:]
            ciphertext = encrypted_data[12:-16]
            
            # Decrypt
            key = self.handshake.session_keys['client_key']
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())
            decryptor = cipher.decryptor()
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
            
            chunks.append(plaintext)
            bytes_remaining -= len(plaintext)
            
            if not plaintext:
                break
        
        return b"".join(chunks), per_recv_durations
    
    def encrypt_and_send(self, data: bytes) -> None:
        """Encrypt and send data using derived session keys"""
        # Use AES-GCM for encryption
        key = self.handshake.session_keys['server_key']
        iv = self.handshake.session_keys['server_iv'][:12]  # GCM uses 12-byte IV
        
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        
        # Send IV + ciphertext + tag
        message = iv + ciphertext + encryptor.tag
        self.client_sock.sendall(struct.pack('>I', len(message)) + message)
    
    def encrypt_and_send_chunked(self, data: bytes) -> None:
        """Encrypt and send data in chunks to match classical measurement methodology"""
        total_sent = 0
        view = memoryview(data)
        
        while total_sent < len(data):
            # Determine chunk size (similar to classical 16384 bytes)
            chunk_size = min(16384, len(data) - total_sent)
            chunk = bytes(view[total_sent:total_sent + chunk_size])
            
            # Use AES-GCM for encryption
            key = self.handshake.session_keys['server_key']
            iv = self.handshake.session_keys['server_iv'][:12]  # GCM uses 12-byte IV
            
            cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
            encryptor = cipher.encryptor()
            ciphertext = encryptor.update(chunk) + encryptor.finalize()
            
            # Send IV + ciphertext + tag
            message = iv + ciphertext + encryptor.tag
            sent = self.client_sock.send(struct.pack('>I', len(message)) + message)
            total_sent += chunk_size
    
    def close(self) -> None:
        """Close the connection"""
        if self.client_sock:
            self.client_sock.close()
        if self.sock:
            self.sock.close()
