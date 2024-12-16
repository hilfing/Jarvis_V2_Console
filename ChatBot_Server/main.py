import os
import uuid
import logging
import base64
from datetime import datetime, timedelta

from fastapi import FastAPI, HTTPException, Depends, Header
from fastapi.security import APIKeyHeader
from sqlalchemy import create_engine, Column, String, DateTime, LargeBinary, Integer
from sqlalchemy.orm import sessionmaker, Session
from sqlalchemy.orm import declarative_base
from pydantic import BaseModel, constr

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

# Enhanced Logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecureEncryptionSystem')

# Database Configuration
DATABASE_URL = "postgresql://user:password@localhost/encryption_system"
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


# Database Models
class ServerKeyRotation(Base):
    __tablename__ = "server_key_rotations"
    id = Column(Integer, primary_key=True, autoincrement=True)
    server_private_key = Column(LargeBinary, nullable=False)
    server_public_key = Column(LargeBinary, nullable=False)
    rotation_timestamp = Column(DateTime, default=datetime.utcnow)
    is_active = Column(String, default='active')


class ClientKeyExchange(Base):
    __tablename__ = "client_key_exchanges"
    client_id = Column(String, primary_key=True)
    client_public_key = Column(LargeBinary, nullable=False)
    server_key_id = Column(Integer, nullable=False)
    derived_key = Column(LargeBinary, nullable=False)
    hmac_key = Column(LargeBinary, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_verified_at = Column(DateTime, nullable=True)
    verification_attempts = Column(Integer, default=0)


# Security Utilities
class SecurityUtilities:
    @staticmethod
    def generate_server_key_pair(db: Session):
        """Generate and store a new server key pair."""
        private_key = ec.generate_private_key(
            ec.SECP384R1(),
            backend=default_backend()
        )
        public_key = private_key.public_key()

        # Deactivate previous active keys
        db.query(ServerKeyRotation).filter(
            ServerKeyRotation.is_active == 'active'
        ).update({'is_active': 'inactive'})

        # Store new key pair
        new_key_rotation = ServerKeyRotation(
            server_private_key=private_key.private_bytes(
                encoding=serialization.Encoding.DER,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ),
            server_public_key=public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            is_active='active'
        )
        db.add(new_key_rotation)
        db.commit()

        return private_key, public_key, new_key_rotation.id

    @staticmethod
    def derive_shared_secret(private_key, peer_public_key):
        """Derive a shared secret using ECDH."""
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)
        return HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

    @staticmethod
    def encrypt_message(key: bytes, message: bytes) -> dict:
        """Secure message encryption with IV and HMAC."""
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        encryptor = cipher.encryptor()

        padded_data = message + b'\x00' * (16 - len(message) % 16)
        encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

        hmac_key = os.urandom(32)
        hmac_obj = hashes.HMAC(hmac_key, hashes.SHA384(), backend=default_backend())
        hmac_obj.update(encrypted_message)
        hmac_digest = hmac_obj.finalize()

        return {
            'iv': base64.b64encode(iv).decode(),
            'ciphertext': base64.b64encode(encrypted_message).decode(),
            'hmac': base64.b64encode(hmac_digest).decode(),
            'hmac_key': base64.b64encode(hmac_key).decode()
        }

    @staticmethod
    def decrypt_message(key: bytes, encrypted_payload: dict) -> bytes:
        """Secure message decryption with HMAC verification."""
        try:
            iv = base64.b64decode(encrypted_payload['iv'])
            ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
            hmac_digest = base64.b64decode(encrypted_payload['hmac'])
            hmac_key = base64.b64decode(encrypted_payload['hmac_key'])

            # HMAC Verification
            hmac_obj = hashes.HMAC(hmac_key, hashes.SHA384(), backend=default_backend())
            hmac_obj.update(ciphertext)
            hmac_obj.verify(hmac_digest)

            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            return decrypted.rstrip(b'\x00')
        except Exception as e:
            logger.error(f"Decryption failed: {e}")
            raise ValueError("Decryption or HMAC verification failed")

    @staticmethod
    def is_key_expired(created_at: datetime, max_age: timedelta = timedelta(days=7)) -> bool:
        """Check if a key has expired."""
        return datetime.utcnow() > created_at + max_age


# Pydantic Models
class KeyExchangeRequest(BaseModel):
    client_public_key: str
    client_id: str = None


class VerificationRequest(BaseModel):
    client_id: str
    encrypted_payload: dict


# FastAPI Application
app = FastAPI(
    title="Advanced Secure Encryption System",
    description="Robust end-to-end encrypted communication with key rotation",
    version="1.0.0"
)


# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


@app.post("/key-exchange")
def initiate_key_exchange(
        request: KeyExchangeRequest,
        db: Session = Depends(get_db)
):
    """Initiate secure key exchange with server key rotation."""
    try:
        # Get active server key
        active_server_key = db.query(ServerKeyRotation).filter(
            ServerKeyRotation.is_active == 'active'
        ).first()

        if not active_server_key:
            # Generate new server key if no active key exists
            server_private_key, server_public_key, server_key_id = SecurityUtilities.generate_server_key_pair(db)
        else:
            # Deserialize existing active server key
            server_private_key = serialization.load_der_private_key(
                active_server_key.server_private_key,
                password=None,
                backend=default_backend()
            )
            server_public_key = serialization.load_pem_public_key(
                active_server_key.server_public_key,
                backend=default_backend()
            )
            server_key_id = active_server_key.id

        # Deserialize client public key
        client_public_key = serialization.load_pem_public_key(
            request.client_public_key.encode(),
            backend=default_backend()
        )

        # Derive shared secret
        shared_secret = SecurityUtilities.derive_shared_secret(
            server_private_key,
            client_public_key
        )

        # Generate/use provided client ID
        client_id = request.client_id or str(uuid.uuid4())

        # Store key exchange details
        key_exchange_record = ClientKeyExchange(
            client_id=client_id,
            client_public_key=client_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            server_key_id=server_key_id,
            derived_key=shared_secret,
            hmac_key=os.urandom(32)
        )
        db.add(key_exchange_record)
        db.commit()

        logger.info(f"Key exchange initiated for client: {client_id}")
        return {
            "client_id": client_id,
            "server_public_key": server_public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ).decode()
        }
    except Exception as e:
        logger.error(f"Key Exchange Error: {e}")
        raise HTTPException(status_code=500, detail="Key exchange failed")


@app.post("/verify-connection")
def verify_connection(
        request: VerificationRequest,
        db: Session = Depends(get_db)
):
    """Verify client connection with a fixed message."""
    try:
        # Retrieve key exchange record
        key_exchange = db.query(ClientKeyExchange).filter(
            ClientKeyExchange.client_id == request.client_id
        ).first()

        if not key_exchange:
            logger.warning(f"Client ID not found: {request.client_id}")
            return {"status": "invalid_client"}

        # Check key expiration
        if SecurityUtilities.is_key_expired(key_exchange.created_at):
            logger.warning(f"Key expired for client: {request.client_id}")
            db.delete(key_exchange)
            db.commit()
            return {"status": "key_expired"}

        try:
            # Attempt to decrypt verification message
            decrypted_message = SecurityUtilities.decrypt_message(
                key_exchange.derived_key,
                request.encrypted_payload
            )

            # Increment verification attempts
            key_exchange.verification_attempts += 1
            key_exchange.last_verified_at = datetime.utcnow()
            db.commit()

            # Additional verification logic
            if decrypted_message == b"CONNECTION_VERIFICATION_REQUEST":
                # Encrypt and return verification response
                verification_response = SecurityUtilities.encrypt_message(
                    key_exchange.derived_key,
                    b"CONNECTION_VERIFIED_SUCCESSFULLY"
                )

                logger.info(f"Connection verified for client: {request.client_id}")
                return {"status": "verified", "verification_payload": verification_response}
            else:
                logger.warning(f"Invalid verification message from client: {request.client_id}")
                return {"status": "invalid_verification"}

        except ValueError:
            logger.error(f"Decryption failed for client: {request.client_id}")
            return {"status": "decryption_failed"}

    except Exception as e:
        logger.error(f"Verification Error: {e}")
        raise HTTPException(status_code=500, detail="Verification failed")


# Periodic Key Rotation Mechanism (can be implemented separately)
def rotate_server_keys(db: Session):
    """Rotate server keys periodically and clean up old keys."""
    try:
        # Generate new key pair
        SecurityUtilities.generate_server_key_pair(db)

        # Clean up expired client key exchanges
        expired_exchanges = db.query(ClientKeyExchange).filter(
            ClientKeyExchange.created_at < datetime.utcnow() - timedelta(days=7)
        ).delete(synchronize_session=False)

        # Clean up old server key rotations
        old_key_rotations = db.query(ServerKeyRotation).filter(
            ServerKeyRotation.rotation_timestamp < datetime.utcnow() - timedelta(days=30)
        ).delete(synchronize_session=False)

        db.commit()

        logger.info(
            f"Server keys rotated. Cleaned up {expired_exchanges} client exchanges and {old_key_rotations} old key rotations.")
    except Exception as e:
        logger.error(f"Key rotation failed: {e}")
        db.rollback()


# Startup and Shutdown Events
@app.on_event("startup")
async def startup_event():
    logger.info("Secure Encryption System starting up")

    # Initial server key generation
    db = SessionLocal()
    try:
        SecurityUtilities.generate_server_key_pair(db)
    except Exception as e:
        logger.error(f"Startup key generation failed: {e}")
    finally:
        db.close()


@app.on_event("shutdown")
async def shutdown_event():
    logger.info("Secure Encryption System shutting down")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app)