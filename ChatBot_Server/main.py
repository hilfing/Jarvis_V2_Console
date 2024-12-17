import base64
import logging
import os
import re
import uuid
from datetime import datetime, timedelta

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.hmac import HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import APIRouter, Depends, HTTPException
from fastapi import FastAPI
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose.exceptions import JWTError
from jose import JWTError as JWTErr, jwt
from passlib.context import CryptContext
from pydantic import BaseModel
from sqlalchemy import create_engine, Column, String, DateTime, LargeBinary, Integer, text
from sqlalchemy.orm import Session
from sqlalchemy.orm import declarative_base
from sqlalchemy.orm import sessionmaker
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from typing_extensions import List, Dict, Optional

# Enhanced Logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('security_system.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('SecureEncryptionSystem')

# Database Configuration
DATABASE_URL = os.getenv("DB_URL")
engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

LOG_LINE_REGEX = re.compile(
    r"(?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d{3}) - "
    r"(?P<logger>\w+) - (?P<level>\w+) - (?P<message>.+)"
)

SECRET_KEY = "secret-key"
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

users_db = {
    os.getenv("ADMIN_NAME", "admin"): {
        "username": os.getenv("ADMIN_NAME", "admin"),
        "hashed_password": pwd_context.hash(os.getenv("ADMIN_PASSWORD", "admin")),
    }}


def parse_log_file(file_path: str) -> Dict[str,List[Dict[str, str]]]:
    logs = []
    try:
        with open(file_path, "r") as log_file:
            for line in log_file:
                match = LOG_LINE_REGEX.match(line.strip())
                if match:
                    logs.append(match.groupdict())
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Log file not found.")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"An error occurred: {str(e)}")
    final = {"logs": logs}
    return final

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Verify a plaintext password against the hashed password.
    """
    return pwd_context.verify(plain_password, hashed_password)

def authenticate_user(username: str, password: str) -> Optional[Dict[str, str]]:
    """
    Authenticate a user by verifying their credentials.
    """
    user = users_db.get(username)
    if user and verify_password(password, user["hashed_password"]):
        return user
    return None

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    """
    Create a JWT token with the given data and expiration time.
    """
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

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


def remove_pkcs7_padding(data):
    """
    Remove PKCS7 padding from the decrypted data.

    Args:
        data (bytes): Decrypted data potentially with PKCS7 padding.

    Returns:
        bytes: Data with padding removed.
    """
    padding_length = data[-1]

    # Validate padding
    if padding_length == 0 or padding_length > 16:
        raise ValueError("Invalid PKCS7 padding")

    # Check that all padding bytes are correct
    if data[-padding_length:] != bytes([padding_length] * padding_length):
        raise ValueError("Invalid PKCS7 padding")

    # Remove padding
    return data[:-padding_length]

# Security Utilities
class SecurityUtilities:
    @staticmethod
    def generate_server_key_pair(db: Session):
        """Generate and store a new server key pair."""
        private_key = ec.generate_private_key(
            ec.SECP256R1(),
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
                encoding=serialization.Encoding.DER,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ),
            is_active='active'
        )
        db.add(new_key_rotation)
        db.commit()

        return private_key, public_key, new_key_rotation.id

    @staticmethod
    def derive_shared_secret(private_key, peer_public_key):
        # Explicit exchange
        shared_key = private_key.exchange(ec.ECDH(), peer_public_key)

        # Consistent HKDF
        return HKDF(
            algorithm=hashes.SHA384(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)

    @staticmethod
    def encrypt_message(key: bytes, message: bytes) -> dict:
        """
        Secure message encryption with PKCS7 padding, IV, and HMAC.

        Args:
            key (bytes): Encryption key
            message (bytes): Message to encrypt

        Returns:
            dict: Encrypted payload with base64 encoded components
        """
        try:

            # Generate IV
            iv = os.urandom(16)

            # Create cipher with PKCS7 padding
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            encryptor = cipher.encryptor()

            # Apply PKCS7 padding
            padder = padding.PKCS7(algorithms.AES.block_size).padder()
            padded_data = padder.update(message) + padder.finalize()

            # Encrypt
            encrypted_message = encryptor.update(padded_data) + encryptor.finalize()

            # Use key to derive consistent HMAC key
            hmac_key = key[:32]  # Use first 32 bytes of key for HMAC

            # Compute HMAC
            hmac_obj = HMAC(hmac_key, hashes.SHA384(), backend=default_backend())
            hmac_obj.update(encrypted_message)
            hmac_digest = hmac_obj.finalize()

            # Return payload
            payload = {
                'iv': base64.b64encode(iv).decode('utf-8'),
                'ciphertext': base64.b64encode(encrypted_message).decode('utf-8'),
                'hmac': base64.b64encode(hmac_digest).decode('utf-8'),
                'hmac_key': base64.b64encode(hmac_key).decode('utf-8')
            }

            return payload

        except Exception as e:
            logging.error(f"Encryption failed: {e}")
            logging.error(f"Exception Type: {type(e).__name__}")
            import traceback
            logging.error(f"Traceback: {traceback.format_exc()}")
            raise

    @staticmethod
    def decrypt_message(key: bytes, encrypted_payload: dict) -> bytes:
        """Secure message decryption with HMAC verification and extensive logging."""
        try:

            # Decoding payload components
            iv = base64.b64decode(encrypted_payload['iv'])
            ciphertext = base64.b64decode(encrypted_payload['ciphertext'])
            hmac_digest = base64.b64decode(encrypted_payload['hmac'])
            hmac_key = base64.b64decode(encrypted_payload['hmac_key'])

            # HMAC Verification
            hmac_obj = HMAC(hmac_key, hashes.SHA384(), backend=default_backend())
            hmac_obj.update(ciphertext)

            try:
                hmac_obj.verify(hmac_digest)
            except Exception as hmac_error:
                logging.error(f"HMAC Verification Failed: {hmac_error}")
                raise

            # Decryption
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()

            decrypted = decryptor.update(ciphertext) + decryptor.finalize()

            # Explicitly remove PKCS7 padding
            unpadded_message = remove_pkcs7_padding(decrypted)

            return unpadded_message

        except Exception as e:
            logging.error(f"Decryption failed: {e}")
            logging.error(f"Exception Type: {type(e).__name__}")
            import traceback
            logging.error(f"Traceback: {traceback.format_exc()}")
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

class SuppressLogMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if request.url.path == "/health":
            # Suppress logs
            import logging
            logging.getLogger("uvicorn.access").disabled = True
        else:
            import logging
            logging.getLogger("uvicorn.access").disabled = False
        return await call_next(request)

app.add_middleware(SuppressLogMiddleware)

# Database Dependency
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

@app.post("/token")
async def login(form_data: OAuth2PasswordRequestForm = Depends()):
    """
    Real login endpoint for obtaining a JWT token.
    """
    logger.debug(f"Received token request for user: {form_data.username}")
    user = authenticate_user(form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=401,
            detail="Invalid username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["username"]}, expires_delta=access_token_expires
    )
    logger.info(f"User {user['username']} authenticated successfully")
    return {"access_token": access_token, "token_type": "bearer"}

async def get_current_user(token: str = Depends(oauth2_scheme)) -> dict:
    """
    Validate the JWT token and retrieve the current user.
    """
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        user = users_db.get(username)
        if user is None:
            raise HTTPException(status_code=401, detail="User not found")
        return {"username": username}
    except JWTError or JWTErr:
        raise HTTPException(status_code=401, detail="Invalid authentication credentials")

@app.post("/key-exchange")
def initiate_key_exchange(
        request: KeyExchangeRequest,
        db: Session = Depends(get_db)
):
    try:
        logger.info(f"Received client public key. Client ID: {request.client_id}")

        # Deserialize client public key
        client_public_key_bytes = base64.b64decode(request.client_public_key)
        client_public_key = serialization.load_der_public_key(
            client_public_key_bytes,
            backend=default_backend()
        )
        logger.info("Successfully loaded client public key")

        # Get active server key or generate new
        active_server_key = db.query(ServerKeyRotation).filter(
            ServerKeyRotation.is_active == 'active'
        ).first()

        # Generate new server key pair using SECP256R1
        server_private_key = ec.generate_private_key(
            ec.SECP256R1(),
            backend=default_backend()
        )
        server_public_key = server_private_key.public_key()

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
            client_public_key=client_public_key_bytes,  # Store original bytes
            server_key_id=active_server_key.id,  # You might want to track this differently
            derived_key=shared_secret,
            hmac_key=os.urandom(32)
        )
        db.add(key_exchange_record)
        db.commit()

        logger.info(f"Key exchange completed for client: {client_id}")

        # Return server public key in DER format
        return {
            "client_id": client_id,
            "server_public_key": base64.b64encode(
                server_public_key.public_bytes(
                    encoding=serialization.Encoding.DER,
                    format=serialization.PublicFormat.SubjectPublicKeyInfo
                )
            ).decode()
        }

    except Exception as e:
        logger.error(f"Key Exchange Error: {e}")
        logger.error(f"Full exception: {e.with_traceback()}")
        raise HTTPException(status_code=500, detail=str(e))


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
                return {"status": "invalid_verification_code"}

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

@app.get("/logs", response_model=List[Dict[str, str]])
async def get_logs(current_user: dict = Depends(get_current_user)):
    """
    Endpoint to fetch logs in JSON format.
    """
    return parse_log_file("security_system.log")

@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    try:
        with SessionLocal() as test_session:
            test_session.execute(text("SELECT 1"))
        return {"status": "ok", "db_status": "connected"}
    except Exception as db_error:
        logger.error(f"Database connection failed: {db_error}")
        return {"status": "error", "db_status": "disconnected"}


# Create a router for chat-related endpoints
chat_router = APIRouter()


# Pydantic model for chat request
class ChatRequest(BaseModel):
    client_id: str
    encrypted_payload: dict


# Pydantic model for chat response
class ChatResponse(BaseModel):
    status: str
    response_payload: dict = None


@chat_router.post("/chat", response_model=ChatResponse)
def process_encrypted_chat(
        request: ChatRequest,
        db: Session = Depends(get_db)
):
    """
    Process an encrypted chat message and return an encrypted response.

    - Validates client connection
    - Decrypts incoming message
    - Processes message
    - Encrypts and returns response
    """
    try:
        # Retrieve key exchange record
        key_exchange = db.query(ClientKeyExchange).filter(
            ClientKeyExchange.client_id == request.client_id
        ).first()

        if not key_exchange:
            logger.warning(f"Client ID not found for chat: {request.client_id}")
            raise HTTPException(status_code=401, detail="Invalid client")

        # Check key expiration
        if SecurityUtilities.is_key_expired(key_exchange.created_at):
            logger.warning(f"Expired key for chat client: {request.client_id}")
            db.delete(key_exchange)
            db.commit()
            raise HTTPException(status_code=401, detail="Key expired")

        try:
            # Decrypt the incoming message
            decrypted_message = SecurityUtilities.decrypt_message(
                key_exchange.derived_key,
                request.encrypted_payload
            )

            # Process the decrypted message
            processed_response = process_chat_message(decrypted_message)

            # Encrypt the response
            encrypted_response = SecurityUtilities.encrypt_message(
                key_exchange.derived_key,
                processed_response.encode()
            )

            # Update last interaction
            key_exchange.last_verified_at = datetime.utcnow()
            db.commit()

            logger.info(f"Chat processed for client: {request.client_id}")
            return {
                "status": "success",
                "response_payload": encrypted_response
            }

        except ValueError as decrypt_error:
            logger.error(f"Decryption error in chat: {decrypt_error}")
            raise HTTPException(status_code=400, detail="Decryption failed")

    except Exception as e:
        logger.error(f"Chat Processing Error: {e}")
        raise HTTPException(status_code=500, detail="Chat processing failed")


def process_chat_message(message: bytes) -> str:
    """
    Core message processing logic.

    This is a placeholder implementation that you'll customize based on your specific requirements.

    Args:
        message (bytes): Decrypted message bytes

    Returns:
        str: Processed response message
    """
    try:
        # Convert bytes to string
        message_str = message.decode('utf-8')

        # Implement your specific message processing logic here
        # For example:
        if message_str.startswith("/help"):
            return "Available commands: /help, /status"
        elif message_str.startswith("/status"):
            return "System is operational"
        else:
            return f"Echo: {message_str}"

    except Exception as e:
        logger.error(f"Message processing error: {e}")
        return "Error processing message"


# Include the router in your main FastAPI app
app.include_router(chat_router, prefix="/api/v1")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
