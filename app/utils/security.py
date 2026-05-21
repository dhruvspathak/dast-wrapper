from cryptography.fernet import Fernet
from app.core.config import settings
import base64

class SecurityUtils:
    def __init__(self):
        key = base64.urlsafe_b64encode(settings.secret_key.encode()[:32].ljust(32, b'\0'))
        self.fernet = Fernet(key)

    def encrypt(self, data: str) -> str:
        return self.fernet.encrypt(data.encode()).decode()

    def decrypt(self, token: str) -> str:
        return self.fernet.decrypt(token.encode()).decode()


def encrypt_data(data: str) -> str:
    return SecurityUtils().encrypt(data)


def decrypt_data(token: str) -> str:
    return SecurityUtils().decrypt(token)
