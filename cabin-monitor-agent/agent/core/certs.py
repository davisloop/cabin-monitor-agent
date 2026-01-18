"""
Certificate management for the telemetry agent.

Handles:
- Private key generation
- CSR creation
- Certificate storage and loading
- Certificate validation and expiry checks
"""
import os
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Optional, Tuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.x509.oid import NameOID


class CertificateError(Exception):
    """Certificate-related error."""
    pass


def generate_private_key(key_size: int = 2048) -> rsa.RSAPrivateKey:
    """
    Generate an RSA private key.

    Args:
        key_size: Key size in bits (default 2048)

    Returns:
        RSA private key
    """
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
        backend=default_backend()
    )


def generate_csr(
    device_id: str,
    private_key: rsa.RSAPrivateKey,
    organization: str = "CabinMonitor",
    country: Optional[str] = None,
    state: Optional[str] = None,
    locality: Optional[str] = None
) -> x509.CertificateSigningRequest:
    """
    Generate a Certificate Signing Request (CSR) for device enrollment.

    Args:
        device_id: Unique device identifier
        private_key: RSA private key
        organization: Organization name (default: CabinMonitor)
        country: Country code (optional)
        state: State/province (optional)
        locality: City/locality (optional)

    Returns:
        Certificate Signing Request
    """
    # Build subject name
    subject_attrs = [
        x509.NameAttribute(NameOID.COMMON_NAME, f"device:{device_id}"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, organization),
    ]

    if country:
        subject_attrs.append(x509.NameAttribute(NameOID.COUNTRY_NAME, country))
    if state:
        subject_attrs.append(x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, state))
    if locality:
        subject_attrs.append(x509.NameAttribute(NameOID.LOCALITY_NAME, locality))

    subject = x509.Name(subject_attrs)

    # Build and sign CSR
    csr = x509.CertificateSigningRequestBuilder().subject_name(
        subject
    ).sign(private_key, hashes.SHA256(), backend=default_backend())

    return csr


def save_private_key(
    private_key: rsa.RSAPrivateKey,
    path: Path,
    password: Optional[bytes] = None
) -> None:
    """
    Save private key to file.

    Args:
        private_key: RSA private key
        path: File path to save to
        password: Optional encryption password
    """
    encryption = serialization.NoEncryption()
    if password:
        encryption = serialization.BestAvailableEncryption(password)

    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=encryption
    )

    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    # Write with restrictive permissions
    with open(path, 'wb') as f:
        f.write(pem)

    # Set permissions to 600 (owner read/write only)
    os.chmod(path, 0o600)


def load_private_key(
    path: Path,
    password: Optional[bytes] = None
) -> rsa.RSAPrivateKey:
    """
    Load private key from file.

    Args:
        path: File path to load from
        password: Optional decryption password

    Returns:
        RSA private key

    Raises:
        CertificateError: If key cannot be loaded
    """
    try:
        with open(path, 'rb') as f:
            pem_data = f.read()

        private_key = serialization.load_pem_private_key(
            pem_data,
            password=password,
            backend=default_backend()
        )

        if not isinstance(private_key, rsa.RSAPrivateKey):
            raise CertificateError("Key is not an RSA private key")

        return private_key

    except FileNotFoundError:
        raise CertificateError(f"Private key file not found: {path}")
    except Exception as e:
        raise CertificateError(f"Failed to load private key: {e}")


def save_certificate(cert_pem: str, path: Path) -> None:
    """
    Save certificate to file.

    Args:
        cert_pem: Certificate in PEM format
        path: File path to save to
    """
    # Ensure directory exists
    path.parent.mkdir(parents=True, exist_ok=True)

    with open(path, 'w') as f:
        f.write(cert_pem)

    # Set permissions to 644 (world-readable)
    os.chmod(path, 0o644)


def load_certificate(path: Path) -> x509.Certificate:
    """
    Load certificate from file.

    Args:
        path: File path to load from

    Returns:
        X.509 certificate

    Raises:
        CertificateError: If certificate cannot be loaded
    """
    try:
        with open(path, 'rb') as f:
            pem_data = f.read()

        cert = x509.load_pem_x509_certificate(pem_data, backend=default_backend())
        return cert

    except FileNotFoundError:
        raise CertificateError(f"Certificate file not found: {path}")
    except Exception as e:
        raise CertificateError(f"Failed to load certificate: {e}")


def save_ca_chain(ca_chain_pem: str, path: Path) -> None:
    """
    Save CA chain to file.

    Args:
        ca_chain_pem: CA chain in PEM format
        path: File path to save to
    """
    save_certificate(ca_chain_pem, path)


def check_certificate_expiry(
    cert: x509.Certificate,
    warn_days: int = 30
) -> Tuple[bool, Optional[datetime], Optional[int]]:
    """
    Check if certificate is expiring soon.

    Args:
        cert: X.509 certificate
        warn_days: Days before expiry to warn (default 30)

    Returns:
        Tuple of (needs_renewal, expiry_date, days_remaining)
        - needs_renewal: True if cert expires within warn_days
        - expiry_date: Certificate expiry timestamp
        - days_remaining: Days until expiry (None if expired)
    """
    now = datetime.now(timezone.utc)
    expiry = cert.not_valid_after_utc

    days_remaining = (expiry - now).days

    if days_remaining < 0:
        # Certificate has expired
        return True, expiry, None

    needs_renewal = days_remaining <= warn_days

    return needs_renewal, expiry, days_remaining


def extract_device_id_from_cert(cert: x509.Certificate) -> Optional[str]:
    """
    Extract device_id from certificate Common Name.

    Args:
        cert: X.509 certificate

    Returns:
        Device ID or None if not found

    The device ID is expected in the CN as "device:<device_id>"
    """
    cn_attrs = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    if not cn_attrs:
        return None

    cn_value = cn_attrs[0].value

    if cn_value.startswith("device:"):
        return cn_value[7:]  # Remove "device:" prefix

    return cn_value  # Return as-is if no prefix


def csr_to_pem(csr: x509.CertificateSigningRequest) -> str:
    """
    Convert CSR to PEM string.

    Args:
        csr: Certificate Signing Request

    Returns:
        PEM-encoded CSR string
    """
    return csr.public_bytes(serialization.Encoding.PEM).decode('utf-8')


class CertificateManager:
    """
    Manages device certificates and keys.

    Handles certificate lifecycle: generation, storage, renewal checks.
    """

    def __init__(
        self,
        cert_dir: Path,
        device_id: str,
        key_password: Optional[str] = None
    ):
        """
        Initialize certificate manager.

        Args:
            cert_dir: Directory for certificate storage
            device_id: Device identifier
            key_password: Optional password for key encryption
        """
        self.cert_dir = Path(cert_dir)
        self.device_id = device_id
        self.key_password = key_password.encode() if key_password else None

        # File paths
        self.key_path = self.cert_dir / "device.key"
        self.cert_path = self.cert_dir / "device.crt"
        self.ca_chain_path = self.cert_dir / "ca-chain.crt"

    def generate_key_and_csr(
        self,
        organization: str = "CabinMonitor"
    ) -> Tuple[rsa.RSAPrivateKey, str]:
        """
        Generate new private key and CSR.

        Args:
            organization: Organization name for CSR

        Returns:
            Tuple of (private_key, csr_pem)
        """
        # Generate private key
        private_key = generate_private_key(key_size=2048)

        # Generate CSR
        csr = generate_csr(
            device_id=self.device_id,
            private_key=private_key,
            organization=organization
        )

        csr_pem = csr_to_pem(csr)

        return private_key, csr_pem

    def save_enrollment_materials(
        self,
        private_key: rsa.RSAPrivateKey,
        device_cert_pem: str,
        ca_chain_pem: str
    ) -> None:
        """
        Save enrollment materials to disk.

        Args:
            private_key: Device private key
            device_cert_pem: Device certificate (PEM)
            ca_chain_pem: CA chain (PEM)
        """
        save_private_key(private_key, self.key_path, self.key_password)
        save_certificate(device_cert_pem, self.cert_path)
        save_ca_chain(ca_chain_pem, self.ca_chain_path)

    def has_valid_certificate(self) -> bool:
        """
        Check if valid certificate materials exist.

        Returns:
            True if key, cert, and CA chain exist
        """
        return (
            self.key_path.exists() and
            self.cert_path.exists() and
            self.ca_chain_path.exists()
        )

    def load_certificate(self) -> x509.Certificate:
        """
        Load device certificate.

        Returns:
            X.509 certificate

        Raises:
            CertificateError: If certificate cannot be loaded
        """
        return load_certificate(self.cert_path)

    def needs_renewal(self, warn_days: int = 30) -> bool:
        """
        Check if certificate needs renewal.

        Args:
            warn_days: Days before expiry to renew (default 30)

        Returns:
            True if renewal is needed

        Raises:
            CertificateError: If certificate cannot be checked
        """
        if not self.has_valid_certificate():
            return True

        try:
            cert = self.load_certificate()
            needs_renewal, _, _ = check_certificate_expiry(cert, warn_days)
            return needs_renewal
        except CertificateError:
            return True

    def get_cert_paths(self) -> Tuple[Path, Path, Path]:
        """
        Get certificate file paths.

        Returns:
            Tuple of (cert_path, key_path, ca_chain_path)
        """
        return self.cert_path, self.key_path, self.ca_chain_path
