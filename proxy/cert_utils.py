"""Certificate utilities for SSL bumping proxy."""

import os
import datetime
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


class CertificateAuthority:
    """Manages CA certificate and generates server certificates on demand."""

    def __init__(self, ca_cert_path="ca/ca.crt", ca_key_path="ca/ca.key"):
        self.ca_cert_path = ca_cert_path
        self.ca_key_path = ca_key_path
        self.ca_cert = None
        self.ca_key = None
        self._cert_cache = {}

        # Ensure the 'ca' directory exists
        ca_dir = os.path.dirname(self.ca_cert_path)
        if ca_dir and not os.path.exists(ca_dir):
            os.makedirs(ca_dir, exist_ok=True)

        if os.path.exists(ca_cert_path) and os.path.exists(ca_key_path):
            self._load_ca()
        else:
            self._generate_ca()

    def _generate_ca(self):
        """Generate a new CA certificate and private key."""
        # Remove existing CA certificate and key if they exist
        if os.path.exists(self.ca_cert_path):
            os.remove(self.ca_cert_path)
        if os.path.exists(self.ca_key_path):
            os.remove(self.ca_key_path)

        # Generate private key
        self.ca_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Generate certificate
        subject = issuer = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy CA"),
                x509.NameAttribute(NameOID.COMMON_NAME, "Proxy CA Root"),
            ]
        )

        self.ca_cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(issuer)
            .public_key(self.ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))
            .add_extension(
                x509.BasicConstraints(ca=True, path_length=None),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(
                    self.ca_key.public_key()
                ),
                critical=False,
            )
            .sign(self.ca_key, hashes.SHA256(), backend=default_backend())
        )

        # Save CA certificate and key
        with open(self.ca_cert_path, "wb") as f:
            f.write(self.ca_cert.public_bytes(serialization.Encoding.PEM))

        with open(self.ca_key_path, "wb") as f:
            f.write(
                self.ca_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption(),
                )
            )

        print(f"Generated new CA certificate: {self.ca_cert_path}")
        print(f"Generated new CA private key: {self.ca_key_path}")
        print("Add ca.crt to your client's trusted certificates!")

    def _load_ca(self):
        """Load existing CA certificate and key from files."""
        with open(self.ca_cert_path, "rb") as f:
            self.ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())

        with open(self.ca_key_path, "rb") as f:
            self.ca_key = serialization.load_pem_private_key(
                f.read(), password=None, backend=default_backend()
            )

        print(f"Loaded CA certificate from: {self.ca_cert_path}")

    def generate_server_cert(self, hostname):
        """Generate a server certificate for the given hostname."""
        if hostname in self._cert_cache:
            return self._cert_cache[hostname]

        # Generate private key for server
        server_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        # Generate certificate
        subject = x509.Name(
            [
                x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "CA"),
                x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Proxy Server"),
                x509.NameAttribute(NameOID.COMMON_NAME, hostname),
            ]
        )

        # Create certificate builder
        builder = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(self.ca_cert.issuer)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow())
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))
        )

        # Add SAN extension
        san_list = [x509.DNSName(hostname)]
        if hostname != "localhost" and not hostname.startswith("*."):
            san_list.append(x509.DNSName(f"*.{hostname}"))

        builder = builder.add_extension(
            x509.SubjectAlternativeName(san_list),
            critical=False,
        )

        # Sign with CA key
        server_cert = builder.sign(
            self.ca_key, hashes.SHA256(), backend=default_backend()
        )

        # Cache the certificate and key
        self._cert_cache[hostname] = (server_cert, server_key)

        return server_cert, server_key

    def get_cert_key_paths(self, hostname):
        """Get certificate and key as PEM bytes for a hostname."""
        cert, key = self.generate_server_cert(hostname)

        cert_pem = cert.public_bytes(serialization.Encoding.PEM)
        key_pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )

        return cert_pem, key_pem
