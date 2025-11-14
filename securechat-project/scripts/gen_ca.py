"""
Generate a self-signed Root Certificate Authority (CA)
This CA will be used to sign client and server certificates
"""
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import os

def generate_ca():
    """Generate root CA private key and self-signed certificate"""
    
    print("[CA] Generating Root Certificate Authority...")
    
    # Create certs directory if it doesn't exist
    os.makedirs('certs', exist_ok=True)
    
    # Generate private key for CA
    print("[CA] Generating RSA private key (2048 bits)...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject for CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "FAST-NUCES SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    # Build the certificate
    print("[CA] Creating self-signed certificate...")
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=3650))  # 10 years
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_cert_sign=True,
                crl_sign=True,
                key_encipherment=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .sign(private_key, hashes.SHA256(), default_backend())
    )
    
    # Save private key
    print("[CA] Saving CA private key to certs/ca_private.key")
    with open("certs/ca_private.key", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    print("[CA] Saving CA certificate to certs/ca_cert.pem")
    with open("certs/ca_cert.pem", "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print("[CA] ✓ Root CA generated successfully!")
    print("[CA] Files created:")
    print("     - certs/ca_private.key")
    print("     - certs/ca_cert.pem")
    print()
    print("[CA] WARNING: Keep ca_private.key SECRET! Never commit to Git!")
    
    return private_key, cert

if __name__ == "__main__":
    generate_ca()
    
    # Display certificate information
    print("\n" + "="*60)
    print("CA Certificate Information:")
    print("="*60)
    os.system("openssl x509 -in certs/ca_cert.pem -text -noout")
