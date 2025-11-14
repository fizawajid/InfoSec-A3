"""
Generate client and server certificates signed by the Root CA
Usage: python gen_cert.py <client|server> <common_name>
Example: python gen_cert.py server localhost
         python gen_cert.py client alice
"""
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtensionOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
import datetime
import sys
import os

def load_ca():
    """Load CA private key and certificate"""
    print("[CERT] Loading CA credentials...")
    
    # Load CA private key
    with open("certs/ca_private.key", "rb") as f:
        ca_private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
            backend=default_backend()
        )
    
    # Load CA certificate
    with open("certs/ca_cert.pem", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    return ca_private_key, ca_cert

def generate_certificate(entity_type, common_name):
    """
    Generate and sign a certificate for client or server
    
    Args:
        entity_type: "client" or "server"
        common_name: hostname for server, username for client
    """
    print(f"[CERT] Generating {entity_type} certificate for '{common_name}'...")
    
    # Load CA credentials
    ca_private_key, ca_cert = load_ca()
    
    # Generate private key for this entity
    print(f"[CERT] Generating RSA private key...")
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Create subject
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "Punjab"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "Rawalpindi"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, f"FAST-NUCES {entity_type.capitalize()}"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    # Build certificate
    print(f"[CERT] Creating certificate signed by CA...")
    builder = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(ca_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=365))  # 1 year
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(private_key.public_key()),
            critical=False,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_private_key.public_key()),
            critical=False,
        )
    )
    
    # Add appropriate key usage based on entity type
    if entity_type == "server":
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH]),
            critical=False,
        ).add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False,
        )
    else:  # client
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                key_encipherment=True,
                key_cert_sign=False,
                crl_sign=False,
                content_commitment=False,
                data_encipherment=False,
                key_agreement=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        ).add_extension(
            x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]),
            critical=False,
        )
    
    # Sign the certificate
    cert = builder.sign(ca_private_key, hashes.SHA256(), default_backend())
    
    # Save private key
    key_filename = f"certs/{entity_type}_private.key"
    print(f"[CERT] Saving private key to {key_filename}")
    with open(key_filename, "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            )
        )
    
    # Save certificate
    cert_filename = f"certs/{entity_type}_cert.pem"
    print(f"[CERT] Saving certificate to {cert_filename}")
    with open(cert_filename, "wb") as f:
        f.write(cert.public_bytes(serialization.Encoding.PEM))
    
    print(f"[CERT] ✓ {entity_type.capitalize()} certificate generated successfully!")
    print(f"[CERT] Files created:")
    print(f"     - {key_filename}")
    print(f"     - {cert_filename}")
    
    return private_key, cert

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <client|server> <common_name>")
        print("Example: python gen_cert.py server localhost")
        print("         python gen_cert.py client alice")
        sys.exit(1)
    
    entity_type = sys.argv[1].lower()
    common_name = sys.argv[2]
    
    if entity_type not in ["client", "server"]:
        print("Error: entity_type must be 'client' or 'server'")
        sys.exit(1)
    
    # Check if CA exists
    if not os.path.exists("certs/ca_private.key") or not os.path.exists("certs/ca_cert.pem"):
        print("Error: CA not found. Run gen_ca.py first!")
        sys.exit(1)
    
    generate_certificate(entity_type, common_name)
    
    # Display certificate information
    print("\n" + "="*60)
    print(f"{entity_type.capitalize()} Certificate Information:")
    print("="*60)
    os.system(f"openssl x509 -in certs/{entity_type}_cert.pem -text -noout")
