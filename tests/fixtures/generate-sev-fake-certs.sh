#!/bin/bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CERTS_DIR="${SCRIPT_DIR}/sev-fake-certs"

mkdir -p "${CERTS_DIR}"
cd "${CERTS_DIR}"

echo "Generating fake SEV-SNP certificate chain..."

# Generate ARK (AMD Root Key) - self-signed
openssl ecparam -name secp384r1 -genkey -noout -out ark.key
openssl req -new -x509 -key ark.key -out ark.pem -days 3650 -sha384 \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Advanced Micro Devices/OU=Engineering/CN=ARK-Milan"
echo "Created ark.pem (self-signed root)"

# Generate ASK (AMD Signing Key) - signed by ARK
openssl ecparam -name secp384r1 -genkey -noout -out ask.key
openssl req -new -key ask.key -out ask.csr \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Advanced Micro Devices/OU=Engineering/CN=SEV-Milan"
openssl x509 -req -in ask.csr -CA ark.pem -CAkey ark.key -CAcreateserial \
  -out ask.pem -days 3650 -sha384
echo "Created ask.pem (signed by ARK)"

# Create VCEK extensions config with SNP OIDs
cat > vcek_ext.cnf << 'EOF'
# SNP OID extensions for VCEK
# bootloader version
1.3.6.1.4.1.3704.1.3.1 = ASN1:INTEGER:0
# tee version
1.3.6.1.4.1.3704.1.3.2 = ASN1:INTEGER:0
# snp version
1.3.6.1.4.1.3704.1.3.3 = ASN1:INTEGER:0
# microcode version
1.3.6.1.4.1.3704.1.3.8 = ASN1:INTEGER:0
# hardware id (64 bytes of zeros)
1.3.6.1.4.1.3704.1.4 = ASN1:FORMAT:HEX,OCTETSTRING:0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
EOF

# Generate VCEK (Versioned Chip Endorsement Key) - signed by ASK
openssl ecparam -name secp384r1 -genkey -noout -out vcek.key
openssl req -new -key vcek.key -out vcek.csr \
  -subj "/C=US/ST=CA/L=Santa Clara/O=Advanced Micro Devices/OU=Engineering/CN=SEV-VCEK"
openssl x509 -req -in vcek.csr -CA ask.pem -CAkey ask.key -CAcreateserial \
  -out vcek.pem -days 3650 -sha384 -extfile vcek_ext.cnf
echo "Created vcek.pem (signed by ASK, with SNP OID extensions)"

# Clean up temporary files
rm -f ark.key ask.key vcek.key ark.srl ask.srl ask.csr vcek.csr vcek_ext.cnf

echo "Done! Fake certificates created in ${CERTS_DIR}/"
echo ""
echo "Certificate chain:"
echo "  ARK (self-signed) -> ASK -> VCEK"
