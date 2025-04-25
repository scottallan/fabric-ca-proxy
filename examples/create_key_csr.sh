 KEY_FILE="appUser7.key"
 CSR_FILE="appUser7.csr"
 # Common Name MUST match the enrollment ID registered with the CA
 ENROLLMENT_ID="appUser7"
 # Subject details (adjust as needed)
 SUBJECT="/C=US/ST=North Carolina/O=Hyperledger/OU=org1/CN=${ENROLLMENT_ID}"
 #SUBJECT="/C=CA/ST=Ontario/L=Oshawa/O=MyOrg/OU=client/CN=${ENROLLMENT_ID}"

 # --- Generate Private Key (e.g., ECDSA P-256) ---
 openssl ecparam -name prime256v1 -genkey -noout -out ${KEY_FILE}
 echo "Private key saved to: ${KEY_FILE}"

 # --- Generate CSR ---
 # Add -addext "subjectAltName = DNS:host1.example.com,IP:192.168.1.10" if needed for TLS certs
 openssl req -new -key ${KEY_FILE} -subj "${SUBJECT}" -out ${CSR_FILE}
 echo "CSR saved to: ${CSR_FILE}"
 
 # --- Prepare CSR content for JSON payload (read and escape newlines) ---
 # Using awk for portability
 CSR_PEM_CONTENT=$(awk 'NF {printf "%s\\n", $0}' ${CSR_FILE})
 # Or using paste (GNU specific potentially)
 # CSR_PEM_CONTENT=$(paste -sd R < "${CSR_FILE}") # Replaces newline with R, then sed replaces R with \n
 # CSR_PEM_CONTENT=$(echo "$CSR_PEM_CONTENT" | sed 's/R/\\n/g')
