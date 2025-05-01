# Fabric CA Enrollment Proxy with ServiceNow Validation & API Key Auth

## Purpose

This example application acts as a secure proxy gateway for both registering '/proxy/register' and enrolling '/proxy/enroll' identities with a Hyperledger Fabric CA. It enhances security and auditability by:

1.  **Requiring client authentication** via a mandatory `x-api-key` header.
2.  Accepting registration requests via its endpoing (`POST /proxy/register`)
2.  Accepting enrollment requests via its endpoint (`POST /proxy/enroll`).
3.  Requiring a `RequestId` query parameter corresponding to a ServiceNow ticket/issue number.
4.  **Validating** that the ServiceNow ticket exists and is in a pre-configured "Approved" state before forwarding the request.
5.  Passing valid registration or enrollment requests (including required HTTP Basic Authentication and JSON body) to the configured Fabric CA `/register` or `/enroll` endpoint.
6.  Returning the Fabric CA's response directly to the original client.
7.  Logging validation checks and proxy actions for auditing.

## Features

* Provides an endpoint for registration: `POST /proxy/register`
* Provides an endpoint: `POST /proxy/enroll`
* Requires client authentication via `x-api-key` header.
* Mandatory `RequestId` query parameter for ServiceNow ticket association.
* Integration with ServiceNow Table API for request validation based on ticket status `currently not tested or validate`.
* Secure forwarding of HTTP Basic Authentication from header and JSON body from payload to Fabric CA.
* Configurable via environment variables.
* Basic logging for request tracking and debugging. 

## TO DO's
* Enable TLS on main proxy application
* Enable storing of key material in an HSM security modules using PKCS11

## Prerequisites

* Python 3.8+
* `pip` package installer
* Access to a running Hyperledger Fabric CA instance.
* Access to a ServiceNow instance.
* A ServiceNow service account (User ID and Password) with read permissions on the table containing the tickets/requests to be validated.
* Knowledge of your ServiceNow workflow:
    * The specific table name (e.g., `incident`, `change_request`, `sc_req_item`).
    * The field name holding the ticket identifier (`number`, `sys_id`).
    * The field name indicating approval status (`state`, `approval`).
    * The *exact* value representing the "Approved" state in that field.
* Generated API Key(s) for clients calling this proxy.

## Configuration (Environment Variables)

This application is configured entirely through environment variables. **All variables listed below are required unless otherwise noted.**

| Variable                    | Description                                                                                                           | Example                               |
| :-------------------------- | :-------------------------------------------------------------------------------------------------------------------- | :------------------------------------ |
| `PROXY_API_KEYS`            | **Required.** Comma-separated list of valid API keys that clients must send in the `x-api-key` header.                  | `key1-abc,key2-xyz,key3-123`         |
| `FABRIC_CA_SERVER_URL`      | **Required.** Base URL of the target Fabric CA server (including `http://` or `https://`).                              | `http://fabric-ca.org1.example.com:7054` |
| `SERVICENOW_INSTANCE`       | **Required.** Your ServiceNow instance hostname.                                                                    | `mycompany.service-now.com`           |
| `SERVICENOW_TABLE`          | **Required.** The ServiceNow table name containing the tickets/requests.                                            | `change_request`                      |
| `SERVICENOW_USER`           | **Required.** Username for the ServiceNow API service account.                                                       | `fabric_proxy_api`                    |
| `SERVICENOW_PASSWORD`       | **Required.** Password for the ServiceNow API service account.                                                      | `Sup3rS3cr3tP@ssw0rd`                |
| `SERVICENOW_ID_FIELD`       | (Optional) Field in ServiceNow table matching `RequestId`. **Defaults to `number`**.                                  | `number`                              |
| `SERVICENOW_APPROVAL_FIELD` | **Required.** Field in ServiceNow table indicating approval status. **CRITICAL: Must match your setup.** | `state`                               |
| `SERVICENOW_APPROVAL_VALUE` | **Required.** The exact value in `SERVICENOW_APPROVAL_FIELD` meaning "Approved". **CRITICAL: Must match setup exactly.** | `3` (e.g., if '3' means Approved)     |
| `PORT`                      | (Optional) Port the proxy application will listen on. **Defaults to `5002`**.                                         | `8080`                                |
| `FLASK_DEBUG`               | (Optional) Set to `True` or `1` to enable Flask debug mode (auto-reload, detailed errors). **Defaults to `False`**.    | `True`                                |

**IMPORTANT:** Determining the correct `SERVICENOW_APPROVAL_FIELD` and `SERVICENOW_APPROVAL_VALUE` is essential. Inspect the relevant table and workflow configuration in your ServiceNow instance. Use strong, unique values for `PROXY_API_KEYS`.

## Local Setup & Running (Development)

1.  **Clone Repository:**
    ```bash
    git clone <your-repo-url>
    cd <your-repo-directory>
    ```

2.  **Create Virtual Environment:**
    ```bash
    python -m venv venv
    source venv/bin/activate  # Linux/macOS
    # venv\Scripts\activate    # Windows
    ```

3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

4.  **Set Environment Variables:** Create a file named `.env` (copy from `.env.example`) in the project root and fill in your configuration values:
    ```dotenv
    # .env file - DO NOT COMMIT ACTUAL SECRETS
    PROXY_API_KEYS=changeme-local-dev-key # Use a specific key for local testing
    FABRIC_CA_SERVER_URL=http://localhost:7054
    SERVICENOW_INSTANCE=yourinstance.service-now.com
    SERVICENOW_TABLE=incident
    SERVICENOW_USER=your_api_user
    SERVICENOW_PASSWORD=your_api_password
    SERVICENOW_APPROVAL_FIELD=state
    SERVICENOW_APPROVAL_VALUE=6 # Example: Check your SN instance!
    # SERVICENOW_ID_FIELD=number # Optional, defaults to number
    PORT=5002
    FLASK_DEBUG=True
    ```
    **IMPORTANT:** Do NOT commit the `.env` file to version control. Ensure `.env` is listed in your `.gitignore` file.

5.  **Source Environment Variables (Optional but Recommended):** Use a tool like `python-dotenv` (install with `pip install python-dotenv`) to load `.env` automatically, or source them manually in your shell. If using `python-dotenv`, you might add `from dotenv import load_dotenv; load_dotenv()` at the top of `proxy_app.py` (before accessing `os.environ`).

6.  **Run the Application:**
    ```bash
    # Ensure environment variables are set in your shell session if not using dotenv
    python proxy_app.py
    ```
    The proxy should now be running (e.g., on `http://0.0.0.0:5002`).

## Using the `/proxy/register` Endpoint

This endpoint allows authorized clients to register new identities (users, peers, etc.) with the Fabric CA.

### Request:

* **Method:** `POST`
* **URL:** `/proxy/register?RequestId=YOUR_SERVICENOW_TICKET`
* **Headers:**
    * `x-api-key`: Your valid API key for authenticating to *this proxy*.
    * `Authorization`: HTTP Basic Authentication credentials for an existing identity on the Fabric CA that has **registrar privileges** (e.g., `hf.Registrar` attribute) along with a EC Sha256 signature of the request.
    ### CRITICAL **The format is:**
    base64(registrar_cert).EC_sig256(METHOD+base64(uri)+base64(body)+base64(registrar_cert)) **see code for details**
    **This is NOT the ID/secret of the user being registered.**
    * `Content-Type`: `application/json`
* **Query Parameter:**
    * `RequestId`: The ServiceNow ticket number associated with this registration request (must be in the configured "Approved" state).
* **Body:** A JSON object specifying the details of the identity *to be registered*. Example:
    ```json
    {
      "id": "newUser1",
      "type": "client",
      "affiliation": "org1.department1",
      "max_enrollments": 1,
      "secret": "newUser1Password", // Optional: CA generates if omitted
      "attributes": [
        {"name": "role", "value": "auditor", "ecert": true}
      ]
    }
    ```
    *(Refer to Fabric CA documentation for all available registration fields.)*
    *Our python client correctly builds the headers and payload from provided certificate, key material and json input files*

### Response:

* **Success (2xx):** A JSON response from the Fabric CA, typically including the generated secret if one wasn't provided in the request:
    ```json
    {
      "secret": "generatedPassword Or ProvidedPassword"
    }
    ```
* **Proxy/Validation Error (4xx):** JSON error indicating missing API key (401), invalid/unapproved `RequestId` (403), missing `Authorization` or bad body (400).
* **CA Error (4xx/5xx forwarded):** JSON error from the Fabric CA indicating issues like the registrar not having permission (401 from CA), duplicate ID (e.g., 409 from CA), bad request data (e.g., 400 from CA), or internal CA errors.
* **Proxy Downstream Error (5xx):** JSON error indicating the proxy couldn't reach the CA (502, 504).

## Using the `/proxy/enroll` Endpoint

* **Method:** `POST`
* **URL:** `/proxy/enroll?RequestId=YOUR_SERVICENOW_TICKET`
* **Headers:**
    * `x-api-key`: Your valid API key for authenticating to *this proxy*
    * `Authorization`: HTTP Basic Authentication credentials for a registered entity on the Fabric CA.
    ### CRITICAL **The format is:**
    base64(registeredId:registeredSecret)
    * `Content-Type`: `application/json`
* **Query Parameter:**
    * `RequestId`: The ServiceNow ticket number associated with this enrollment request (must be in teh configured "Approved" state).
* **Body:**
    ```json
    {
      "certificate_request": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBGDCBwAIBADBeMQswCQYDVQ...=\n-----END CERTIFICATE REQUEST-----\n",
      "profile": "tls",
      "caname": "my-org-ca"
    }
    ```
    *(Refer to Fabric CA documentation for all available enrollment fields.)*
    *Our python client correctly builds the headers and payload from provided inpute*

### Response:

* **Success (2xx):**
    ```json
    {
      "result":
      {
        "Cert":"Base64 Encoded Enrollment Cert",
        "ServerInfo":
        {
          "CAChain": "Base65 Encoded CA Cahin"
        }
      }
    }
    ```
* **Proxy/Validation Error (4xx):** JSON error indicating missing API key (401), invalid/unapproved `RequestId` (403), missing `Authorization` or bad body (400).
* **CA Error (4xx/5xx forwarded):** JSON error from the Fabric CA indicating issues like the enrollemnt ID not having permission to enroll (max enrollments reached) (401 from CA), duplicate ID (e.g., 409 from CA), bad request data (e.g., 400 from CA), or internal CA errors.
* **Proxy Downstream Error (5xx):** JSON error indicating the proxy couldn't reach the CA (502, 504).

*our python client will create the necessary key material for the enrolling client and create the CSR for the payload.  The client will save the recieved enrollment cert and ca chain into enrollment files

## Testing

Useing provided python clients.

### Testing /proxy/register


# --- Run Tests ---

# Successful Registration (using registrar auth)
```bash

```

# Registration Attempt with Non-Registrar Credentials (Expect error from CA)
# Use ENCODED_AUTH from the /enroll example (non-registrar)
```bash

```

# Registration Attempt with Invalid RequestId
```bash

```

# Registration Attempt with Invalid Proxy API Key
```bash

```

### Testing /proxy/enroll

* you can prepare the CSR content for the json content using:
      ```
        CSR_PEM_CONTENT=$(awk 'NF {printf "%s\\n", $0}' ${CSR_FILE})
      ```
      replace${CSR_FILE} with your actual CSR file location
       

# --- Run Tests ---
*(Replace `TICKET-APPROVED` with a valid, approved ticket number from your ServiceNow instance, and `TICKET-PENDING` with one that is not approved).*

# Successful Enrollment (using registered client credentials)
```bash

```

# Enrollment Attempt with invalid RequestId (ServiceNow check fails)
```bash

```

# Enrollment Attempt with missing RequestId
```bash

```

# Enrollement Attempt with missing `x-api-key` Header
```bash

```

# Enrollment Attempt with missing Authorization Header
```bash

```
    

## Deployment (Production)

Running the Flask development server (`python proxy_app.py`) is **NOT suitable for production**. Use a production-grade WSGI server like Gunicorn or uWSGI, managed by a process supervisor (like systemd), and preferably placed behind a reverse proxy (like Nginx or Apache) handling HTTPS termination.

### Option 1: Docker Deployment

1.  **Create `Dockerfile`:** (See provided Dockerfile below)
2.  **Build Docker Image:**
    ```bash
    docker build -t fabric-ca-proxy:latest .
    ```
3.  **Run Docker Container:** Pass environment variables securely (e.g., using `--env-file` pointing to a secured file, Kubernetes Secrets, or other secure methods). **Never commit secrets directly in Dockerfiles or version control.**
    ```bash
    docker run -d \
      --name fabric-proxy-container \
      -p 5002:5002 \ # Map host port 5002 to container port 5002 (adjust if needed)
      --env-file /path/to/secure/.env.prod \ # Load variables from a secured .env file
      # Or pass individually (less secure for secrets):
      # -e PROXY_API_KEYS="prod-key-1,prod-key-2" \
      # -e FABRIC_CA_SERVER_URL="[https://prod-ca.example.com:7054](https://www.google.com/search?q=https://prod-ca.example.com:7054)" \
      # -e SERVICENOW_INSTANCE="..." \
      # -e SERVICENOW_PASSWORD="..." \
      # ... other variables ...
      # -e FLASK_DEBUG=False \ # Ensure DEBUG is False for production
      # -e PORT=5002 \ # Ensure container listens on the expected port
      --restart unless-stopped \ # Optional: auto-restart policy
      fabric-ca-proxy:latest
    ```

### Option 2: Server Setup (Gunicorn + systemd on Linux)

1.  **Install Gunicorn:**
    ```bash
    # Activate your virtual environment first (if used)
    pip install gunicorn
    ```

2.  **Create systemd Service File:** Create `/etc/systemd/system/fabric-proxy.service`.
    ```ini
    [Unit]
    Description=Fabric CA Enrollment Proxy Service
    After=network.target

    [Service]
    User=your_app_user        # Replace with a dedicated non-root user
    Group=your_app_group      # Replace with the user's group
    WorkingDirectory=/path/to/your/app/directory # Replace with project root
    # Load environment variables from a file (secure this file!)
    EnvironmentFile=/etc/fabric-proxy/environment.conf
    # Set permissions on environment.conf: sudo chmod 600 /etc/fabric-proxy/environment.conf; sudo chown your_app_user:your_app_group /etc/fabric-proxy/environment.conf

    # Start Gunicorn
    # Use absolute path to gunicorn in your venv if applicable
    ExecStart=/path/to/your/venv/bin/gunicorn --workers 3 --bind unix:/run/fabric-proxy.sock -m 007 --access-logfile - --error-logfile - proxy_app:app

    Restart=on-failure # Or always

    [Install]
    WantedBy=multi-user.target
    ```
    * Replace placeholders (`your_app_user`, paths).
    * Create `/etc/fabric-proxy/environment.conf` with `VAR=VALUE` pairs (e.g., `PROXY_API_KEYS=key1,key2`). Set strict permissions.
    * Adjust `--workers` (typically 2 * CPU cores + 1). Gunicorn binds to a Unix socket (`/run/fabric-proxy.sock`) for the reverse proxy. `--access-logfile - --error-logfile -` sends logs to stdout/stderr, which systemd captures.

3.  **Enable and Start Service:**
    ```bash
    sudo systemctl daemon-reload
    sudo systemctl enable fabric-proxy
    sudo systemctl start fabric-proxy
    sudo systemctl status fabric-proxy # Check status
    sudo journalctl -u fabric-proxy -f # View logs
    ```

4.  **Configure Reverse Proxy (Nginx Example):** Create `/etc/nginx/sites-available/fabric-proxy`.
    ```nginx
    server {
        listen 443 ssl http2; # Listen on HTTPS
        listen [::]:443 ssl http2;
        server_name your-proxy-domain.com; # Replace with your domain

        # SSL Configuration (Use Let's Encrypt or your own certs)
        ssl_certificate /etc/letsencrypt/live/[your-proxy-domain.com/fullchain.pem](https://www.google.com/search?q=https://your-proxy-domain.com/fullchain.pem);
        ssl_certificate_key /etc/letsencrypt/live/[your-proxy-domain.com/privkey.pem](https://www.google.com/search?q=https://your-proxy-domain.com/privkey.pem);
        include /etc/letsencrypt/options-ssl-nginx.conf; # Recommended SSL settings
        ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem; # Diffie-Hellman params

        # Optional: Add security headers
        add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
        add_header X-Frame-Options DENY always;
        add_header X-Content-Type-Options nosniff always;
        add_header Referrer-Policy "strict-origin-when-cross-origin" always;

        location / {
            proxy_pass http://unix:/run/fabric-proxy.sock; # Match Gunicorn socket
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme; # Important for Flask if it needs to know it's HTTPS
        }

        # Optional: Deny access to hidden files
        location ~ /\. {
            deny all;
        }

        # Optional: Redirect HTTP to HTTPS
        # Add a separate server block for port 80:
        # server {
        #    listen 80;
        #    listen [::]:80;
        #    server_name your-proxy-domain.com;
        #    return 301 https://$host$request_uri;
        # }
    }
    ```
    * Replace `your-proxy-domain.com`. Configure SSL (Let's Encrypt is recommended).
    * Enable site: `sudo ln -s /etc/nginx/sites-available/fabric-proxy /etc/nginx/sites-enabled/`
    * Test Nginx config: `sudo nginx -t`
    * Reload Nginx: `sudo systemctl reload nginx`

## Security Considerations

* **Credentials:** **NEVER** hardcode passwords or API keys. Use environment variables loaded securely (e.g., from `.env` files *not* in Git, systemd `EnvironmentFile` with restricted permissions 600, Docker secrets, or a dedicated secrets management system).
* **Proxy API Keys:** The `PROXY_API_KEYS` are sensitive. Use strong, randomly generated keys. Implement a key rotation strategy (add new key, update clients, remove old key).
* **HTTPS:** **Always** run this proxy behind a reverse proxy configured with **HTTPS** in production to encrypt traffic between the client and the proxy. Use modern TLS protocols and ciphers.
* **Firewall:** Restrict network access to the server running the proxy (e.g., only allow ports 80/443) using firewall rules (`ufw`, `firewalld`, cloud provider security groups). The proxy itself only needs outbound access to ServiceNow (`*.service-now.com` on 443) and the Fabric CA (specific host/port).
* **Permissions:** Run the application process (Gunicorn/Docker container) as a non-root user with minimal privileges. Ensure file permissions are strict for configuration files containing secrets.
* **Input Validation:** The code validates the presence and format of required inputs (API Key, RequestId, JSON body, Auth header). Consider adding schema validation for the JSON body if strict structure is required.
* **Rate Limiting:** Implement rate limiting (e.g., in Nginx or using Flask extensions) to prevent brute-force attacks and resource exhaustion.
* **Logging:** Be mindful of logging sensitive data. The current code avoids logging full request bodies or sensitive headers at INFO level, but review DEBUG logs carefully if enabled. Ensure logs are stored securely and rotated.

## Starting a Defalt CA Server

here is a sample docker run to start up a fabric ca server in debug

# Example docker run command (adapt volumes, ports, env vars as needed)

# Make sure to adjust the volume path and any other specific configurations
# like CA name, bootstrap user/pass, TLS settings etc.
docker run --rm \
  --name fabric-ca-server-debug \
  -p 7054:7054 \
  -e FABRIC_CA_SERVER_HOME=/etc/hyperledger/fabric-ca-server \
  -e FABRIC_CA_SERVER_CA_NAME=my-org-ca \
  -e FABRIC_CA_SERVER_TLS_ENABLED=true \
  -v $(pwd)/fabric-ca-server-home:/etc/hyperledger/fabric-ca-server \
  hyperledger/fabric-ca:1.5.15 \
  fabric-ca-server start -b admin:adminpw --ca.name my-org-ca -d

* Registering a user with HLF CA
* First get the admin MSP
```
# --- Set Environment Variables (adjust paths and credentials as needed) ---

# Path on your HOST machine to store the enrolled admin's MSP files
export FABRIC_CA_CLIENT_HOME=$HOME/fabric-ca/admin/msp

# URL and host:port of your running Fabric CA server
export FABRIC_CA_SERVER_HOSTPORT=localhost:7054

# Bootstrap admin user credentials
export BOOTSTRAP_ADMIN_USER=admin
export BOOTSTRAP_ADMIN_PASS=adminpw

# Path on your HOST machine to the CA server's TLS root certificate
# This is likely inside the volume you mounted for the server, e.g., ./fabric-ca-server-home/
export CA_TLS_CERTFILE=$(pwd)/fabric-ca-server-home/ca-cert.pem # ADJUST THIS PATH!

# --- Create directory for the admin's MSP ---
mkdir -p $FABRIC_CA_CLIENT_HOME

# --- Run the enrollment command using Docker ---
# Note: --network host allows the container to easily access localhost:7054 on your host.
# If your CA is on a different machine or Docker network, adjust accordingly.
docker run --rm \
  -v "$FABRIC_CA_CLIENT_HOME:/etc/hyperledger/fabric-ca-client/msp" \
  -v "$CA_TLS_CERTFILE:/certs/ca-cert.pem" \
  --network host \
  hyperledger/fabric-ca:1.5.15 \
  fabric-ca-client enroll \
  -u https://${BOOTSTRAP_ADMIN_USER}:${BOOTSTRAP_ADMIN_PASS}@${FABRIC_CA_SERVER_HOSTPORT} \
  -M /etc/hyperledger/fabric-ca-client/msp \
  --tls.certfiles /certs/ca-cert.pem

# --- Verification ---
# Check if the MSP files were created in your local $FABRIC_CA_CLIENT_HOME directory.
# You should see directories like 'cacerts', 'keystore', 'signcerts', etc.
echo "Check for MSP files in: $FABRIC_CA_CLIENT_HOME"
ls -l $FABRIC_CA_CLIENT_HOME
```

* Register a user I.e. appUser3
```
# --- Set Environment Variables for the New User ---
export NEW_USER_ID=appUser1
export NEW_USER_SECRET=appUser1pw
export NEW_USER_TYPE=client # Type: client, peer, orderer, auditor
# Affiliation must exist in the CA server config (e.g., org1.department1)
export NEW_USER_AFFILIATION=org1.department1 # ADJUST AS NEEDED

# Other variables (FABRIC_CA_CLIENT_HOME, FABRIC_CA_SERVER_HOSTPORT, CA_TLS_CERTFILE)
# should still be set from Step 1.

# --- Run the registration command using Docker ---
docker run --rm \
  -v "$FABRIC_CA_CLIENT_HOME:/etc/hyperledger/fabric-ca-client/msp" \
  -v "$CA_TLS_CERTFILE:/certs/ca-cert.pem" \
  --network host \
  hyperledger/fabric-ca:1.5.15 \
  fabric-ca-client register \
  -u https://${FABRIC_CA_SERVER_HOSTPORT} \
  -M /etc/hyperledger/fabric-ca-client/msp \
  --id.name $NEW_USER_ID \
  --id.secret $NEW_USER_SECRET \
  --id.type $NEW_USER_TYPE \
  --id.affiliation $NEW_USER_AFFILIATION \
  # Optional: Add custom attributes
  # --id.attrs 'admin=false:ecert,department=IT:ecert' \
  --tls.certfiles /certs/ca-cert.pem

# --- Verification ---
# If successful, the command should output the password (secret) for the registered user.
# Example output: "Password: appUser1pw"
# There won't be new files created locally for registration, it just updates the CA's internal database.
```


