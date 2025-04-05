# Fabric CA Enrollment Proxy with ServiceNow Validation & API Key Auth

## Purpose

This application acts as a secure proxy gateway for both registering '/proxy/register' and enrolling '/proxy/enroll' identities with a Hyperledger Fabric CA. It enhances security and auditability by:

1.  **Requiring client authentication** via a mandatory `x-api-key` header.
2.  Accepting enrollment requests only via its single endpoint (`POST /proxy/enroll`).
3.  Requiring a `RequestId` query parameter corresponding to a ServiceNow ticket/issue number.
4.  **Validating** that the ServiceNow ticket exists and is in a pre-configured "Approved" state before forwarding the request.
5.  Passing valid enrollment requests (including required HTTP Basic Authentication and JSON body) to the configured Fabric CA `/enroll` endpoint.
6.  Returning the Fabric CA's response directly to the original client.
7.  Logging validation checks and proxy actions for auditing.

## Features

* Provides an endpoint for registration: `POST /proxy/register`
* Provides an endpoint: `POST /proxy/enroll`
* Requires client authentication via `x-api-key` header.
* Mandatory `RequestId` query parameter for ServiceNow ticket association.
* Integration with ServiceNow Table API for request validation based on ticket status.
* Secure forwarding of HTTP Basic Authentication and JSON body to Fabric CA.
* Configurable via environment variables.
* Basic logging for request tracking and debugging.

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

### Using the `/proxy/register` Endpoint

This endpoint allows authorized clients to register new identities (users, peers, etc.) with the Fabric CA.

**Request:**

* **Method:** `POST`
* **URL:** `/proxy/register?RequestId=YOUR_SERVICENOW_TICKET`
* **Headers:**
    * `x-api-key`: Your valid API key for authenticating to *this proxy*.
    * `Authorization`: **CRITICAL:** HTTP Basic Authentication credentials for an existing identity on the Fabric CA that has **registrar privileges** (e.g., `hf.Registrar` attribute). The format is `Basic base64(registrar_enrollment_id:registrar_enrollment_secret)`. **This is NOT the ID/secret of the user being registered.**
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

**Response:**

* **Success (2xx):** A JSON response from the Fabric CA, typically including the generated secret if one wasn't provided in the request:
    ```json
    {
      "secret": "generatedPasswordOrProvidedPassword"
    }
    ```
* **Proxy/Validation Error (4xx):** JSON error indicating missing API key (401), invalid/unapproved `RequestId` (403), missing `Authorization` or bad body (400).
* **CA Error (4xx/5xx forwarded):** JSON error from the Fabric CA indicating issues like the registrar not having permission (401 from CA), duplicate ID (e.g., 409 from CA), bad request data (e.g., 400 from CA), or internal CA errors.
* **Proxy Downstream Error (5xx):** JSON error indicating the proxy couldn't reach the CA (502, 504).

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

## Testing

Use `curl` or a similar tool.

### Testing /proxy/register

# --- Prepare Registrar Credentials ---
# Replace with YOUR registrar's enrollment ID and secret
REGISTRAR_ID="admin"
REGISTRAR_SECRET="adminpw"
REGISTRAR_AUTH=$(echo -n "${REGISTRAR_ID}:${REGISTRAR_SECRET}" | base64)

# --- Prepare Registration Body ---
# Create register_request.json
cat << EOF > register_request.json
{
  "id": "testUserFromProxy",
  "type": "client",
  "affiliation": "org1",
  "max_enrollments": 2
}
EOF

# --- Run Tests ---

# Successful Registration (using registrar auth)
curl -X POST \
  "http://localhost:5002/proxy/register?RequestId=TICKET-APPROVED-FOR-REG" \
  -H "x-api-key: ${PROXY_KEY}" \
  -H "Authorization: Basic ${REGISTRAR_AUTH}" \
  -H "Content-Type: application/json" \
  -d @register_request.json \
  -v

# Registration Attempt with Non-Registrar Credentials (Expect error from CA)
# Use ENCODED_AUTH from the /enroll example (non-registrar)
curl -X POST \
  "http://localhost:5002/proxy/register?RequestId=TICKET-APPROVED-FOR-REG" \
  -H "x-api-key: ${PROXY_KEY}" \
  -H "Authorization: Basic ${ENCODED_AUTH}" \
  -H "Content-Type: application/json" \
  -d @register_request.json \
  -v

# Registration Attempt with Invalid RequestId
curl -X POST \
  "http://localhost:5002/proxy/register?RequestId=TICKET-PENDING" \
  -H "x-api-key: ${PROXY_KEY}" \
  -H "Authorization: Basic ${REGISTRAR_AUTH}" \
  -H "Content-Type: application/json" \
  -d @register_request.json \
  -v

# Registration Attempt with Invalid Proxy API Key
curl -X POST \
  "http://localhost:5002/proxy/register?RequestId=TICKET-APPROVED-FOR-REG" \
  -H "x-api-key: INVALID-KEY" \
  -H "Authorization: Basic ${REGISTRAR_AUTH}" \
  -H "Content-Type: application/json" \
  -d @register_request.json \
  -v

1.  **Prepare:**
    * Set your valid proxy API key: `PROXY_KEY="your-key-from-PROXY_API_KEYS"`
    * Generate Fabric CA HTTP Basic Auth credentials:
        ```bash
        # Replace with your actual enrollment ID and secret for Fabric CA
        ENROLL_ID="your_fabric_enroll_id"
        ENROLL_SECRET="your_fabric_enroll_secret"
        ENCODED_AUTH=$(echo -n "${ENROLL_ID}:${ENROLL_SECRET}" | base64)
        ```
    * Create a sample enrollment request body file (`enroll_request.json`):
        ```json
        {
          "certificate_request": "-----BEGIN CERTIFICATE REQUEST-----\nMIIC...your_actual_csr_content...=\n-----END CERTIFICATE REQUEST-----\n",
          "profile": "tls",
          "caname": "ca-org1"
        }
        ```

2.  **Run Tests:** (Replace `TICKET-APPROVED` with a valid, approved ticket number from your ServiceNow instance, and `TICKET-PENDING` with one that is not approved).

    * **Successful Request:**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll?RequestId=TICKET-APPROVED" \
          -H "x-api-key: ${PROXY_KEY}" \
          -H "Authorization: Basic ${ENCODED_AUTH}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
        ```
    * **Invalid/Unapproved RequestId (ServiceNow check fails):**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll?RequestId=TICKET-PENDING" \
          -H "x-api-key: ${PROXY_KEY}" \
          -H "Authorization: Basic ${ENCODED_AUTH}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
        ```
    * **Missing RequestId:**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll" \
          -H "x-api-key: ${PROXY_KEY}" \
          -H "Authorization: Basic ${ENCODED_AUTH}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
        ```
    * **Missing `x-api-key` Header:**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll?RequestId=TICKET-APPROVED" \
          -H "Authorization: Basic ${ENCODED_AUTH}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
        ```
    * **Invalid `x-api-key` Header:**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll?RequestId=TICKET-APPROVED" \
          -H "x-api-key: INVALID-KEY-12345" \
          -H "Authorization: Basic ${ENCODED_AUTH}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
        ```
    * **Missing Fabric CA `Authorization` Header:**
        ```bash
        curl -X POST \
          "http://localhost:5002/proxy/enroll?RequestId=TICKET-APPROVED" \
          -H "x-api-key: ${PROXY_KEY}" \
          -H "Content-Type: application/json" \
          -d @enroll_request.json \
          -v
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
