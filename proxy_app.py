import os
import requests
import base64
from flask import Flask, request, jsonify, make_response
import logging
import sys
import traceback # Import traceback for detailed error logging

# --- Basic Logging Setup ---
# Configure logging to output to stdout, suitable for containers/systemd
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    stream=sys.stdout # Explicitly direct logs to standard output
)
# Add a specific logger for this app
logger = logging.getLogger('FabricCaProxy')

# --- Configuration from Environment Variables ---
logger.info("Loading configuration from environment variables...")

# Proxy Security Configuration
PROXY_API_KEYS_STR = os.environ.get("PROXY_API_KEYS") # Comma-separated list
if not PROXY_API_KEYS_STR:
    logger.critical("FATAL ERROR: PROXY_API_KEYS environment variable not set. Proxy cannot operate securely.")
    sys.exit(1) # Exit if critical config is missing
# Store valid keys in a set for efficient lookup, removing any empty strings from split
VALID_PROXY_API_KEYS = set(key.strip() for key in PROXY_API_KEYS_STR.split(',') if key.strip()) # Use strip()
if not VALID_PROXY_API_KEYS:
    logger.critical("FATAL ERROR: PROXY_API_KEYS environment variable is set but contains no valid keys after splitting.")
    sys.exit(1)
logger.info(f"Loaded {len(VALID_PROXY_API_KEYS)} valid proxy API key(s).")

# Fabric CA Configuration
FABRIC_CA_SERVER_URL = os.environ.get("FABRIC_CA_SERVER_URL")
if not FABRIC_CA_SERVER_URL:
    logger.critical("FATAL ERROR: FABRIC_CA_SERVER_URL environment variable not set.")
    sys.exit(1)
FABRIC_CA_ENROLL_ENDPOINT = f"{FABRIC_CA_SERVER_URL.rstrip('/')}/enroll" # Ensure no double slash

# ServiceNow Configuration
SN_INSTANCE = os.environ.get("SERVICENOW_INSTANCE")
SN_TABLE = os.environ.get("SERVICENOW_TABLE")
SN_USER = os.environ.get("SERVICENOW_USER")
SN_PASSWORD = os.environ.get("SERVICENOW_PASSWORD")
# Field in ServiceNow matching the RequestId (e.g., 'number', 'sys_id'). Defaults to 'number'.
SN_ID_FIELD = os.environ.get("SERVICENOW_ID_FIELD", "number")
# Field in ServiceNow indicating approval status (e.g., 'state', 'approval', 'u_approval_status')
SN_APPROVAL_FIELD = os.environ.get("SERVICENOW_APPROVAL_FIELD")
# Exact value in SN_APPROVAL_FIELD indicating "Approved" (e.g., 'Approved', 'complete', '6', '2')
SN_APPROVAL_VALUE = os.environ.get("SERVICENOW_APPROVAL_VALUE")

SN_CONFIG_COMPLETE = all([SN_INSTANCE, SN_TABLE, SN_USER, SN_PASSWORD, SN_APPROVAL_FIELD, SN_APPROVAL_VALUE])
if not SN_CONFIG_COMPLETE:
    logger.critical("FATAL ERROR: ServiceNow validation configuration is incomplete. "
                     "Check SERVICENOW_INSTANCE, _TABLE, _USER, _PASSWORD, _APPROVAL_FIELD, _APPROVAL_VALUE.")
    sys.exit(1)
logger.info(f"ServiceNow config loaded: Instance={SN_INSTANCE}, Table={SN_TABLE}, User={SN_USER}, ID Field={SN_ID_FIELD}, Approval Field={SN_APPROVAL_FIELD}, Approved Value={SN_APPROVAL_VALUE}")

# Optional: Application Port and Debug Mode
APP_PORT = int(os.environ.get("PORT", 5002))
# Use FLASK_DEBUG for consistency with Flask's own environment variable
FLASK_DEBUG_MODE = os.environ.get("FLASK_DEBUG", "False").lower() in ["true", "1", "t"]

# --- Flask App Setup ---
app = Flask(__name__)

# --- ServiceNow Validation Function ---
def validate_ticket_request(request_id: str) -> bool:
    """
    Checks if a ServiceNow ticket/request exists with the given ID
    and is in the configured 'Approved' state using the Table API.

    Args:
        request_id: The ticket ID string (e.g., INC0010001) received by the proxy.

    Returns:
        True if the ticket is found and approved, False otherwise.
    """
    logger.info(f"Validating ServiceNow request: ID={request_id}, Table={SN_TABLE}, Field={SN_ID_FIELD}, "
                 f"Approval Condition: {SN_APPROVAL_FIELD} == '{SN_APPROVAL_VALUE}'")

    # Construct ServiceNow API Request
    api_url = f"https://{SN_INSTANCE}/api/now/table/{SN_TABLE}"
    query = f"{SN_ID_FIELD}={request_id}^{SN_APPROVAL_FIELD}={SN_APPROVAL_VALUE}"
    params = {
        "sysparm_query": query,
        "sysparm_limit": "1",
        "sysparm_fields": f"sys_id,{SN_ID_FIELD},{SN_APPROVAL_FIELD}" # Request only necessary fields
    }
    headers = {"Accept": "application/json"}
    auth = (SN_USER, SN_PASSWORD) # Basic Auth

    # Make API Call
    try:
        response = requests.get(
            api_url,
            params=params,
            headers=headers,
            auth=auth,
            timeout=10 # Timeout for the API call (seconds)
        )
        logger.info(f"ServiceNow API response status for {request_id}: {response.status_code}")

        if response.status_code == 200:
            response_data = response.json()
            if response_data.get("result") and len(response_data["result"]) > 0:
                # Record found matching the ID and Approved state
                logger.info(f"Validation SUCCESS: ServiceNow record found for {request_id} with status '{SN_APPROVAL_VALUE}'.")
                return True
            else:
                # No record found matching the criteria
                logger.warning(f"Validation FAILED: No ServiceNow record found for {request_id} with status '{SN_APPROVAL_VALUE}'. Query: {query}")
                return False
        else:
            # Handle ServiceNow API errors (auth failure, table not found, etc.)
            error_details = response.text # Log raw text for debugging
            logger.error(f"Validation FAILED: ServiceNow API returned status {response.status_code} for {request_id}. Response snippet: {error_details[:200]}") # Log snippet
            return False

    except requests.exceptions.Timeout:
        logger.error(f"Validation FAILED: Timeout connecting to ServiceNow API for {request_id}.")
        return False
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Validation FAILED: Connection error to ServiceNow API for {request_id}: {e}")
        return False
    except requests.exceptions.RequestException as e:
        logger.error(f"Validation FAILED: Error during ServiceNow API request for {request_id}: {e}")
        return False
    except Exception as e: # Catch potential JSON parsing errors or other issues
        logger.error(f"Validation FAILED: Unexpected error during ServiceNow validation for {request_id}: {e}", exc_info=True) # Log traceback
        return False

# --- Proxy Enrollment Endpoint ---
@app.route('/proxy/enroll', methods=['POST'])
def proxy_enroll():
    """
    Receives Fabric CA enrollment requests, validates Proxy API Key, validates
    RequestId against ServiceNow, and proxies valid requests to the Fabric CA /enroll endpoint.
    """
    client_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    logger.info(f"--- New Request --- Client: {client_ip}, Method: {request.method}, URL: {request.url}")
    logger.debug(f"Incoming Query Params: {request.args}") # Use debug for less critical info

    # --- 0. Validate Proxy API Key ---
    provided_api_key = request.headers.get('x-api-key')
    if not provided_api_key or provided_api_key not in VALID_PROXY_API_KEYS:
        logger.warning(f"Unauthorized (Client: {client_ip}): Missing or invalid 'x-api-key' header.")
        # Provide a generic error message, don't reveal if key was present but wrong
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "Unauthorized: Missing or invalid API key."}],
            "messages": [], "result": None
        }), 401 # Unauthorized - Authentication to the proxy itself failed

    logger.info(f"Proxy API Key validated successfully for client {client_ip}.")

    # --- 1. Extract RequestId & Validate via ServiceNow ---
    request_id = request.args.get('RequestId')
    if not request_id:
        logger.warning(f"Validation Error (Client: {client_ip}): 'RequestId' query parameter is missing.")
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "Missing 'RequestId' query parameter."}],
            "messages": [], "result": None
        }), 400 # Bad Request - Client request is malformed

    if not validate_ticket_request(request_id):
        # Reason logged inside validate_ticket_request
        logger.warning(f"Validation Failed (Client: {client_ip}): RequestId '{request_id}' not approved or invalid via ServiceNow.")
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": f"RequestId '{request_id}' is not approved or invalid."}],
            "messages": [], "result": None
        }), 403 # Forbidden - User is authenticated to proxy, but request is forbidden by business logic (ServiceNow state)

    logger.info(f"RequestId '{request_id}' validated successfully via ServiceNow. Proceeding to proxy.")

    # --- 2. Extract Body and Headers for Downstream ---
    try:
        downstream_body = request.get_data()
        if not downstream_body: raise ValueError("Request body is empty")
        if not request.is_json: raise ValueError("Request Content-Type must be application/json")
        # Try parsing JSON to catch errors early, but send raw bytes
        request.get_json(silent=True) # Use silent=True if we just want to validate format
    except Exception as e:
        logger.error(f"Error reading/validating request body (Client: {client_ip}, RequestId: {request_id}): {e}")
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": f"Invalid or missing JSON request body: {e}"}],
            "messages": [], "result": None
        }), 400 # Bad Request - Body is malformed

    forward_headers = {}
    # This is the Authorization header for the downstream Fabric CA
    auth_header = request.headers.get('Authorization')
    content_type_header = request.headers.get('Content-Type')

    if not auth_header:
        logger.error(f"Auth Error (Client: {client_ip}, RequestId: {request_id}): Missing 'Authorization' header for downstream CA.")
        # 400 Bad Request seems appropriate because the client request is missing a component
        # needed for the intended downstream operation, even if authenticated to the proxy.
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "Missing Authorization header for CA enrollment."}],
            "messages": [], "result": None
        }), 400

    forward_headers['Authorization'] = auth_header
    if content_type_header: forward_headers['Content-Type'] = content_type_header
    # Forward 'Accept' header if client sent it
    if 'Accept' in request.headers: forward_headers['Accept'] = request.headers['Accept']

    logger.info(f"Proxying RequestId '{request_id}' to Downstream URL: {FABRIC_CA_ENROLL_ENDPOINT}")
    logger.debug(f"Forwarding Headers: {list(forward_headers.keys())}") # Log only header keys for security

    # --- 3. Make Downstream Fabric CA Call ---
    try:
        response = requests.post(
            FABRIC_CA_ENROLL_ENDPOINT,
            headers=forward_headers,
            data=downstream_body, # Send raw body bytes
            timeout=20 # Slightly longer timeout for CA operations may be needed
        )
        logger.info(f"Downstream CA Response Status for RequestId '{request_id}': {response.status_code}")

        # --- 4. Return Downstream Response ---
        proxy_response = make_response(response.content, response.status_code)
        # Forward relevant headers from CA response (especially Content-Type)
        for header in ['Content-Type', 'Content-Length', 'Date']:
             if header in response.headers:
                  proxy_response.headers[header] = response.headers[header]
        # Add custom header for audit trail
        proxy_response.headers['X-Proxy-Audit-RequestId'] = request_id
        return proxy_response

    except requests.exceptions.Timeout:
        logger.error(f"Downstream Error (RequestId: {request_id}): Fabric CA timed out.")
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "Downstream Fabric CA service timeout."}],
            "messages": [], "result": None
        }), 504 # Gateway Timeout
    except requests.exceptions.ConnectionError as e:
        logger.error(f"Downstream Error (RequestId: {request_id}): Could not connect to Fabric CA: {e}")
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "Downstream Fabric CA service connection error."}],
            "messages": [], "result": None
        }), 502 # Bad Gateway
    except requests.exceptions.RequestException as e:
        logger.error(f"Downstream Error (RequestId: {request_id}): Fabric CA request failed: {e}")
        error_message = f"Proxy error during request to Fabric CA: {e}"
        # Try to include downstream response info if available
        if e.response is not None:
            # Avoid logging potentially large response bodies in production logs
            error_message += f" Downstream Status: {e.response.status_code}. Downstream Response Snippet: {e.response.text[:200]}"
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": error_message}],
            "messages": [], "result": None
        }), 502 # Bad Gateway
    except Exception as e: # Catch-all for unexpected errors
        logger.error(f"Unexpected Proxy Error (RequestId: {request_id}): {e}", exc_info=True)
        # Log the full traceback for unexpected errors
        detailed_error = traceback.format_exc()
        logger.error(detailed_error)
        return jsonify({
            "success": False, "errors": [{"code": 0, "message": "An unexpected error occurred in the proxy."}],
            "messages": [], "result": None
        }), 500 # Internal Server Error


# --- Run the App ---
if __name__ == '__main__':
    # Disable Werkzeug's default request logging if FLASK_DEBUG is false, rely on our logger
    if not FLASK_DEBUG_MODE:
        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.setLevel(logging.WARNING)

    logger.info(f"Starting Fabric CA Enrollment Proxy on 0.0.0.0:{APP_PORT} with FLASK_DEBUG={FLASK_DEBUG_MODE}")
    # For production, use a WSGI server like Gunicorn (see documentation)
    # The host '0.0.0.0' makes the server accessible externally (important for Docker/deployment)
    app.run(host='0.0.0.0', port=APP_PORT, debug=FLASK_DEBUG_MODE)
