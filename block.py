import base64
import json
import time
import subprocess
import sys
import argparse
from typing import Dict, Any, Tuple, Optional
from datetime import datetime, timezone, timedelta

CURL_SUCCESS_CODE: int = 0  # Standard exit code for successful curl execution

# Timeout for verifying filter status changes.
VERIFICATION_TIMEOUT_DELTA: timedelta = timedelta(seconds=60)
# Sleep duration for polling loops (e.g., in verification and log monitoring)
POLLING_INTERVAL_DELTA: timedelta = timedelta(seconds=5)


# --- Helper function to execute curl commands ---
def execute_curl(
    method: str,
    path_with_query: str,
    auth_header: str,
    content_type_header: str,
    base_api_url: str,
    data: Optional[Dict[str, Any]] = None,
) -> Tuple[str, str, int]:
    """
    Executes a curl command and returns its stdout, stderr, and return code.
    path_with_query: The endpoint including any query parameters (e.g., "querylog?limit=10").
    """
    url: str = f"{base_api_url}/{path_with_query}"
    cmd: list[str] = [
        "curl",
        "-s",
    ]  # -s for silent mode (no progress meter or error messages)

    cmd.append("-X")
    cmd.append(method)

    cmd.append("-H")
    cmd.append(auth_header)

    if data:
        cmd.append("-H")
        cmd.append(content_type_header)
        cmd.append("-d")
        cmd.append(json.dumps(data))  # Convert Python dict to JSON string for -d

    cmd.append(url)  # Add the URL to the curl command

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        return result.stdout, result.stderr, result.returncode
    except FileNotFoundError:
        print(
            "Error: 'curl' command not found. Please ensure curl is installed and in your PATH."
        )
        sys.exit(1)
    except Exception as e:
        print(f"An unexpected error occurred while running curl: {e}")
        sys.exit(1)


# --- Argument Parsing Function ---
def parse_arguments() -> argparse.Namespace:
    """
    Parses command-line arguments for AdGuard Home configuration.
    Returns an argparse.Namespace object containing the parsed arguments.
    """
    parser = argparse.ArgumentParser(
        description="Block and unblock a specific domain in AdGuard Home based on query logs."
    )
    parser.add_argument(
        "--ip", required=True, help="AdGuard Home IP address (e.g., 192.168.1.100)"
    )
    parser.add_argument(
        "--port",
        required=True,
        type=int,
        help="AdGuard Home web interface port (e.g., 80, 443, 3000)",
    )
    parser.add_argument("--username", required=True, help="AdGuard Home username")
    parser.add_argument("--password", required=True, help="AdGuard Home password")

    # REQUIRED: The domain logic you requested
    parser.add_argument(
        "--domain",
        required=True,
        help="The domain to block. This will also block all subdomains (e.g. 'example.com' blocks 'sub.example.com').",
    )

    parser.add_argument(
        "--timeout",
        type=int,
        default=60,
        help="Timeout duration in seconds for monitoring the blocked query (default: 60)",
    )
    parser.add_argument(
        "--app",
        type=str,
        help="Path to an application to open after blocking (e.g., /Applications/Safari.app)",
    )

    return parser.parse_args()


# --- Verification Helper Function ---
def verify_filter_status(
    auth_header: str,
    content_type_header: str,
    adguard_api_url: str,
    domain: str,
    expected_reason: str,
    timeout_delta: timedelta = VERIFICATION_TIMEOUT_DELTA,
) -> bool:
    """
    Polls the /control/filtering/check_host endpoint to verify the domain's filter status.
    Returns True if the expected reason is found within the timeout, False otherwise.
    """
    check_url_path: str = f"filtering/check_host?name={domain}"
    start_time: datetime = datetime.now(timezone.utc)

    print(
        f"      Verifying '{domain}' status is '{expected_reason}' (timeout: {timeout_delta.total_seconds()}s)..."
    )

    while (datetime.now(timezone.utc) - start_time) < timeout_delta:
        stdout, stderr, returncode = execute_curl(
            "GET", check_url_path, auth_header, content_type_header, adguard_api_url
        )

        if returncode != CURL_SUCCESS_CODE:
            print(
                f"      Warning: Error checking host filter status. Curl exited with code {returncode}."
            )
            print(f"      Curl stderr: {stderr}")
            time.sleep(POLLING_INTERVAL_DELTA.total_seconds())
            continue

        try:
            check_data: Dict[str, Any] = json.loads(stdout)
            current_reason: Optional[str] = check_data.get("reason")

            if current_reason == expected_reason:
                print(
                    f"      Verification successful: '{domain}' reason is '{current_reason}'."
                )
                return True
            else:
                print(
                    f"      Current reason for '{domain}' is '{current_reason}'. Expected '{expected_reason}'. Retrying..."
                )
        except json.JSONDecodeError:
            print(
                f"      Warning: Could not parse JSON response from check_host: {stdout}"
            )
        except Exception as e:
            print(f"      An unexpected error occurred during status verification: {e}")

        time.sleep(POLLING_INTERVAL_DELTA.total_seconds())

    print(
        f"      Verification timed out for '{domain}'. Expected '{expected_reason}' but got '{current_reason if 'current_reason' in locals() else 'N/A'}'"
    )
    return False


# --- Step Functions ---
def block_domain(
    auth_header: str,
    content_type_header: str,
    adguard_api_url: str,
    domain_to_block: str,
    block_rule: str,
) -> None:
    """
    Blocks access to the specified domain in AdGuard Home and verifies the change.
    """
    print(
        f"1. Attempting to BLOCK access to '{domain_to_block}' (Rule: {block_rule})..."
    )
    try:
        # Fetch current custom filtering rules
        print("   Fetching current filtering rules...")
        stdout, stderr, returncode = execute_curl(
            "GET", "filtering/status", auth_header, content_type_header, adguard_api_url
        )

        if returncode != CURL_SUCCESS_CODE:
            print(
                f"   Error: Failed to fetch current filtering status. Curl exited with code {returncode}."
            )
            print(f"   Curl stderr: {stderr}")
            sys.exit(1)

        try:
            current_rules_data: Dict[str, Any] = json.loads(stdout)
            current_user_rules: list[str] = current_rules_data.get("user_rules", [])
        except json.JSONDecodeError:
            print(
                f"   Error: Failed to parse JSON response from AdGuard Home status API."
            )
            print(f"   Raw response: {stdout}")
            sys.exit(1)

        # Check if the blocking rule already exists to avoid duplicates
        if block_rule in current_user_rules:
            print(f"   Rule '{block_rule}' already exists. Skipping addition.")
            new_rules: list[str] = current_user_rules
        else:
            # Add the new blocking rule to the existing rules
            new_rules = current_user_rules + [block_rule]
            print(f"   Adding rule: '{block_rule}'")

        # Send the updated rules list back to AdGuard Home
        stdout, stderr, returncode = execute_curl(
            "POST",
            "filtering/set_rules",
            auth_header,
            content_type_header,
            adguard_api_url,
            data={"rules": new_rules},
        )

        if returncode != CURL_SUCCESS_CODE:
            print(
                f"   Error: Failed to BLOCK access to '{domain_to_block}'. Curl exited with code {returncode}."
            )
            print(f"   Curl stderr: {stderr}")
            print(f"   Curl stdout: {stdout}")
            sys.exit(1)

        print(f"   Successfully sent BLOCK command for '{domain_to_block}'.")

        # --- Verification Step ---
        if not verify_filter_status(
            auth_header,
            content_type_header,
            adguard_api_url,
            domain_to_block,
            "FilteredBlackList",
            VERIFICATION_TIMEOUT_DELTA,
        ):
            print(
                f"   Error: Failed to verify '{domain_to_block}' is blocked after {VERIFICATION_TIMEOUT_DELTA.total_seconds()} seconds."
            )
            sys.exit(1)
        print(f"   Verified '{domain_to_block}' is now BLOCKED.")

    except Exception as e:
        print(f"   An unexpected error occurred during blocking: {e}")
        sys.exit(1)
    print("")


def monitor_for_blocked_query(
    auth_header: str,
    content_type_header: str,
    adguard_api_url: str,
    start_datetime_utc: datetime,
    domain_to_check: str,
) -> bool:
    """
    Checks query logs for a blocked query to the specified domain
    since the given start_datetime_utc. Returns True if found, False otherwise.

    UPDATED LOGIC: checks if the query ends with the domain (subdomain match).
    """
    # Construct query parameters for the API call
    params: Dict[str, Any] = {
        "search": domain_to_check,  # AdGuard API performs a substring search here
        "limit": 50,  # Fetch a reasonable number of recent queries
    }

    # Manually build query string from parameters
    query_string: str = "&".join([f"{k}={v}" for k, v in params.items()])
    full_path_with_query: str = f"querylog?{query_string}"

    # Debugging: show the exact query URL
    # print(f"   Querying logs with: {full_path_with_query}")

    stdout, stderr, returncode = execute_curl(
        "GET", full_path_with_query, auth_header, content_type_header, adguard_api_url
    )

    if returncode != CURL_SUCCESS_CODE:
        print(
            f"   Warning: Error fetching query logs. Curl exited with code {returncode}."
        )
        print(f"   Curl stderr: {stderr}")
        return False  # Don't exit, just report failure to monitor this specific poll

    try:
        log_data: Dict[str, Any] = json.loads(stdout)
        queries: list[Dict[str, Any]] = log_data.get("data", [])

        if not queries:
            return False

        for query in queries:
            query_time_str: Optional[str] = query.get("time")
            query_name: Optional[str] = query.get("question", {}).get("name")
            query_reason: Optional[str] = query.get("reason")

            # Ensure all necessary fields are present
            if not (query_time_str and query_name and query_reason):
                continue

            # LOGIC UPDATE: Check if it's the domain OR a subdomain
            # e.g. domain_to_check="zenless.net" matches "global.zenless.net"
            is_match = (query_name == domain_to_check) or query_name.endswith(
                f".{domain_to_check}"
            )

            if is_match and query_reason == "FilteredBlackList":
                try:
                    # Parse the ISO 8601 timestamp from AdGuard Home logs
                    query_dt: datetime = datetime.fromisoformat(
                        query_time_str.replace("Z", "+00:00")
                    )

                    # Compare timestamps: query must be at or after our start_datetime_utc
                    if query_dt >= start_datetime_utc:
                        print(
                            f"   Found matching blocked query: '{query_name}' (Reason: {query_reason}, Time: {query_time_str}) - MATCH!"
                        )
                        return True
                    else:
                        pass  # Just skip old entries silently
                except ValueError as ve:
                    print(
                        f"   Warning: Could not parse query time '{query_time_str}': {ve}"
                    )

        return False  # No matching query found
    except json.JSONDecodeError:
        print(f"   Warning: Error parsing query log JSON: {stdout}")
        return False
    except Exception as e:
        print(f"   An unexpected error occurred while processing query logs: {e}")
        return False


def unblock_domain(
    auth_header: str,
    content_type_header: str,
    adguard_api_url: str,
    domain_to_block: str,
    block_rule: str,
) -> None:
    """
    Re-enables access to the specified domain in AdGuard Home and verifies the change.
    """
    print(f"3. Attempting to RE-ENABLE access to '{domain_to_block}'...")
    try:
        # Fetch current custom filtering rules again to ensure we have the latest state
        print("   Fetching current filtering rules again...")
        stdout, stderr, returncode = execute_curl(
            "GET", "filtering/status", auth_header, content_type_header, adguard_api_url
        )

        if returncode != CURL_SUCCESS_CODE:
            print(
                f"   Error: Failed to fetch current filtering status for re-enabling. Curl exited with code {returncode}."
            )
            print(f"   Curl stderr: {stderr}")
            sys.exit(1)

        try:
            current_rules_data: Dict[str, Any] = json.loads(stdout)
            current_user_rules: list[str] = current_rules_data.get("user_rules", [])
        except json.JSONDecodeError:
            print(
                f"   Error: Failed to parse JSON response from AdGuard Home status API during unblock."
            )
            print(f"   Raw response: {stdout}")
            sys.exit(1)

        # Remove the specific blocking rule from the list
        updated_rules: list[str] = [
            rule for rule in current_user_rules if rule != block_rule
        ]

        if block_rule not in current_user_rules:
            print(
                f"   Rule '{block_rule}' was not found. Domain might already be unblocked."
            )
        else:
            print(f"   Removing rule: '{block_rule}'")

        # Send the updated rules list back to AdGuard Home
        stdout, stderr, returncode = execute_curl(
            "POST",
            "filtering/set_rules",
            auth_header,
            content_type_header,
            adguard_api_url,
            data={"rules": updated_rules},
        )

        if returncode != CURL_SUCCESS_CODE:
            print(
                f"   Error: Failed to RE-ENABLE access to '{domain_to_block}'. Curl exited with code {returncode}."
            )
            print(f"   Curl stderr: {stderr}")
            print(f"   Curl stdout: {stdout}")
            sys.exit(1)

        print(f"   Successfully sent UNBLOCK command for '{domain_to_block}'.")

        # --- Verification Step ---
        if not verify_filter_status(
            auth_header,
            content_type_header,
            adguard_api_url,
            domain_to_block,
            "NotFilteredNotFound",
            VERIFICATION_TIMEOUT_DELTA,
        ):
            print(
                f"   Error: Failed to verify '{domain_to_block}' is unblocked after {VERIFICATION_TIMEOUT_DELTA.total_seconds()} seconds."
            )
            sys.exit(1)
        print(f"   Verified '{domain_to_block}' is now UNBLOCKED.")

    except Exception as e:
        print(f"   An unexpected error occurred during unblocking: {e}")
        sys.exit(1)
    print("")


# --- Main Script Execution ---
def main() -> None:
    # 1. Parse arguments
    args: argparse.Namespace = parse_arguments()

    # Assign parsed arguments to variables
    adguard_home_ip: str = args.ip
    adguard_home_port: int = args.port
    username: str = args.username
    password: str = args.password
    domain_to_block: str = args.domain  # Captured from CLI

    # --- Rule Configuration ---
    # We use AdBlock syntax "||example.com^" instead of Hosts syntax "0.0.0.0 example.com"
    # This allows blocking the parent domain to automatically block all subdomains.
    block_rule: str = f"||{domain_to_block}^"

    # Convert timeout_seconds (int) to timeout_delta (timedelta)
    timeout_delta: timedelta = timedelta(seconds=args.timeout)

    # --- Internal Setup (using parsed arguments) ---
    # Base64 encode credentials for Basic Authentication
    credentials: str = f"{username}:{password}"
    encoded_credentials: str = base64.b64encode(credentials.encode()).decode()

    # Set up common headers for API requests
    AUTH_HEADER: str = f"Authorization: Basic {encoded_credentials}"
    CONTENT_TYPE_HEADER: str = "Content-Type: application/json"

    # Construct the base URL for the AdGuard Home API
    ADGUARD_API_URL: str = f"http://{adguard_home_ip}:{adguard_home_port}/control"

    print("--- AdGuard Home Domain Blocker/Unblocker ---")
    print(f"Target AdGuard Home: {ADGUARD_API_URL}")
    print(f"Domain to manage: {domain_to_block}")
    print(f"Applied Rule: {block_rule}")
    print(f"Monitoring timeout: {timeout_delta.total_seconds()} seconds")
    print("")

    # 2. Execute steps
    block_domain(
        AUTH_HEADER, CONTENT_TYPE_HEADER, ADGUARD_API_URL, domain_to_block, block_rule
    )

    # --- Open application after successful blocking ---
    if args.app:
        print(f"   Opening application: {args.app}")
        try:
            # Use 'open' command for macOS to launch applications
            subprocess.run(["open", "-n", args.app], check=True, capture_output=True)
            print(f"   Successfully opened '{args.app}'.")
        except FileNotFoundError:
            print(
                f"   Error: 'open' command not found. This script is intended for macOS."
            )
        except subprocess.CalledProcessError as e:
            print(f"   Error opening application '{args.app}': {e}")
            print(f"   Stderr: {e.stderr.decode()}")
        except Exception as e:
            print(
                f"   An unexpected error occurred while trying to open '{args.app}': {e}"
            )
    else:
        print("   No application path provided. Skipping app launch.")

    # Record the start time for monitoring using datetime object
    start_monitoring_dt: datetime = datetime.now(timezone.utc)
    blocked_query_found: bool = False

    # Monitor logs until the blocked query is found or timeout occurs
    print(f"2. Monitoring query logs for a blocked query to '{domain_to_block}'...")
    while (datetime.now(timezone.utc) - start_monitoring_dt) < timeout_delta:
        # Pass the datetime object directly to the function
        found_blocked_this_check: bool = monitor_for_blocked_query(
            AUTH_HEADER,
            CONTENT_TYPE_HEADER,
            ADGUARD_API_URL,
            start_monitoring_dt,
            domain_to_block,
        )
        if found_blocked_this_check:
            blocked_query_found = True
            print(
                f"   Detected a BLOCK for '{domain_to_block}' (or subdomain) in query logs."
            )
            break
        else:
            elapsed_time_dt: timedelta = (
                datetime.now(timezone.utc) - start_monitoring_dt
            )
            # Calculate remaining time based on timedelta total_seconds
            remaining_time: int = max(
                0, int(timeout_delta.total_seconds() - elapsed_time_dt.total_seconds())
            )
            print(
                f"   '{domain_to_block}' not yet found as BLOCKED in logs. Retrying in {POLLING_INTERVAL_DELTA.total_seconds()} second(s). ({remaining_time}s remaining)"
            )
            time.sleep(POLLING_INTERVAL_DELTA.total_seconds())

    if not blocked_query_found:
        print(
            f"   Timeout reached ({timeout_delta.total_seconds()} seconds). No blocked query for '{domain_to_block}' detected."
        )

    # Always proceed to unblock the domain after monitoring (whether found or timed out)
    unblock_domain(
        AUTH_HEADER, CONTENT_TYPE_HEADER, ADGUARD_API_URL, domain_to_block, block_rule
    )

    print("--- Script finished. ---")


if __name__ == "__main__":
    main()
