import configparser
import datetime
import logging
import os
import platform
import requests
import schedule # Using schedule library for internal scheduling
import sys
import time
import traceback
import uuid # For initial UUID generation if needed
import signal # For graceful shutdown
import threading # To run schedule in background

from .utils import setup_logging, run_command
from .backup_tasks import backup_directory, backup_database, restore_files # Import task functions
try:
    from .utils_crypto import decrypt_data_client # If client needs decryption
except ImportError:
     # Dummy function if crypto utils aren't needed/present on client
     def decrypt_data_client(data, key): return data


# --- Global Variables ---
CONFIG = None
API_HEADERS = {}
MASTER_URL = None
CLIENT_ID = None
AGENT_STOP_EVENT = threading.Event() # Use threading event for daemon stop signal

# --- Helper Functions ---
def load_config(config_file):
    """Loads configuration from the INI file."""
    global CONFIG, MASTER_URL, CLIENT_ID, API_HEADERS
    if not os.path.exists(config_file):
        logging.error(f"Configuration file not found: {config_file}")
        return False
    CONFIG = configparser.ConfigParser()
    CONFIG.read(config_file)

    # Validate essential sections/keys
    if not CONFIG.has_section('main') or not CONFIG.has_section('ssh'):
        logging.error("Config file missing 'main' or 'ssh' section.")
        return False
    if not CONFIG.has_option('main', 'master_url'):
        logging.error("Config file missing 'master_url' in [main] section.")
        return False

    MASTER_URL = CONFIG.get('main', 'master_url').rstrip('/')
    CLIENT_ID = CONFIG.get('main', 'client_id', fallback=None)
    api_key = CONFIG.get('main', 'api_key', fallback=None)

    if api_key:
        API_HEADERS = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    else:
        API_HEADERS = {'Content-Type': 'application/json'} # Needed for registration

    # Setup logging based on config
    log_file = CONFIG.get('main', 'log_file', fallback='agent.log')
    log_level = CONFIG.get('main', 'log_level', fallback='INFO')
    setup_logging(log_file, log_level)

    logging.info(f"Configuration loaded from {config_file}")
    return True

def api_request(method, endpoint, data=None, ignore_errors=False):
    """Makes an API request to the master server."""
    url = f"{MASTER_URL}/api{endpoint}"
    verify_ssl = CONFIG.getboolean('main', 'verify_ssl', fallback=True)
    if not verify_ssl:
        # Suppress only the single InsecureRequestWarning from urllib3 needed
        requests.packages.urllib3.disable_warnings(requests.packages.urllib3.exceptions.InsecureRequestWarning)
        logging.warning("SSL verification is disabled. This is insecure.")

    try:
        logging.debug(f"Sending {method} request to {url}")
        if data:
             logging.debug(f"Request data: {data}") # Avoid logging sensitive data in production

        response = requests.request(method, url, json=data, headers=API_HEADERS, verify=verify_ssl, timeout=30) # 30s timeout

        # Log response status and potentially body for debugging
        logging.debug(f"Response status code: {response.status_code}")
        if response.content:
            try:
                # Limit log size
                log_content = response.text[:500] + ('...' if len(response.text) > 500 else '')
                logging.debug(f"Response content: {log_content}")
            except Exception:
                 logging.debug("Could not decode response content for logging.")


        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)
        return response.json()

    except requests.exceptions.Timeout:
        logging.error(f"API request timed out: {method} {url}")
        if ignore_errors: return None
        raise
    except requests.exceptions.SSLError as e:
         logging.error(f"SSL Error connecting to master at {url}: {e}")
         logging.error("Ensure the master URL is correct and the server's SSL certificate is valid.")
         logging.error("If using a self-signed certificate, set 'verify_ssl = False' in config (INSECURE).")
         if ignore_errors: return None
         raise
    except requests.exceptions.ConnectionError as e:
        logging.error(f"Connection error: Could not connect to master at {url}: {e}")
        if ignore_errors: return None
        raise
    except requests.exceptions.RequestException as e:
        logging.error(f"API request failed: {method} {url} - {e}")
        # Log response body if available and request failed
        if hasattr(e, 'response') and e.response is not None:
            logging.error(f"Failed response status: {e.response.status_code}")
            logging.error(f"Failed response body: {e.response.text[:500]}") # Limit log size
        if ignore_errors: return None
        raise
    except Exception as e:
        logging.error(f"An unexpected error occurred during API request: {e}", exc_info=True)
        if ignore_errors: return None
        raise


def register_client(config_file):
    """Registers the client with the master server."""
    logging.info("Attempting to register client with master...")

    if not CONFIG:
        logging.error("Configuration not loaded, cannot register.")
        return False

    token = CONFIG.get('main', 'registration_token', fallback=None)
    if not token:
        logging.error("Registration token not found in configuration.")
        return False

    # Get client information
    hostname = platform.node()
    os_info = f"{platform.system()} {platform.release()}"
    # Generate or reuse a client UUID? Let's generate one if not present.
    client_uuid = CONFIG.get('main', 'client_id', fallback=str(uuid.uuid4()))

    # Get SSH public key
    ssh_key_path = CONFIG.get('ssh', 'private_key_path', fallback=None)
    if not ssh_key_path:
        logging.error("SSH private key path not configured.")
        return False
    public_key_path = ssh_key_path + '.pub'
    if not os.path.exists(public_key_path):
        logging.error(f"SSH public key not found at {public_key_path}. Ensure key pair was generated.")
        return False
    with open(public_key_path, 'r') as f:
        public_key = f.read().strip()

    payload = {
        'token': token,
        'uuid': client_uuid,
        'hostname': hostname,
        'os_info': os_info,
        'ssh_public_key': public_key
    }

    # Add master's host key to known_hosts before registration? Risky.
    # Better: Get host key during registration response or manual add.
    # Let's try adding the host key *after* successful registration.

    try:
        response_data = api_request('POST', '/register', data=payload)

        if response_data and 'api_key' in response_data and 'client_id' in response_data:
            new_api_key = response_data['api_key']
            new_client_id = response_data['client_id'] # Master might assign a different ID/UUID

            # Save the new API key and Client ID back to the config file
            CONFIG.set('main', 'api_key', new_api_key)
            CONFIG.set('main', 'client_id', new_client_id)
            # Remove the used token
            CONFIG.remove_option('main', 'registration_token')

            try:
                with open(config_file, 'w') as cfgfile:
                    CONFIG.write(cfgfile)
                # Secure permissions again after writing
                os.chmod(config_file, 0o600)
                logging.info("Registration successful! API Key and Client ID saved.")
                print("Registration successful! API Key and Client ID saved.") # Also print to stdout for install script

                # --- Handle SSH Host Key ---
                master_host_key = response_data.get('master_ssh_host_key')
                master_host = MASTER_URL.split('//')[-1].split('/')[0].split(':')[0] # Extract hostname/IP
                known_hosts_file = CONFIG.get('ssh', 'known_hosts_file')

                if master_host_key and master_host and known_hosts_file:
                    logging.info(f"Attempting to add master SSH host key for {master_host} to {known_hosts_file}")
                    try:
                        # Ensure .ssh dir exists
                        os.makedirs(os.path.dirname(known_hosts_file), mode=0o700, exist_ok=True)
                        # Check if host key already exists
                        key_found = False
                        if os.path.exists(known_hosts_file):
                             with open(known_hosts_file, 'r') as khf:
                                 if master_host in khf.read(): # Simple check
                                     key_found = True
                                     logging.info(f"Host key for {master_host} likely already exists in {known_hosts_file}.")

                        if not key_found:
                             # Append the key provided by the master
                             with open(known_hosts_file, 'a') as khf:
                                 # Ensure file ends with newline before adding
                                 khf.seek(0, os.SEEK_END)
                                 if khf.tell() > 0:
                                     khf.seek(khf.tell() - 1, os.SEEK_SET)
                                     if khf.read(1) != '\n':
                                         khf.write('\n')
                                 # Add the key (Master should provide it in correct format)
                                 khf.write(f"{master_host_key}\n")
                             os.chmod(known_hosts_file, 0o600) # Secure permissions
                             logging.info(f"Successfully added master SSH host key to {known_hosts_file}")
                        else:
                            # Optional: Verify existing key matches? More complex.
                            pass

                    except Exception as e:
                        logging.error(f"Failed to add master SSH host key: {e}", exc_info=True)
                        logging.warning("You may need to manually add the master's SSH host key to known_hosts or disable strict host key checking (less secure).")
                else:
                    logging.warning("Master did not provide SSH host key or could not determine hostname. Manual SSH connection might be needed first.")


                # Reload config in memory after update
                load_config(config_file)
                return True
            except IOError as e:
                logging.error(f"Failed to write updated configuration to {config_file}: {e}")
                print(f"Error: Failed to write updated configuration to {config_file}")
                return False
        else:
            error_msg = response_data.get('message', 'Registration failed. No API Key received.') if response_data else 'Registration failed. Empty response.'
            logging.error(error_msg)
            print(f"Error: {error_msg}")
            return False

    except requests.exceptions.RequestException as e:
        logging.error(f"Registration request failed: {e}")
        # Try to print more specific error from response if available
        error_detail = "Network error or Master unreachable."
        if hasattr(e, 'response') and e.response is not None:
             try:
                 err_data = e.response.json()
                 error_detail = err_data.get('message', e.response.text[:200])
             except ValueError: # Not JSON
                 error_detail = e.response.text[:200] # Log first 200 chars
        print(f"Error: Registration failed. {error_detail}")
        return False
    except Exception as e:
         logging.error(f"An unexpected error occurred during registration: {e}", exc_info=True)
         print(f"Error: An unexpected error occurred: {e}")
         return False


def send_heartbeat():
    """Sends a heartbeat signal to the master."""
    if not CLIENT_ID or not API_HEADERS.get('Authorization'):
        logging.warning("Client not registered or API key missing, cannot send heartbeat.")
        return

    logging.debug("Sending heartbeat...")
    payload = {
        'client_id': CLIENT_ID,
        'status': 'online', # Add more detailed status later? (e.g., idle, running_backup)
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z'
    }
    try:
        api_request('POST', '/heartbeat', data=payload, ignore_errors=True) # Ignore errors for heartbeat
        logging.debug("Heartbeat sent successfully.")
    except Exception as e:
        logging.warning(f"Failed to send heartbeat: {e}") # Don't crash agent for heartbeat failure


def send_log(job_id, level, message, status=None, duration=None, size=None, snapshot_name=None):
    """Sends a log entry to the master."""
    if not CLIENT_ID or not API_HEADERS.get('Authorization'):
        logging.warning("Client not registered or API key missing, cannot send log.")
        return

    logging.debug(f"Sending log: Level={level}, Job={job_id}, Status={status}, Msg={message[:100]}...")
    payload = {
        'client_id': CLIENT_ID,
        'job_id': job_id,
        'log_level': level.upper(),
        'message': message,
        'timestamp': datetime.datetime.utcnow().isoformat() + 'Z',
        'status': status,
        'duration_seconds': duration,
        'size_bytes': size,
        'backup_snapshot_name': snapshot_name
    }
    try:
        # Use ignore_errors=True so agent doesn't stop if master log endpoint fails
        api_request('POST', '/log', data=payload, ignore_errors=True)
        logging.debug("Log sent successfully.")
    except Exception as e:
        logging.warning(f"Failed to send log entry: {e}")


def get_jobs_and_config():
    """Fetches backup jobs and configuration from the master."""
    if not CLIENT_ID or not API_HEADERS.get('Authorization'):
        logging.error("Client not registered or API key missing, cannot fetch jobs.")
        return None, None

    logging.info("Fetching jobs and configuration from master...")
    try:
        response_data = api_request('GET', f'/config/{CLIENT_ID}')
        if response_data:
            jobs = response_data.get('jobs', [])
            # Decrypt sensitive data if needed (e.g., DB passwords)
            # Requires a shared secret or asymmetric encryption setup.
            # For simplicity, let's assume master sends decrypted pass over HTTPS for now.
            # OR implement decryption here using utils_crypto.py and a key derived
            # from the API key or another shared secret.
            # Example:
            # shared_secret = CONFIG.get('main', 'api_key') # Example usage
            # for job in jobs:
            #     if 'db_password_encrypted' in job and job['db_password_encrypted']:
            #         try:
            #            job['db_password'] = decrypt_data_client(job['db_password_encrypted'], shared_secret)
            #         except Exception as decrypt_err:
            #              logging.error(f"Failed to decrypt password for job {job.get('id')}: {decrypt_err}")
            #              job['db_password'] = None # Ensure password is None if decryption fails


            restore_tasks = response_data.get('restore_tasks', []) # Get pending restore tasks

            logging.info(f"Fetched {len(jobs)} backup jobs and {len(restore_tasks)} restore tasks.")
            return jobs, restore_tasks
        else:
            logging.warning("No jobs or configuration received from master.")
            return [], []
    except Exception as e:
        logging.error(f"Failed to fetch jobs and configuration: {e}")
        return None, None # Indicate error


def run_backup_job(job_config):
    """Executes a single backup job."""
    job_id = job_config.get('id')
    job_name = job_config.get('name', f'Job {job_id}')
    job_type = job_config.get('job_type')

    logging.info(f"Starting backup job: '{job_name}' (ID: {job_id}, Type: {job_type})")
    send_log(job_id, 'INFO', f"Starting backup job: {job_name}", status='Running')

    # Prepare SSH config dictionary
    ssh_config = {
        'private_key_path': CONFIG.get('ssh', 'private_key_path'),
        'master_ssh_user': CONFIG.get('ssh', 'master_ssh_user'),
        'master_ssh_port': CONFIG.getint('ssh', 'master_ssh_port', fallback=22),
        'known_hosts_file': CONFIG.get('ssh', 'known_hosts_file'),
        'master_host': MASTER_URL.split('//')[-1].split('/')[0].split(':')[0] # Extract host/IP from master URL
    }

    # Get master base path for this job (Master API should provide this)
    master_target_path = job_config.get('master_target_path') # Master needs to construct and send this!
    if not master_target_path:
        msg = f"Master did not provide target path for job {job_name}."
        logging.error(msg)
        send_log(job_id, 'ERROR', msg, status='Failed')
        return

    # --- Pre-backup script ---
    pre_script = job_config.get('pre_backup_script')
    if pre_script:
        logging.info(f"Executing pre-backup script for job {job_name}...")
        send_log(job_id, 'INFO', "Executing pre-backup script...")
        stdout, stderr, exit_code = run_command(pre_script, shell=True) # Allow complex scripts via shell
        if exit_code == 0:
            logging.info(f"Pre-backup script finished successfully. Output:\n{stdout}")
            send_log(job_id, 'DEBUG', f"Pre-backup script output:\n{stdout}")
        else:
            msg = f"Pre-backup script failed (code {exit_code}) for job {job_name}. Aborting backup.\nStderr: {stderr}\nStdout: {stdout}"
            logging.error(msg)
            send_log(job_id, 'ERROR', msg, status='Failed')
            return # Stop backup if pre-script fails

    # --- Execute Backup Task ---
    success = False
    message = "Backup task not implemented."
    snapshot_name = None
    duration = 0
    size_bytes = None

    try:
        if job_type == 'dir':
            success, message, snapshot_name, duration, size_bytes = backup_directory(job_config, ssh_config, master_target_path)
        elif job_type in ['mysql', 'pgsql']:
            success, message, snapshot_name, duration, size_bytes = backup_database(job_config, ssh_config, master_target_path)
        else:
            message = f"Unsupported job type: {job_type}"
            logging.error(message)
            success = False

    except Exception as e:
        success = False
        message = f"Exception during backup execution for job {job_name}: {e}"
        logging.error(message, exc_info=True)
        duration = 0 # Reset duration on exception

    # --- Post-backup script ---
    post_script = job_config.get('post_backup_script')
    post_script_status = "Not Run"
    if post_script:
        # Run post-script regardless of backup success? Or only on success? Let's run always for cleanup etc.
        logging.info(f"Executing post-backup script for job {job_name}...")
        send_log(job_id, 'INFO', f"Executing post-backup script (Backup success: {success})...")
        p_stdout, p_stderr, p_exit_code = run_command(post_script, shell=True)
        if p_exit_code == 0:
            post_script_status = "Success"
            logging.info(f"Post-backup script finished successfully. Output:\n{p_stdout}")
            send_log(job_id, 'DEBUG', f"Post-backup script output:\n{p_stdout}")
        else:
            post_script_status = f"Failed (code {p_exit_code})"
            post_err_msg = f"Post-backup script failed (code {p_exit_code}) for job {job_name}.\nStderr: {p_stderr}\nStdout: {p_stdout}"
            logging.error(post_err_msg)
            send_log(job_id, 'ERROR', post_err_msg)
            # Don't necessarily mark the whole backup as failed if only post-script failed, but log clearly.
            message += f"\nWarning: Post-backup script {post_script_status}."

    # --- Send Final Log ---
    final_status = 'Success' if success else 'Failed'
    log_level = 'INFO' if success else 'ERROR'
    log_message = f"Backup job '{job_name}' finished. Status: {final_status}. Duration: {duration:.2f}s. Message: {message}"
    if post_script:
         log_message += f" Post-script status: {post_script_status}."

    send_log(job_id, log_level, log_message, status=final_status, duration=duration, size=size_bytes, snapshot_name=snapshot_name)
    logging.info(f"Finished backup job: '{job_name}'. Success: {success}")

def run_restore_task(restore_config):
    """Executes a single restore task."""
    restore_id = restore_config.get('id')
    job_id = restore_config.get('backup_job_id') # Original job whose backup is restored
    client_target_path = restore_config.get('target_path')
    snapshot = restore_config.get('source_snapshot')

    logging.info(f"Starting restore task ID: {restore_id} (From Job ID: {job_id}, Snapshot: {snapshot}) to '{client_target_path}'")
    # Send status update to master? Add API endpoint /api/restore_status/<restore_id>
    api_request('POST', f'/restore_status/{restore_id}', data={'status': 'Running', 'message': 'Restore started on client.'}, ignore_errors=True)


    # Prepare SSH config dictionary (same as backup)
    ssh_config = {
        'private_key_path': CONFIG.get('ssh', 'private_key_path'),
        'master_ssh_user': CONFIG.get('ssh', 'master_ssh_user'),
        'master_ssh_port': CONFIG.getint('ssh', 'master_ssh_port', fallback=22),
        'known_hosts_file': CONFIG.get('ssh', 'known_hosts_file'),
        'master_host': MASTER_URL.split('//')[-1].split('/')[0].split(':')[0]
    }

    # Get the base path ON THE MASTER for the original backup job
    # This needs to be provided by the master in the restore_config!
    master_backup_path = restore_config.get('master_backup_path')
    if not master_backup_path:
        msg = f"Master did not provide source backup path for restore task {restore_id}."
        logging.error(msg)
        api_request('POST', f'/restore_status/{restore_id}', data={'status': 'Failed', 'message': msg}, ignore_errors=True)
        return

    success = False
    message = "Restore task failed."
    duration = 0
    size_bytes = None

    try:
        # Currently only supports restoring directory/file backups
        # DB restore would require downloading dump, then using mysql/pg_restore client commands
        # Assuming file restore for now
        if not os.path.exists(client_target_path):
             logging.info(f"Restore target path '{client_target_path}' does not exist. Attempting to create.")
             try:
                 os.makedirs(client_target_path, exist_ok=True)
             except OSError as e:
                 raise OSError(f"Failed to create restore target directory '{client_target_path}': {e}")

        success, message, duration, size_bytes = restore_files(restore_config, ssh_config, master_backup_path)

    except Exception as e:
        success = False
        message = f"Exception during restore execution for task {restore_id}: {e}"
        logging.error(message, exc_info=True)
        duration = 0

    # --- Send Final Status ---
    final_status = 'Completed' if success else 'Failed'
    log_level = 'INFO' if success else 'ERROR'
    log_message = f"Restore task {restore_id} finished. Status: {final_status}. Duration: {duration:.2f}s. Message: {message}"

    logging.log(logging.INFO if success else logging.ERROR, log_message)
    api_request('POST', f'/restore_status/{restore_id}', data={'status': final_status, 'message': message, 'duration_seconds': duration}, ignore_errors=True)


def check_and_run_tasks():
    """Fetches jobs and runs any scheduled backups or pending restores."""
    logging.info("Checking for scheduled tasks...")
    try:
        backup_jobs, restore_tasks = get_jobs_and_config()

        if backup_jobs is None and restore_tasks is None:
            logging.warning("Could not fetch tasks from master. Skipping check.")
            return

        now = datetime.datetime.now(datetime.timezone.utc) # Use timezone-aware UTC

        # --- Process Backup Jobs ---
        if backup_jobs:
            for job in backup_jobs:
                if not job.get('enabled', False):
                    logging.debug(f"Job '{job.get('name')}' (ID: {job.get('id')}) is disabled. Skipping.")
                    continue

                cron_schedule_str = job.get('cron_schedule')
                if not cron_schedule_str:
                    logging.warning(f"Job '{job.get('name')}' (ID: {job.get('id')}) has no schedule. Skipping.")
                    continue

                try:
                    # Use croniter to check if the job should run now
                    # Get the previous scheduled time and check if it falls between the last check and now
                    # This requires storing the last check time, or using schedule library's interval logic.

                    # Using schedule library: We define jobs based on fetched config
                    # Clear existing schedule jobs specific to backups before adding new ones
                    schedule.clear(tag='backup_job')

                    for job_cfg in backup_jobs:
                         if not job_cfg.get('enabled', False): continue
                         cron_str = job_cfg.get('cron_schedule')
                         job_id = job_cfg.get('id')
                         job_name = job_cfg.get('name', f'Job {job_id}')
                         if not cron_str or not job_id: continue

                         try:
                             # Simple way: run based on cron interval. Doesn't handle missed runs well.
                             # A better way involves checking last run time vs cron schedule.
                             # For schedule library, we can try parsing cron (might need workarounds)
                             # Example: schedule.every().day.at("02:00").do(run_backup_job, job_cfg).tag('backup_job', job_id)
                             # schedule doesn't directly support cron strings well.

                             # Fallback: check croniter manually each time check_and_run_tasks is called.
                             # This runs inside the schedule loop below.
                             pass # Logic moved to the schedule loop


                         except Exception as e:
                             logging.error(f"Failed to schedule job '{job_name}' (ID: {job_id}) with schedule '{cron_str}': {e}")

                except Exception as e:
                    logging.error(f"Error processing backup job schedules: {e}", exc_info=True)

        # --- Process Restore Tasks ---
        if restore_tasks:
             for task_cfg in restore_tasks:
                 task_id = task_cfg.get('id')
                 logging.info(f"Found pending restore task ID: {task_id}. Starting execution...")
                 try:
                     # Run restore immediately in a separate thread? Or synchronously?
                     # Running synchronously might block heartbeat/other checks. Let's use thread.
                     restore_thread = threading.Thread(target=run_restore_task, args=(task_cfg,), name=f"RestoreTask-{task_id}")
                     restore_thread.start()
                 except Exception as e:
                     logging.error(f"Failed to start restore task {task_id}: {e}", exc_info=True)
                     # Notify master of failure to start?
                     api_request('POST', f'/restore_status/{task_id}', data={'status': 'Failed', 'message': f'Failed to start restore thread: {e}'}, ignore_errors=True)


    except Exception as e:
        logging.error(f"Error in check_and_run_tasks: {e}", exc_info=True)


# --- Schedule Runner ---
# Keep track of last run time for croniter check
last_check_time = datetime.datetime.now(datetime.timezone.utc)

def schedule_checker():
    """The main loop that uses croniter to check job schedules."""
    global last_check_time
    logging.debug("Running periodic schedule check...")

    try:
        backup_jobs, restore_tasks = get_jobs_and_config()

        if backup_jobs is None and restore_tasks is None:
            logging.warning("Could not fetch tasks from master for schedule check.")
            return

        now = datetime.datetime.now(datetime.timezone.utc)

        # --- Process Backup Jobs using croniter ---
        if backup_jobs:
             for job in backup_jobs:
                 if not job.get('enabled', False): continue
                 cron_str = job.get('cron_schedule')
                 job_id = job.get('id')
                 job_name = job.get('name', f'Job {job_id}')
                 if not cron_str or not job_id: continue

                 try:
                     # Check if the job should have run between last check and now
                     cron = croniter(cron_str, now)
                     # Get the *previous* scheduled run time relative to 'now'
                     prev_run = cron.get_prev(datetime.datetime)

                     # Check if prev_run is after the last time we checked
                     if prev_run >= last_check_time:
                          logging.info(f"Cron schedule '{cron_str}' triggered for job '{job_name}' (ID: {job_id}). Previous run time: {prev_run}")
                          # Run the backup job (maybe in a thread to avoid blocking?)
                          # For simplicity, run synchronously for now. If jobs are long, use threads.
                          run_backup_job(job)
                     else:
                          logging.debug(f"Job '{job_name}' schedule '{cron_str}' not due. Prev run: {prev_run}, Last check: {last_check_time}")

                 except Exception as e:
                     logging.error(f"Error checking schedule '{cron_str}' for job '{job_name}': {e}")

        # --- Process Restore Tasks (fetched again, maybe redundant but ensures latest) ---
        if restore_tasks:
             for task_cfg in restore_tasks:
                  task_id = task_cfg.get('id')
                  logging.info(f"Found pending restore task ID: {task_id} during schedule check. Starting execution...")
                  try:
                      restore_thread = threading.Thread(target=run_restore_task, args=(task_cfg,), name=f"RestoreTask-{task_id}")
                      restore_thread.start()
                  except Exception as e:
                      logging.error(f"Failed to start restore task {task_id}: {e}", exc_info=True)
                      api_request('POST', f'/restore_status/{task_id}', data={'status': 'Failed', 'message': f'Failed to start restore thread: {e}'}, ignore_errors=True)


    except Exception as e:
        logging.error(f"Error during schedule check: {e}", exc_info=True)
    finally:
        # Update last check time *after* processing
        last_check_time = datetime.datetime.now(datetime.timezone.utc)


def run_scheduler():
    """Sets up and runs the internal schedule."""
    logging.info("Initializing agent scheduler...")

    # --- Define schedule ---
    # Send heartbeat frequently
    schedule.every(1).minute.do(send_heartbeat).tag('system')
    # Check for jobs/restores less frequently
    # schedule.every(5).minutes.do(check_and_run_tasks).tag('system')
    # Use the croniter checker instead
    schedule.every(60).seconds.do(schedule_checker).tag('system') # Check cron schedules every minute


    logging.info("Scheduler started. Running initial task check...")
    # Run checks immediately on start
    try:
        # check_and_run_tasks()
        schedule_checker() # Run the croniter check once on start
        send_heartbeat() # Send initial heartbeat
    except Exception as e:
        logging.error(f"Error during initial task run: {e}", exc_info=True)

    # --- Schedule loop ---
    logging.info("Entering main schedule loop...")
    while not AGENT_STOP_EVENT.is_set():
        schedule.run_pending()
        # Sleep for a short interval to avoid busy-waiting
        # Check event more frequently than schedule runs
        AGENT_STOP_EVENT.wait(1) # Wait for 1 second or until event is set

    logging.info("Scheduler loop exited.")


def run_daemon(config_file):
    """Runs the agent as a background daemon."""
    if not load_config(config_file):
        sys.exit(1)

    # Setup signal handling for graceful shutdown
    def signal_handler(sig, frame):
        logging.warning(f"Received signal {sig}, initiating graceful shutdown...")
        AGENT_STOP_EVENT.set() # Signal the scheduler loop to stop
        # Optionally wait for threads?

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler) # Handle Ctrl+C

    logging.info("Starting Simbak Agent in daemon mode...")
    # Start the scheduler loop in a background thread? Or run directly?
    # Running directly makes signal handling easier.
    run_scheduler()

    logging.info("Simbak Agent daemon stopped.")


# --- Main Execution ---
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Simbak Client Agent")
    parser.add_argument('--config', required=True, help="Path to the configuration file (config_client.ini)")
    parser.add_argument('--register', action='store_true', help="Register the client with the master")
    parser.add_argument('--run-daemon', action='store_true', help="Run the agent as a background daemon")
    parser.add_argument('--run-once', action='store_true', help="Run heartbeat and task check once, then exit")

    args = parser.parse_args()

    # Basic logging setup until config is loaded
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    if args.register:
        if load_config(args.config):
             if not register_client(args.config):
                 sys.exit(1) # Exit with error if registration fails
             else:
                  sys.exit(0) # Exit successfully after registration
        else:
            sys.exit(1) # Exit if config fails to load

    elif args.run_daemon:
        run_daemon(args.config)

    elif args.run_once:
        if load_config(args.config):
            logging.info("Running tasks once...")
            try:
                send_heartbeat()
                # check_and_run_tasks()
                schedule_checker() # Run the croniter check
            except Exception as e:
                 logging.error(f"Error during run-once execution: {e}", exc_info=True)
                 sys.exit(1)
            logging.info("Run-once completed.")
            sys.exit(0)
        else:
            sys.exit(1)

    else:
        parser.print_help()
        sys.exit(1)
