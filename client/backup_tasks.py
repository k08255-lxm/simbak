import os
import datetime
import logging
import tempfile
import shutil
import time

from .utils import run_command

def _get_timestamp():
    """Returns a filesystem-safe timestamp string."""
    return datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')

def _get_db_dump_cmd(job_config, output_file):
    """Constructs the command for mysqldump or pg_dump."""
    job_type = job_config['job_type']
    db_name = job_config.get('db_name')
    db_user = job_config.get('db_user')
    db_password = job_config.get('db_password') # Decrypted by agent before passing here
    db_host = job_config.get('db_host', 'localhost')
    db_port = job_config.get('db_port')
    # Allow specifying tool path in config
    mysqldump_path = job_config.get('mysqldump_path', 'mysqldump')
    pg_dump_path = job_config.get('pg_dump_path', 'pg_dump')


    cmd = []
    env = os.environ.copy() # Pass environment variables

    if job_type == 'mysql':
        cmd = [mysqldump_path]
        if db_user:
            cmd.extend(['--user', db_user])
        # Password handling: PGPASSWORD env var is not standard for mysql, use --password or .my.cnf
        # Using --password=<pass> can expose password in process list.
        # Best practice is often a credentials file (.my.cnf).
        # Second best: Environment variable (less standard for mysql client itself)
        # For simplicity here, we'll add it directly, but WARN about it.
        # Consider adding support for .my.cnf later.
        if db_password:
             logging.warning("Using --password with mysqldump exposes the password in the process list. Consider using a .my.cnf file.")
             cmd.append(f"--password={db_password}") # Be cautious with shell=True if used
             # Alternative (if tool supports it): env['MYSQL_PWD'] = db_password
        if db_host:
            cmd.extend(['--host', db_host])
        if db_port:
            cmd.extend(['--port', str(db_port)])
        cmd.extend(['--single-transaction', '--quick', '--routines', '--triggers']) # Good defaults
        cmd.append(db_name)
        # Redirect output to file (handled by run_command wrapper or direct redirection)
        # The command list itself doesn't include redirection usually

    elif job_type == 'pgsql':
        cmd = [pg_dump_path]
        if db_user:
            cmd.extend(['--username', db_user])
        if db_host:
            cmd.extend(['--host', db_host])
        if db_port:
            cmd.extend(['--port', str(db_port)])
        # Use PGPASSWORD environment variable for password
        if db_password:
            env['PGPASSWORD'] = db_password
        cmd.extend(['--format=c', '--blobs']) # Custom format is often better for pg_restore
        cmd.append(db_name)
        # Redirect output to file

    else:
        raise ValueError(f"Unsupported database type for dump: {job_type}")

    return cmd, env

def _run_rsync(ssh_config, source, destination, bwlimit_kbps=0, extra_opts=None, is_restore=False):
    """Runs the rsync command with appropriate SSH options."""
    ssh_cmd = f"ssh -i {ssh_config['private_key_path']} -p {ssh_config.get('master_ssh_port', 22)} -o StrictHostKeyChecking=no -o UserKnownHostsFile={ssh_config['known_hosts_file']}"
    # Note: StrictHostKeyChecking=no is a security risk. Better to add host key on registration.

    rsync_cmd = ['rsync']
    # Base options: archive, verbose (optional), compress, progress (optional)
    # Use -a (archive), -z (compress)
    # -v (verbose) can be noisy for logs, maybe add based on log level?
    # --delete: crucial for mirroring, removes files from destination not in source
    # --partial: keep partially transferred files for resuming
    # --info=progress2: show overall progress
    base_opts = ['-az', '--partial']
    if not is_restore: # Delete only makes sense when backing up (mirroring source to dest)
        base_opts.append('--delete')

    rsync_cmd.extend(base_opts)

    # Bandwidth limit
    if bwlimit_kbps and int(bwlimit_kbps) > 0:
        rsync_cmd.append(f"--bwlimit={int(bwlimit_kbps)}")

    # Extra user-defined options (split string into list)
    if extra_opts:
        # Basic split, doesn't handle quotes well. A more robust parser might be needed.
        rsync_cmd.extend(extra_opts.split())

    # SSH command
    rsync_cmd.extend(['-e', ssh_cmd])

    # Source and Destination
    rsync_cmd.append(source)
    rsync_cmd.append(destination)

    logging.info(f"Executing rsync: {' '.join(rsync_cmd)}") # Log command without sensitive parts if possible
    stdout, stderr, exit_code = run_command(rsync_cmd) # shell=False is safer

    if exit_code == 0:
        logging.info("Rsync completed successfully.")
        # Parse output for stats if needed (size, files transferred)
        # Example: Look for lines like "total size is ... speedup is ..."
        return True, stdout + stderr # Combine output for logging
    elif exit_code == 24:
         logging.warning("Rsync finished, but some files vanished before transfer (exit code 24). This might be acceptable.")
         return True, stdout + stderr # Treat as non-fatal error usually
    else:
        logging.error(f"Rsync failed with exit code {exit_code}.")
        logging.error(f"Rsync stderr: {stderr}")
        logging.error(f"Rsync stdout: {stdout}")
        return False, f"Rsync failed (code {exit_code}):\nstderr: {stderr}\nstdout: {stdout}"


def backup_directory(job_config, ssh_config, master_target_path):
    """Performs a directory backup using rsync."""
    start_time = time.time()
    source_path = job_config['source_path']
    bwlimit = job_config.get('bandwidth_limit_kbps')
    extra_opts = job_config.get('rsync_options')

    # Ensure source path ends with / if it's a directory to copy contents, not the dir itself
    if os.path.isdir(source_path) and not source_path.endswith('/'):
        source_path += '/'

    # Create a timestamped subdirectory on the master for snapshotting
    snapshot_name = _get_timestamp()
    destination_path = f"{ssh_config['master_ssh_user']}@{ssh_config['master_host']}:{os.path.join(master_target_path, snapshot_name)}/"

    # --- Rsync with --link-dest for snapshot efficiency ---
    # Get path to the 'latest' backup to link against
    latest_path_on_master = os.path.join(master_target_path, 'latest')
    link_dest_opt = f"--link-dest={latest_path_on_master}"

    # Combine base options with link-dest
    link_dest_rsync_opts = extra_opts + f" {link_dest_opt}" if extra_opts else link_dest_opt

    # Run the actual rsync to the timestamped dir
    success, message = _run_rsync(ssh_config, source_path, destination_path, bwlimit, link_dest_rsync_opts)

    duration = time.time() - start_time

    if success:
        logging.info(f"Directory backup successful for '{job_config['name']}' in {duration:.2f}s.")
        # After successful backup, update the 'latest' symlink on the master
        # This requires running a command on the master via SSH
        update_latest_cmd = f"ln -snf {shlex.quote(snapshot_name)} {shlex.quote(latest_path_on_master)}"
        ssh_cmd_update = [
            'ssh',
            '-i', ssh_config['private_key_path'],
            '-p', str(ssh_config.get('master_ssh_port', 22)),
            '-o', f"UserKnownHostsFile={ssh_config['known_hosts_file']}",
            '-o', 'StrictHostKeyChecking=no', # Again, insecure default
            f"{ssh_config['master_ssh_user']}@{ssh_config['master_host']}",
            update_latest_cmd
        ]
        logging.info(f"Attempting to update 'latest' symlink on master: {' '.join(ssh_cmd_update)}")
        up_stdout, up_stderr, up_exit_code = run_command(ssh_cmd_update)
        if up_exit_code == 0:
            logging.info("'latest' symlink updated successfully.")
        else:
            logging.error(f"Failed to update 'latest' symlink on master (exit code {up_exit_code}): {up_stderr}")
            # Backup itself succeeded, but link failed - maybe report as partial success?
            message += "\nWarning: Failed to update 'latest' symlink on master."
            # Don't flip success flag, the data is there.

    else:
        logging.error(f"Directory backup failed for '{job_config['name']}'.")

    # TODO: Calculate size transferred (parse rsync output or measure target)
    size_bytes = None

    return success, message, snapshot_name, duration, size_bytes


def backup_database(job_config, ssh_config, master_target_path):
    """Performs a database backup (MySQL/PostgreSQL)."""
    start_time = time.time()
    success = False
    message = ""
    snapshot_name = _get_timestamp() # Timestamp for the dump file
    size_bytes = None
    tmp_dir = None

    try:
        # Create temporary directory for dump file
        tmp_dir = tempfile.mkdtemp(prefix='simbak_db_dump_')
        logging.debug(f"Created temporary directory: {tmp_dir}")

        # Determine filename based on type
        db_type = job_config['job_type']
        db_name = job_config['db_name']
        ext = '.sql.gz' if db_type == 'mysql' else '.dump.gz' # Use compressed custom format for pg
        # Include DB name in filename for clarity
        dump_filename = f"{db_name}_{snapshot_name}{ext}"
        local_dump_path = os.path.join(tmp_dir, dump_filename)

        # 1. Run mysqldump or pg_dump
        dump_cmd, dump_env = _get_db_dump_cmd(job_config, local_dump_path) # Pass decrypted password if needed
        logging.info(f"Running database dump command: {' '.join(dump_cmd)}")

        # Pipe output to gzip and then to file
        dump_full_cmd = f"{' '.join(dump_cmd)} | gzip -c > {shlex.quote(local_dump_path)}"

        stdout, stderr, exit_code = run_command(dump_full_cmd, env=dump_env, shell=True) # Need shell for pipe

        if exit_code != 0:
            # Check stderr specifically for password errors if possible
             if db_type == 'mysql' and 'Access denied' in stderr:
                 message = f"Database dump failed: Access denied for user '{job_config.get('db_user', 'N/A')}'. Check credentials."
             elif db_type == 'pgsql' and 'password authentication failed' in stderr:
                  message = f"Database dump failed: Password authentication failed for user '{job_config.get('db_user', 'N/A')}'."
             else:
                 message = f"Database dump command failed (code {exit_code}):\nstderr: {stderr}\nstdout: {stdout}"
             logging.error(message)
             raise Exception(message) # Raise to trigger finally block for cleanup

        logging.info(f"Database dump successful: {local_dump_path}")
        size_bytes = os.path.getsize(local_dump_path)

        # 2. Rsync the dump file to the master
        destination_path = f"{ssh_config['master_ssh_user']}@{ssh_config['master_host']}:{os.path.join(master_target_path, dump_filename)}"
        bwlimit = job_config.get('bandwidth_limit_kbps')

        # Use simple rsync, no --delete or --link-dest needed for single file
        rsync_success, rsync_message = _run_rsync(ssh_config, local_dump_path, destination_path, bwlimit)

        if not rsync_success:
            message = f"Database dump created locally but failed to transfer: {rsync_message}"
            logging.error(message)
            raise Exception(message)

        logging.info("Database dump transferred successfully.")
        success = True
        message = f"Database backup completed successfully. Dump file: {dump_filename}"

    except Exception as e:
        success = False
        # Ensure message is set if not already
        if not message:
             message = f"Database backup failed: {e}"
        logging.error(f"Error during database backup for '{job_config['name']}': {e}", exc_info=True)

    finally:
        # 3. Clean up temporary directory
        if tmp_dir and os.path.exists(tmp_dir):
            try:
                shutil.rmtree(tmp_dir)
                logging.debug(f"Removed temporary directory: {tmp_dir}")
            except Exception as cleanup_e:
                logging.error(f"Failed to remove temporary directory {tmp_dir}: {cleanup_e}")

    duration = time.time() - start_time
    # Use dump filename as the "snapshot name" identifier
    return success, message, dump_filename, duration, size_bytes


# --- Restore Functions ---

def restore_files(restore_job_config, ssh_config, master_backup_path):
    """Performs a file restore using rsync from master to client."""
    start_time = time.time()
    success = False
    message = ""
    size_bytes = None

    client_target_path = restore_job_config['target_path']
    snapshot = restore_job_config['source_snapshot'] # e.g., 'latest' or 'YYYY-MM-DD_HH-MM-SS'
    # items_to_restore = restore_job_config.get('source_items', ['/']) # List of relative paths ['/'] means all

    # Construct the source path on the master
    # master_backup_path is the job's base dir, e.g., /opt/simbak/backups/client-uuid/job-id
    source_on_master_base = os.path.join(master_backup_path, snapshot)
    # Ensure source ends with / to copy contents
    if not source_on_master_base.endswith('/'):
         source_on_master_base += '/'

    # For simplicity, restore the entire snapshot first. Item selection adds complexity.
    source = f"{ssh_config['master_ssh_user']}@{ssh_config['master_host']}:{source_on_master_base}"

    # Destination is the local path provided
    destination = client_target_path
    # Ensure destination ends with / if restoring multiple items into it
    if os.path.isdir(destination) and not destination.endswith('/'):
        destination += '/'
    elif not os.path.exists(destination):
         # Try to create the destination directory if it doesn't exist?
         try:
             os.makedirs(destination, exist_ok=True)
             logging.info(f"Created destination directory for restore: {destination}")
             if not destination.endswith('/'): destination += '/'
         except OSError as e:
             message = f"Failed to create destination directory '{destination}': {e}"
             logging.error(message)
             return False, message, None, None # Fail early

    logging.info(f"Starting restore from master snapshot '{snapshot}' to local path '{client_target_path}'")

    # Rsync command for restore (pulling from master)
    # No --delete, no --link-dest usually
    # Bandwidth limit might still be useful
    bwlimit = 0 # Get from config if restore limits are implemented
    rsync_success, rsync_message = _run_rsync(ssh_config, source, destination, bwlimit, is_restore=True)

    duration = time.time() - start_time

    if rsync_success:
        success = True
        message = f"Restore completed successfully from snapshot '{snapshot}' to '{client_target_path}' in {duration:.2f}s."
        logging.info(message)
        # Try to get size? Difficult for restore.
    else:
        success = False
        message = f"Restore failed: {rsync_message}"
        logging.error(message)

    return success, message, duration, size_bytes

# Add shlex import for command construction safety
import shlex
