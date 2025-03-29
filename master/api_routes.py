# master/api_routes.py
import datetime
import os

from flask import Blueprint, request, jsonify, current_app, abort
from sqlalchemy.exc import IntegrityError

from .models import db, Client, BackupJob, BackupLog, Setting, ClientStatus, RestoreJob, RestoreJobStatus
from .utils.security import verify_api_key, hash_api_key # Assuming verify compares hash(provided) vs stored_hash
from .app import add_ssh_key_to_authorized # Import helper

api_bp = Blueprint('api', __name__)

# --- Decorator for API Key Authentication ---
from functools import wraps

def require_api_key(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = None
        # Check Authorization header first (Bearer token)
        auth_header = request.headers.get('Authorization')
        if auth_header and auth_header.startswith('Bearer '):
            api_key = auth_header.split(' ')[1]
        else:
            # Fallback or alternative: check custom header or request data?
            # api_key = request.headers.get('X-API-Key')
             return jsonify(error="Unauthorized", message="API key missing or invalid format in Authorization header (Bearer <key>)."), 401


        if not api_key:
             return jsonify(error="Unauthorized", message="API key required."), 401

        # Find client by hashing the provided key and comparing to stored hashes
        hashed_provided_key = hash_api_key(api_key) # Hash the key the client sent
        client = Client.query.filter_by(api_key_hash=hashed_provided_key).first()

        if not client:
            current_app.logger.warning(f"Invalid API key received from {request.remote_addr}. Key hash prefix: {hashed_provided_key[:10]}...")
            return jsonify(error="Unauthorized", message="Invalid API key."), 401

        # Store client on request context? Could be useful.
        # from flask import g
        # g.client = client
        kwargs['client'] = client # Or pass client as argument to route function

        return f(*args, **kwargs)
    return decorated_function


# --- API Endpoints ---

@api_bp.route('/register', methods=['POST'])
def register():
    """Registers a new client using a one-time token."""
    data = request.get_json()
    if not data:
        return jsonify(error="Bad Request", message="Invalid JSON payload."), 400

    token = data.get('token')
    client_uuid = data.get('uuid')
    hostname = data.get('hostname')
    os_info = data.get('os_info')
    public_key = data.get('ssh_public_key')

    if not all([token, client_uuid, hostname, os_info, public_key]):
        return jsonify(error="Bad Request", message="Missing required fields (token, uuid, hostname, os_info, ssh_public_key)."), 400

    # TODO: Validate token against a stored list of temporary tokens/expiries
    # For now, assume token is valid if present (less secure)
    # A better approach: Generate token via UI, store hash+expiry in DB, validate here.
    current_app.logger.info(f"Registration attempt received for UUID {client_uuid} with token.")


    # Check if UUID already exists
    existing_client = Client.query.filter_by(uuid=client_uuid).first()
    if existing_client:
        # Allow re-registration if token is valid and maybe IP matches? Or just deny?
        current_app.logger.warning(f"Registration attempt failed: Client UUID {client_uuid} already exists.")
        return jsonify(error="Conflict", message="Client UUID already registered."), 409

    # Get master settings for SSH user
    settings = Setting.query.first()
    if not settings:
         current_app.logger.error("Registration failed: Master settings not configured.")
         return jsonify(error="Internal Server Error", message="Master server settings not configured."), 500

    ssh_user = settings.backup_ssh_user

    # Generate API Key
    api_key = uuid.uuid4().hex + uuid.uuid4().hex # Generate a strong API key

    try:
        client = Client(
            uuid=client_uuid,
            name=hostname, # Default name to hostname
            hostname=hostname,
            os_info=os_info,
            ssh_public_key=public_key,
            status=ClientStatus.OFFLINE, # Mark as offline until first heartbeat
            last_heartbeat=None,
            # Store the HASH of the API key, not the raw key
            api_key_hash=hash_api_key(api_key)
        )
        db.session.add(client)
        db.session.flush() # Get client.id before commit potentially

        # Add SSH key to authorized_keys (best effort)
        if not add_ssh_key_to_authorized(ssh_user, public_key, client_uuid):
             # Don't fail registration, but log warning. User must add key manually.
             current_app.logger.warning(f"Failed to automatically add SSH key for client {client_uuid} to user {ssh_user}. Manual addition required.")
             # Optionally flash a message or store status for UI?

        # Get master's SSH host key to send back? More complex. Requires reading host keys.
        master_ssh_host_key = None
        try:
             # Try reading common host key files (adjust paths as needed)
             # This is a simplification and might not find the correct key.
             rsa_key_path = '/etc/ssh/ssh_host_rsa_key.pub'
             ed25519_key_path = '/etc/ssh/ssh_host_ed25519_key.pub'
             if os.path.exists(ed25519_key_path):
                  with open(ed25519_key_path, 'r') as f: master_ssh_host_key = f.read().strip()
             elif os.path.exists(rsa_key_path):
                   with open(rsa_key_path, 'r') as f: master_ssh_host_key = f.read().strip()
             else:
                 current_app.logger.warning("Could not find master SSH host public key to send to client.")
        except Exception as e:
             current_app.logger.error(f"Error reading master SSH host key: {e}")


        db.session.commit()
        current_app.logger.info(f"Client registered successfully: {hostname} (UUID: {client_uuid}, DB ID: {client.id})")

        return jsonify(
            message="Registration successful",
            api_key=api_key, # Send the RAW key back to the client this one time
            client_id=client.uuid, # Send back the UUID master uses
            master_ssh_host_key=master_ssh_host_key # Send host key if found
            ), 201

    except IntegrityError as e:
        db.session.rollback()
        current_app.logger.warning(f"Registration failed due to potential duplicate UUID or API key hash: {e}")
        return jsonify(error="Conflict", message="Client UUID or generated key hash conflicts with existing record."), 409
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error during client registration: {e}", exc_info=True)
        return jsonify(error="Internal Server Error", message=f"An error occurred: {e}"), 500


@api_bp.route('/heartbeat', methods=['POST'])
@require_api_key
def heartbeat(client): # client object passed by decorator
    """Receives heartbeat from a client."""
    data = request.get_json() or {}
    now = datetime.datetime.utcnow()

    client.last_heartbeat = now
    # Update status based on heartbeat, maybe reset error status?
    if client.status != ClientStatus.ONLINE:
         current_app.logger.info(f"Client '{client.name}' came online. Previous status: {client.status.name}")
         client.status = ClientStatus.ONLINE
    # Optionally update IP address if it changes? Get from request.remote_addr
    client.ip_address = request.remote_addr

    # Update other info if provided? e.g., client agent version
    # client.agent_version = data.get('agent_version', client.agent_version)

    try:
        db.session.commit()
        return jsonify(status="received"), 200
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating heartbeat for client {client.uuid}: {e}", exc_info=True)
        return jsonify(error="Internal Server Error", message="Failed to process heartbeat."), 500


@api_bp.route('/config/<string:client_uuid>', methods=['GET'])
@require_api_key
def get_config(client_uuid, client): # client object passed by decorator
    """Provides configuration (jobs, restore tasks) for a specific client."""
    # Double check UUID matches authenticated client
    if client.uuid != client_uuid:
         current_app.logger.warning(f"API key authenticated for client {client.uuid} but requested config for {client_uuid}.")
         abort(403) # Forbidden

    settings = Setting.query.first()
    if not settings: return jsonify(error="Master settings not configured"), 500

    # Fetch enabled backup jobs for this client
    backup_jobs = BackupJob.query.filter_by(client_id=client.id, enabled=True).all()
    jobs_list = []
    for job in backup_jobs:
        job_data = {
            'id': job.id,
            'name': job.name,
            'job_type': job.job_type.value,
            'source_path': job.source_path,
            'db_name': job.db_name,
            'db_user': job.db_user,
            # Send encrypted password for client to decrypt, or send raw over HTTPS?
            # Sending raw simplifies client but less secure if HTTPS compromised or misconfigured.
            # Let's send raw for now, assuming strong HTTPS. Client must handle it securely.
            'db_password': decrypt_data(job.db_password, current_app.config['SECRET_KEY']) if job.db_password else None,
            'db_host': job.db_host,
            'db_port': job.db_port,
            'cron_schedule': job.cron_schedule,
            'bandwidth_limit_kbps': job.bandwidth_limit_kbps,
            'rsync_options': job.rsync_options,
            'pre_backup_script': job.pre_backup_script,
            'post_backup_script': job.post_backup_script,
            # Provide the full target path on the master for the client
            'master_target_path': job.get_target_path(settings.backup_base_path, client.uuid)
        }
        jobs_list.append(job_data)

    # Fetch pending restore tasks for this client
    restore_tasks = RestoreJob.query.filter_by(client_id=client.id, status=RestoreJobStatus.PENDING).all()
    restore_list = []
    for task in restore_tasks:
         # Get the original job's base path on master
         original_job = BackupJob.query.get(task.backup_job_id)
         if not original_job:
              current_app.logger.error(f"Restore task {task.id} references non-existent job {task.backup_job_id}. Skipping.")
              # Optionally mark task as failed here?
              continue

         task_data = {
             'id': task.id,
             'backup_job_id': task.backup_job_id,
             'source_snapshot': task.source_snapshot,
             'source_items': task.source_items,
             'target_path': task.target_path,
             'master_backup_path': original_job.get_target_path(settings.backup_base_path, client.uuid) # Provide source base path
         }
         restore_list.append(task_data)

    return jsonify(jobs=jobs_list, restore_tasks=restore_list), 200


@api_bp.route('/log', methods=['POST'])
@require_api_key
def submit_log(client): # client object passed by decorator
    """Receives log entries from a client."""
    data = request.get_json()
    if not data:
        return jsonify(error="Bad Request", message="Invalid JSON payload."), 400

    try:
        log_entry = BackupLog(
            client_id=client.id,
            job_id=data.get('job_id'), # Can be null for general client logs
            timestamp=datetime.datetime.fromisoformat(data.get('timestamp', '').replace('Z', '+00:00')), # Ensure UTC
            log_level=data.get('log_level', 'INFO').upper(),
            message=data.get('message', ''),
            status=data.get('status'),
            duration_seconds=data.get('duration_seconds'),
            size_bytes=data.get('size_bytes'),
            backup_snapshot_name=data.get('backup_snapshot_name')
        )
        db.session.add(log_entry)

        # Update job's last run status if this log indicates completion
        if log_entry.job_id and log_entry.status in ['Success', 'Failed', 'Partial']:
            job = BackupJob.query.get(log_entry.job_id)
            if job and job.client_id == client.id:
                 job.last_run = log_entry.timestamp
                 job.last_status = log_entry.status
                 job.last_message = log_entry.message # Store last message? Maybe too long. Store truncated?
                 if len(job.last_message) > 500: # Truncate if necessary
                     job.last_message = job.last_message[:500] + "..."

        db.session.commit()
        return jsonify(status="log received"), 201

    except ValueError as e: # Handle invalid timestamp format etc.
        current_app.logger.warning(f"Failed to parse log data from client {client.uuid}: {e}. Data: {data}")
        return jsonify(error="Bad Request", message=f"Invalid data format: {e}"), 400
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error saving log from client {client.uuid}: {e}", exc_info=True)
        return jsonify(error="Internal Server Error", message="Failed to save log entry."), 500


@api_bp.route('/restore_status/<int:restore_id>', methods=['POST'])
@require_api_key
def update_restore_status(restore_id, client): # client object passed by decorator
    """Updates the status of a restore job."""
    restore_job = RestoreJob.query.get_or_404(restore_id)

    # Verify the restore job belongs to the authenticated client
    if restore_job.client_id != client.id:
        current_app.logger.warning(f"Client {client.uuid} attempted to update status for restore job {restore_id} belonging to client {restore_job.client_id}.")
        abort(403) # Forbidden

    data = request.get_json()
    if not data:
        return jsonify(error="Bad Request", message="Invalid JSON payload."), 400

    new_status_str = data.get('status')
    message = data.get('message')
    duration = data.get('duration_seconds')

    if not new_status_str:
        return jsonify(error="Bad Request", message="Missing 'status' field."), 400

    try:
        new_status = RestoreJobStatus(new_status_str) # Validate enum value
    except ValueError:
         return jsonify(error="Bad Request", message=f"Invalid status value: '{new_status_str}'. Valid values are: {', '.join([s.value for s in RestoreJobStatus])}."), 400

    try:
        restore_job.status = new_status
        if message:
            restore_job.message = message
        if new_status == RestoreJobStatus.RUNNING:
             restore_job.started_at = datetime.datetime.utcnow()
        elif new_status in [RestoreJobStatus.COMPLETED, RestoreJobStatus.FAILED]:
             restore_job.completed_at = datetime.datetime.utcnow()
             if duration is not None:
                  # Calculate duration if not provided? Maybe client provides it.
                  if restore_job.started_at:
                     # Use client provided duration if available, else calculate
                     # restore_job.duration = duration ?? (datetime.datetime.utcnow() - restore_job.started_at).total_seconds()
                     pass # Store duration if needed in model

             # Send notification on completion/failure
             settings = Setting.query.first()
             if settings:
                 original_job = BackupJob.query.get(restore_job.backup_job_id)
                 send_notification(
                     subject=f"恢复任务 {new_status.name.title()}: {client.name}",
                     recipient_email=settings.notification_email,
                     webhook_url=settings.notification_webhook_url,
                     text_body=f"恢复任务 (ID: {restore_job.id}) for client '{client.name}' finished with status: {new_status.name}.\n"
                               f"任务: {original_job.name if original_job else 'N/A'}\n快照: {restore_job.source_snapshot}\n目标路径: {restore_job.target_path}\n"
                               f"消息: {message}",
                     context={'client': client, 'job': original_job, 'restore_job': restore_job, 'status': new_status.name}
                 )


        db.session.commit()
        current_app.logger.info(f"Restore job {restore_id} status updated to {new_status.name} by client {client.uuid}.")
        return jsonify(status="status updated"), 200

    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Error updating restore status for job {restore_id}: {e}", exc_info=True)
        return jsonify(error="Internal Server Error", message="Failed to update restore status."), 500
