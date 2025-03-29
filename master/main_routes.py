# master/main_routes.py
import os
import datetime
import uuid
import json
from pathlib import Path

from flask import (Blueprint, render_template, redirect, url_for, flash, request,
                   jsonify, abort, current_app, send_from_directory, Response, stream_with_context)
from flask_login import login_required, current_user
from sqlalchemy import desc, or_
import humanize # For human readable sizes/times (install: pip install humanize)
import pwd # For getting user info for authorized_keys path

from .models import (db, User, Setting, Client, BackupJob, BackupLog, RestoreJob,
                    ClientStatus, BackupJobType, RestoreJobStatus)
from .app import (SettingsForm, ChangePasswordForm, ClientForm, BackupJobForm, RestoreForm,
                  is_safe_path, list_directory_recursive, remove_ssh_key_from_authorized) # Import forms & helpers
from .utils.security import encrypt_data, decrypt_data # Import security utils if needed here
from .utils.notifications import send_notification

main_bp = Blueprint('main', __name__)

# --- Template Filters ---
@main_bp.app_template_filter()
def human_readable_size(size_bytes):
    if size_bytes is None:
        return "N/A"
    try:
        return humanize.naturalsize(size_bytes, binary=True) # Use binary=True for KiB, MiB etc.
    except (ValueError, TypeError):
        return str(size_bytes) # Fallback

@main_bp.app_template_filter()
def timesince(dt, default="just now"):
    """Returns string representing 'time since'"""
    if dt is None:
        return "never"
    now = datetime.datetime.utcnow()
    diff = now - dt
    return humanize.naturaltime(diff)


# --- Routes ---
@main_bp.route('/')
@login_required
def index():
    return redirect(url_for('main.dashboard'))

@main_bp.route('/dashboard')
@login_required
def dashboard():
    # Gather stats
    total_clients = Client.query.count()
    online_clients = Client.query.filter_by(status=ClientStatus.ONLINE).count()
    offline_clients = Client.query.filter_by(status=ClientStatus.OFFLINE).count()

    # Estimate total backup size (this can be slow if many files/dirs)
    # A better way might be to store size during backup logging and sum those.
    # Simple estimation for now by checking base path size.
    settings = Setting.query.first()
    total_backup_size = 0
    if settings and settings.backup_base_path and os.path.isdir(settings.backup_base_path):
         try:
             # Sum size of all files in the base path - VERY SLOW for large backups!
             # total_backup_size = sum(f.stat().st_size for f in Path(settings.backup_base_path).glob('**/*') if f.is_file())

             # Faster alternative: Use du command (requires shell access)
              # result = subprocess.run(['du', '-sb', settings.backup_base_path], capture_output=True, text=True)
              # if result.returncode == 0:
              #     total_backup_size = int(result.stdout.split()[0])

             # Simplification: Just report 0 or a placeholder if calculation is too complex/slow
             total_backup_size = 0 # Placeholder - implement size tracking during backup for accuracy
             pass
         except Exception as e:
             current_app.logger.warning(f"Could not calculate total backup size: {e}")

    # Recent logs
    recent_logs = BackupLog.query.order_by(desc(BackupLog.timestamp)).limit(15).all()
    # All clients for status overview
    clients = Client.query.order_by(Client.name).all()


    stats = {
        'total_clients': total_clients,
        'online_clients': online_clients,
        'offline_clients': offline_clients,
        'total_backup_size': total_backup_size
    }
    return render_template('dashboard.html', stats=stats, recent_logs=recent_logs, clients=clients, ClientStatus=ClientStatus)


@main_bp.route('/clients')
@login_required
def list_clients():
    clients = Client.query.order_by(Client.name).all()
    settings = Setting.query.first()
    backup_ssh_user = settings.backup_ssh_user if settings else 'simbak'
    # Try to determine authorized_keys path for instructions
    authorized_keys_path = f"~{backup_ssh_user}/.ssh/authorized_keys"
    try:
        user_info = pwd.getpwnam(backup_ssh_user)
        authorized_keys_path = os.path.join(user_info.pw_dir, '.ssh', 'authorized_keys')
    except KeyError:
        current_app.logger.warning(f"Could not determine home directory for user '{backup_ssh_user}'. Using default path in instructions.")


    return render_template('clients.html',
                           clients=clients,
                           ClientStatus=ClientStatus,
                           registration_token_lifetime_minutes=current_app.config.get('REGISTRATION_TOKEN_EXPIRY_MINUTES', 60),
                           master_base_url=request.host_url.rstrip('/'), # Base URL of this master
                           backup_ssh_user=backup_ssh_user,
                           authorized_keys_path=authorized_keys_path
                           )


@main_bp.route('/clients/generate_token', methods=['POST'])
@login_required
def generate_client_token():
    """Generates a one-time registration token and returns the install command."""
    try:
        token = uuid.uuid4().hex + uuid.uuid4().hex[:16] # Longer token
        expiry = datetime.datetime.utcnow() + datetime.timedelta(minutes=current_app.config.get('REGISTRATION_TOKEN_EXPIRY_MINUTES', 60))

        # Store token temporarily (or associate with a placeholder client?)
        # For simplicity, let's just generate it. Master API will validate it.
        # Consider storing the token hash and expiry in DB for better validation.

        settings = Setting.query.first()
        if not settings:
            return jsonify(error="Master settings not configured."), 500

        master_url = request.host_url.rstrip('/')
        ssh_user = settings.backup_ssh_user

        # Construct the command
        # IMPORTANT: Ensure the URL points to the raw install.sh on GitHub main branch
        install_script_url = f"https://raw.githubusercontent.com/{current_app.config.get('GITHUB_REPO', 'k08255-lxm/simbak')}/main/install.sh"

        command = f"curl -sSL {install_script_url} | sudo bash -s -- --mode client --master-url {master_url} --token {token} --ssh-user {ssh_user}"

        current_app.logger.info(f"Generated registration token (expires {expiry})")
        # Return command and maybe authorized_keys path for instructions
        authorized_keys_path = f"~{ssh_user}/.ssh/authorized_keys"
        try:
            user_info = pwd.getpwnam(ssh_user)
            authorized_keys_path = os.path.join(user_info.pw_dir, '.ssh', 'authorized_keys')
        except KeyError: pass

        return jsonify(command=command, authorized_keys_path=authorized_keys_path)

    except Exception as e:
        current_app.logger.error(f"Error generating client token: {e}", exc_info=True)
        return jsonify(error=f"Failed to generate command: {e}"), 500


@main_bp.route('/clients/<int:client_id>')
@login_required
def client_detail(client_id):
    client = Client.query.get_or_404(client_id)
    settings = Setting.query.first() # Needed for SSH user info etc.
    # Get logs for this client, ordered by time desc
    logs = BackupLog.query.filter_by(client_id=client.id).order_by(desc(BackupLog.timestamp)).limit(100).all() # Limit initial load

    # Prepare forms (use separate forms for add/edit clarity if needed, or one form)
    form = BackupJobForm() # For adding/editing jobs
    restore_form = RestoreForm() # For initiating restore

    return render_template('client_detail.html',
                            client=client,
                            logs=logs,
                            form=form,
                            restore_form=restore_form,
                            settings=settings,
                            ClientStatus=ClientStatus,
                            BackupJobType=BackupJobType,
                            human_readable_size=human_readable_size # Pass filter to template context
                           )

@main_bp.route('/clients/<int:client_id>/delete', methods=['POST'])
@login_required
def delete_client(client_id):
    client = Client.query.get_or_404(client_id)
    client_name = client.name
    client_uuid = client.uuid # Get UUID before deletion
    settings = Setting.query.first()
    ssh_user = settings.backup_ssh_user if settings else None

    try:
        # Remove associated SSH key first (best effort)
        if ssh_user and client.ssh_public_key:
             if not remove_ssh_key_from_authorized(ssh_user, client_uuid):
                 flash(f"警告：无法从 authorized_keys 文件中自动移除客户端 '{client_name}' 的 SSH 公钥。您可能需要手动清理。", "warning")
             else:
                  current_app.logger.info(f"Removed SSH key for deleted client {client_name} ({client_uuid}) from user {ssh_user}'s authorized_keys.")

        # Delete client and cascaded jobs/logs/restore_jobs from DB
        db.session.delete(client)
        db.session.commit()
        flash(f"客户端 '{client_name}' 已成功删除。", "success")
        current_app.logger.info(f"Deleted client: {client_name} (ID: {client_id}, UUID: {client_uuid})")

        # Send notification?
        if settings:
             send_notification(
                 subject=f"客户端已删除: {client_name}",
                 recipient_email=settings.notification_email,
                 webhook_url=settings.notification_webhook_url,
                 text_body=f"管理员 '{current_user.username}' 删除了客户端 '{client_name}' (UUID: {client_uuid})."
             )

    except Exception as e:
        db.session.rollback()
        flash(f"删除客户端 '{client_name}' 时出错: {e}", "danger")
        current_app.logger.error(f"Error deleting client {client_name} (ID: {client_id}): {e}", exc_info=True)

    return redirect(url_for('main.list_clients'))


# --- Backup Job Routes ---

@main_bp.route('/clients/<int:client_id>/jobs/add', methods=['POST'])
@login_required
def add_backup_job(client_id):
    client = Client.query.get_or_404(client_id)
    form = BackupJobForm() # WTForms automatically gets data from request.form

    if form.validate_on_submit():
        try:
            new_job = BackupJob(client_id=client.id)
            # Populate job object from form data
            form.populate_obj(new_job) # Populates matching fields

            # Handle password encryption (only set if provided)
            if form.db_password.data:
                 # Encrypt password before saving (needs app context for SECRET_KEY)
                 new_job.db_password = form.db_password.data # Model handles encryption via EncryptedString type

            # Ensure retention is None if 0 was entered
            if new_job.retention_days == 0:
                 new_job.retention_days = None

            db.session.add(new_job)
            db.session.commit()
            flash(f"备份任务 '{new_job.name}' 已成功添加。", "success")
            current_app.logger.info(f"Added backup job '{new_job.name}' (ID: {new_job.id}) for client {client.name} (ID: {client.id})")

        except Exception as e:
            db.session.rollback()
            flash(f"添加备份任务时出错: {e}", "danger")
            current_app.logger.error(f"Error adding backup job for client {client.id}: {e}", exc_info=True)

    else:
        # Collect validation errors and flash them
        for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return redirect(url_for('main.client_detail', client_id=client_id))


@main_bp.route('/jobs/<int:job_id>/edit', methods=['POST'])
@login_required
def edit_backup_job(job_id):
    job = BackupJob.query.get_or_404(job_id)
    form = BackupJobForm(obj=job) # Load existing data into the form for editing

    # Preserve password if field is left blank during edit
    original_encrypted_password = job.db_password # This is already the encrypted value from DB

    if form.validate_on_submit():
        try:
            # Populate job object with updated data
            form.populate_obj(job)

            # Handle password: only update if a new password was entered
            if form.db_password.data:
                job.db_password = form.db_password.data # Model handles encryption
            else:
                # Restore original encrypted password if field was blank
                 job.db_password = original_encrypted_password

            # Ensure retention is None if 0 was entered
            if job.retention_days == 0:
                 job.retention_days = None

            db.session.commit()
            flash(f"备份任务 '{job.name}' 已成功更新。", "success")
            current_app.logger.info(f"Updated backup job '{job.name}' (ID: {job.id}) for client {job.client.name} (ID: {job.client_id})")

        except Exception as e:
            db.session.rollback()
            flash(f"更新备份任务时出错: {e}", "danger")
            current_app.logger.error(f"Error updating backup job {job.id}: {e}", exc_info=True)
    else:
        # Collect validation errors
         for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return redirect(url_for('main.client_detail', client_id=job.client_id))

@main_bp.route('/jobs/<int:job_id>/delete', methods=['POST'])
@login_required
def delete_backup_job(job_id):
    job = BackupJob.query.get_or_404(job_id)
    client_id = job.client_id
    job_name = job.name
    try:
        db.session.delete(job)
        db.session.commit()
        flash(f"备份任务 '{job_name}' 已成功删除。", "success")
        current_app.logger.info(f"Deleted backup job '{job_name}' (ID: {job_id}) for client ID {client_id}")
    except Exception as e:
        db.session.rollback()
        flash(f"删除备份任务时出错: {e}", "danger")
        current_app.logger.error(f"Error deleting backup job {job_id}: {e}", exc_info=True)

    return redirect(url_for('main.client_detail', client_id=client_id))


@main_bp.route('/jobs/<int:job_id>/data', methods=['GET'])
@login_required
def get_backup_job_data(job_id):
    """Endpoint to fetch job data for editing in modal."""
    job = BackupJob.query.get_or_404(job_id)
    # Convert job object to a dictionary suitable for JSON
    # Handle encrypted fields carefully - don't send password back!
    job_data = {
        'id': job.id,
        'name': job.name,
        'job_type': job.job_type.value, # Send enum value
        'source_path': job.source_path,
        'db_name': job.db_name,
        'db_user': job.db_user,
        # 'db_password': job.db_password, # DO NOT SEND PASSWORD BACK
        'db_host': job.db_host,
        'db_port': job.db_port,
        'target_subdirectory': job.target_subdirectory,
        'cron_schedule': job.cron_schedule,
        'bandwidth_limit_kbps': job.bandwidth_limit_kbps,
        'rsync_options': job.rsync_options,
        'pre_backup_script': job.pre_backup_script,
        'post_backup_script': job.post_backup_script,
        'enabled': job.enabled,
        'retention_days': job.retention_days # Send null if None?
    }
    return jsonify(job_data)

# --- File Browser / Restore Routes ---

@main_bp.route('/jobs/<int:job_id>/snapshots', methods=['GET'])
@login_required
def get_job_snapshots(job_id):
    """Returns a list of available backup snapshots for a job."""
    job = BackupJob.query.get_or_404(job_id)
    client = job.client
    settings = Setting.query.first()
    if not settings:
        return jsonify(error="Master settings not configured."), 500

    base_path = settings.backup_base_path
    job_path = job.get_target_path(base_path, client.uuid)

    snapshots = []
    has_latest = False
    error_msg = None

    try:
        if os.path.isdir(job_path):
            # List directories (snapshots) or files (DB dumps)
            items = os.listdir(job_path)
            # Filter for likely snapshot directories (e.g., YYYY-MM-DD_HH-MM-SS) or dump files
            # This logic needs refinement based on how snapshots/dumps are stored
            potential_snapshots = sorted([
                item for item in items
                if os.path.isdir(os.path.join(job_path, item)) or item.endswith(('.sql.gz', '.dump.gz')) # Basic check
                   and item != 'latest' # Exclude the symlink
            ], reverse=True) # Sort newest first

            snapshots = potential_snapshots # Use filtered list

            # Check if 'latest' symlink exists (relevant for dir backups using link-dest)
            if os.path.islink(os.path.join(job_path, 'latest')):
                 has_latest = True

        else:
            # If job path doesn't exist, maybe no backups yet or path error
            # Check logs for recent backups?
            log_exists = BackupLog.query.filter_by(job_id=job.id).first()
            if log_exists:
                 error_msg = f"备份目录不存在: {job_path}"
            else:
                 error_msg = "尚未执行备份"


    except OSError as e:
        current_app.logger.error(f"Error listing snapshots for job {job_id} in path '{job_path}': {e}")
        error_msg = f"读取备份目录时出错: {e}"
    except Exception as e:
         current_app.logger.error(f"Unexpected error getting snapshots for job {job_id}: {e}", exc_info=True)
         error_msg = f"获取快照列表时发生意外错误。"


    if error_msg:
        return jsonify(error=error_msg)
    else:
        return jsonify(snapshots=snapshots, has_latest=has_latest)


@main_bp.route('/clients/<int:client_id>/browse', methods=['GET'])
@login_required
def browse_files(client_id):
    """Endpoint for jsTree to fetch directory contents."""
    client = Client.query.get_or_404(client_id)
    settings = Setting.query.first()
    if not settings: return jsonify(error="Master settings missing"), 500

    job_id = request.args.get('job_id')
    snapshot = request.args.get('snapshot') # e.g., 'latest' or 'YYYY-MM-DD_HH-MM-SS'
    req_path = request.args.get('path', '/') # Relative path requested by jsTree

    if not job_id or not snapshot:
        return jsonify([{"id": "error", "text": "缺少 Job ID 或 Snapshot 参数", "icon": "fas fa-exclamation-triangle text-danger"}])

    job = BackupJob.query.get_or_404(job_id)
    if job.client_id != client.id: # Ensure job belongs to client
        abort(403)

    base_path = settings.backup_base_path
    job_base_path = job.get_target_path(base_path, client.uuid)

    # Resolve 'latest' symlink if used
    if snapshot == 'latest':
        latest_link_path = os.path.join(job_base_path, 'latest')
        if os.path.islink(latest_link_path):
            try:
                # Read the link and use the target directory name as the effective snapshot
                snapshot_dir_name = os.path.basename(os.readlink(latest_link_path))
                snapshot_path = os.path.join(job_base_path, snapshot_dir_name)
                current_app.logger.debug(f"Resolved 'latest' for job {job_id} to snapshot: {snapshot_dir_name}")
            except Exception as e:
                 current_app.logger.error(f"Error resolving 'latest' symlink '{latest_link_path}': {e}")
                 return jsonify([{"id": "error", "text": f"无法解析 'latest' 链接: {e}", "icon": "fas fa-exclamation-triangle text-danger"}])
        else:
             # Handle case where 'latest' is requested but doesn't exist (maybe first backup failed?)
             return jsonify([{"id": "error", "text": "'latest' 快照链接不存在", "icon": "fas fa-exclamation-triangle text-danger"}])
    else:
        # Use the specific snapshot directory/file name
        snapshot_path = os.path.join(job_base_path, snapshot)


    # --- Handle Database Dump Files ---
    # If the snapshot path points to a file (e.g., db dump), we can't browse inside it directly.
    # Return a single node representing the dump file.
    if os.path.isfile(snapshot_path) and snapshot.endswith(('.sql.gz', '.dump.gz')):
        try:
            stat_info = os.stat(snapshot_path)
            # Return a structure jsTree understands for a single file node
            return jsonify([{
                "id": snapshot, # Use filename as ID
                "text": snapshot,
                "icon": "fas fa-database text-primary", # DB icon
                 "data": {
                     "full_path": snapshot_path,
                     "relative_path": snapshot, # Relative to job base
                     "is_dir": False,
                     "size": stat_info.st_size,
                     "modified": datetime.datetime.fromtimestamp(stat_info.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                 },
                 "children": False # No children for a file
            }])
        except OSError as e:
             current_app.logger.error(f"Error accessing DB dump file '{snapshot_path}': {e}")
             return jsonify([{"id": "error", "text": f"无法访问数据库备份文件: {e}", "icon": "fas fa-exclamation-triangle text-danger"}])


    # --- Handle Directory Browsing ---
    # Calculate the absolute path to browse based on relative path request
    # IMPORTANT: Prevent path traversal attacks!
    base_browse_path = os.path.abspath(snapshot_path) # Get absolute path of the snapshot root
    requested_absolute_path = os.path.abspath(os.path.join(base_browse_path, req_path.lstrip('/')))

    # Security Check: Ensure the requested path is still within the snapshot directory
    if not is_safe_path(base_browse_path, requested_absolute_path):
        current_app.logger.warning(f"Path traversal attempt blocked: Base='{base_browse_path}', Requested='{requested_absolute_path}'")
        return jsonify([{"id": "error", "text": "禁止访问的路径", "icon": "fas fa-exclamation-triangle text-danger"}])

    if not os.path.isdir(requested_absolute_path):
         # Path might be invalid or point to a file when listing children
         # jsTree usually handles this, but good to check.
         current_app.logger.warning(f"Browse path not found or not a directory: {requested_absolute_path}")
         return jsonify([]) # Return empty list if path invalid


    # Get directory listing
    try:
        # Pass length of snapshot_path to calculate relative paths correctly inside list_directory_recursive
        directory_data = list_directory_recursive(requested_absolute_path, len(snapshot_path))
        return jsonify(directory_data)
    except Exception as e:
        current_app.logger.error(f"Error browsing directory '{requested_absolute_path}': {e}", exc_info=True)
        return jsonify([{"id": "error", "text": f"浏览目录时出错: {e}", "icon": "fas fa-exclamation-triangle text-danger"}])


@main_bp.route('/clients/<int:client_id>/restore', methods=['POST'])
@login_required
def restore_files(client_id):
    """Initiates a restore job."""
    client = Client.query.get_or_404(client_id)
    form = RestoreForm() # Gets data from request.form

    if form.validate_on_submit():
        job_id = form.job_id.data
        snapshot = form.snapshot.data
        target_path = form.target_path.data
        # source_items = [item.strip() for item in form.source_items.data.splitlines() if item.strip()]
        source_items = ['/'] # Restore all for now

        job = BackupJob.query.get_or_404(job_id)
        if job.client_id != client.id: abort(403) # Ensure job belongs to client

        try:
            # Create a RestoreJob record in the database
            restore_job = RestoreJob(
                client_id=client.id,
                backup_job_id=job.id,
                source_snapshot=snapshot,
                source_items=source_items,
                target_path=target_path,
                status=RestoreJobStatus.PENDING
            )
            db.session.add(restore_job)
            db.session.commit()

            flash(f"恢复任务已创建 (ID: {restore_job.id})。客户端代理将在下次检查时开始执行。", "success")
            current_app.logger.info(f"Restore job created (ID: {restore_job.id}) for client {client.name}, job {job.name}, snapshot {snapshot} to target {target_path}")

            # Send notification?
            settings = Setting.query.first()
            if settings:
                 send_notification(
                     subject=f"恢复任务已创建: {client.name}",
                     recipient_email=settings.notification_email,
                     webhook_url=settings.notification_webhook_url,
                     text_body=f"管理员 '{current_user.username}' 创建了一个恢复任务 (ID: {restore_job.id}) for client '{client.name}'.\n"
                               f"任务: {job.name}\n快照: {snapshot}\n目标路径: {target_path}",
                     context={'client': client, 'job': job, 'restore_job': restore_job}
                 )

        except Exception as e:
            db.session.rollback()
            flash(f"创建恢复任务时出错: {e}", "danger")
            current_app.logger.error(f"Error creating restore job for client {client.id}: {e}", exc_info=True)

    else:
         # Collect validation errors
         for field, errors in form.errors.items():
            for error in errors:
                flash(f"{getattr(form, field).label.text}: {error}", "danger")

    return redirect(url_for('main.client_detail', client_id=client_id))


# --- Settings and Logs ---

@main_bp.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    # Settings are stored as a single row in the Setting table
    current_settings = Setting.query.first()
    if not current_settings:
        # Should not happen after setup, but handle defensively
        flash("系统设置尚未初始化，请联系管理员。", "danger")
        return redirect(url_for('main.dashboard'))

    form = SettingsForm(obj=current_settings) # Load current settings into form

    # Preserve encrypted password if field is left blank
    original_smtp_password = current_settings.smtp_password

    if form.validate_on_submit():
        try:
            # Populate the settings object with form data
            form.populate_obj(current_settings)

            # Handle SMTP password: only update if provided
            if form.smtp_password.data:
                # The EncryptedString type handles encryption on assignment/commit
                 current_settings.smtp_password = form.smtp_password.data
            else:
                 current_settings.smtp_password = original_smtp_password # Keep old one if blank

            # Update Flask-Mail config dynamically if settings changed
            mail_config_changed = False
            app = current_app._get_current_object()
            if app.config.get('MAIL_SERVER') != current_settings.smtp_host: mail_config_changed = True; app.config['MAIL_SERVER'] = current_settings.smtp_host
            if app.config.get('MAIL_PORT') != current_settings.smtp_port: mail_config_changed = True; app.config['MAIL_PORT'] = current_settings.smtp_port
            if app.config.get('MAIL_USE_TLS') != current_settings.smtp_use_tls: mail_config_changed = True; app.config['MAIL_USE_TLS'] = current_settings.smtp_use_tls
            if app.config.get('MAIL_USERNAME') != current_settings.smtp_username: mail_config_changed = True; app.config['MAIL_USERNAME'] = current_settings.smtp_username
            # Password update requires re-init or careful handling - model stores encrypted, app needs raw if re-initing Mail
            if form.smtp_password.data: # If password changed, update app config (might require Mail re-init)
                 mail_config_changed = True
                 app.config['MAIL_PASSWORD'] = form.smtp_password.data # Use raw password here if Mail uses it directly


            db.session.commit()
            flash("系统设置已成功更新。", "success")
            current_app.logger.info(f"System settings updated by user '{current_user.username}'.")

            if mail_config_changed:
                 flash("SMTP 设置已更改。如果遇到邮件发送问题，可能需要重启应用以完全应用更改。", "info")
                 # Ideally, re-initialize Flask-Mail here if possible without restart

            return redirect(url_for('main.settings')) # Redirect to refresh page
        except Exception as e:
            db.session.rollback()
            flash(f"保存设置时出错: {e}", "danger")
            current_app.logger.error(f"Error saving settings: {e}", exc_info=True)

    # For GET request, pass the form already populated with current_settings
    return render_template('settings.html', form=form)


@main_bp.route('/settings/change_password', methods=['GET', 'POST'])
@login_required
def change_password():
    form = ChangePasswordForm()
    if form.validate_on_submit():
        user = current_user._get_current_object() # Get the actual User object
        if user.check_password(form.current_password.data):
            user.set_password(form.new_password.data) # Hashes the new password
            db.session.commit()
            flash("密码已成功更改。", "success")
            current_app.logger.info(f"Password changed for user '{user.username}'.")
            # Log user out after password change? Or keep logged in? Let's keep logged in.
            return redirect(url_for('main.settings')) # Redirect back to settings or dashboard
        else:
            flash("当前密码不正确。", "danger")
    return render_template('change_password.html', form=form) # Need this template


@main_bp.route('/logs')
@login_required
def view_logs():
    page = request.args.get('page', 1, type=int)
    per_page = 50 # Number of logs per page

    # Add filtering options later (client, job, level, date)
    log_query = BackupLog.query.order_by(desc(BackupLog.timestamp))

    logs_pagination = log_query.paginate(page=page, per_page=per_page, error_out=False)
    logs = logs_pagination.items

    return render_template('logs.html',
                            logs=logs,
                            pagination=logs_pagination,
                            human_readable_size=human_readable_size # Pass filter
                           ) # Need this template
