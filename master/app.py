import os
import datetime
import uuid
import logging
from logging.handlers import RotatingFileHandler
import secrets
import subprocess
import json

from flask import (Flask, render_template, request, redirect, url_for, flash,
                   jsonify, abort, send_from_directory, Response, stream_with_context)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (LoginManager, UserMixin, login_user, logout_user,
                       login_required, current_user)
from flask_wtf import FlaskForm
from flask_wtf.csrf import CSRFProtect
from wtforms import (StringField, PasswordField, SubmitField, BooleanField,
                   TextAreaField, SelectField, IntegerField, HiddenField)
from wtforms.validators import DataRequired, Length, EqualTo, Optional, Email, URL, NumberRange, Regexp
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.exceptions import HTTPException
from flask_migrate import Migrate
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from croniter import croniter # To validate cron strings
import bleach # For sanitizing user input / file browser output

# Import models and utils AFTER db is defined below
# from .models import db, User, Setting, Client, BackupJob, BackupLog, RestoreJob, ClientStatus, BackupJobType, RestoreJobStatus
# from .utils.security import generate_api_key, verify_api_key, encrypt_data, decrypt_data
# from .utils.notifications import send_notification

# Initialize extensions without app context first
db = SQLAlchemy()
login_manager = LoginManager()
csrf = CSRFProtect()
migrate = Migrate()
scheduler = BackgroundScheduler(daemon=True, timezone='UTC') # Use UTC for scheduling

# Import models and utils now that db is an object
from .models import (User, Setting, Client, BackupJob, BackupLog, RestoreJob,
                    ClientStatus, BackupJobType, RestoreJobStatus)
from .utils.security import (generate_api_key, hash_api_key, verify_api_key,
                           encrypt_data, decrypt_data)
from .utils.notifications import send_notification


# --- Configuration ---
class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or secrets.token_hex(32) # MUST be set securely in production
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Default SQLite path in instance folder
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or \
        'sqlite:///' + os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance', 'simbak.db')
    # Ensure instance folder exists
    INSTANCE_FOLDER_PATH = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'instance')
    os.makedirs(INSTANCE_FOLDER_PATH, exist_ok=True)

    # Flask-Mail configuration (defaults, should be in instance/production.cfg or env vars)
    MAIL_SERVER = os.environ.get('MAIL_SERVER')
    MAIL_PORT = int(os.environ.get('MAIL_PORT', 587))
    MAIL_USE_TLS = os.environ.get('MAIL_USE_TLS', 'true').lower() in ['true', '1', 't']
    MAIL_USE_SSL = os.environ.get('MAIL_USE_SSL', 'false').lower() in ['true', '1', 't']
    MAIL_USERNAME = os.environ.get('MAIL_USERNAME')
    MAIL_PASSWORD = os.environ.get('MAIL_PASSWORD') # Store encrypted in DB ideally
    MAIL_DEFAULT_SENDER = os.environ.get('MAIL_DEFAULT_SENDER', 'Simbak <noreply@yourdomain.com>') # Change this

    # Simbak Specific Config (can be overridden by DB settings)
    BACKUP_BASE_PATH = '/opt/simbak/backups'
    BACKUP_SSH_USER = 'simbak'
    DEFAULT_RETENTION_DAYS = 30
    REGISTRATION_TOKEN_EXPIRY_MINUTES = 60

    # Logging
    LOG_FILE = os.path.join(INSTANCE_FOLDER_PATH, 'simbak_master.log')
    LOG_LEVEL = logging.INFO # DEBUG, INFO, WARNING, ERROR, CRITICAL

class ProductionConfig(Config):
    # Production specific settings
    FLASK_ENV = 'production'
    # Ensure SECRET_KEY is definitely set from environment in production
    SECRET_KEY = os.environ.get('SECRET_KEY')
    if not SECRET_KEY:
        raise ValueError("No SECRET_KEY set for Flask application in production environment!")
    # Configure logging for production
    LOG_LEVEL = logging.INFO

class DevelopmentConfig(Config):
    DEBUG = True
    FLASK_ENV = 'development'
    SQLALCHEMY_ECHO = False # Set to True to see SQL queries
    LOG_LEVEL = logging.DEBUG


config_by_name = dict(
    development=DevelopmentConfig,
    production=ProductionConfig,
    default=DevelopmentConfig
)

# --- Forms ---

class LoginForm(FlaskForm):
    username = StringField('用户名', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('密码', validators=[DataRequired()])
    submit = SubmitField('登录')

class SetupForm(FlaskForm):
    username = StringField('管理员用户名', validators=[DataRequired(), Length(min=3, max=80)])
    password = PasswordField('管理员密码', validators=[DataRequired(), Length(min=8)])
    confirm_password = PasswordField('确认密码', validators=[DataRequired(), EqualTo('password', message='密码必须匹配')])
    backup_base_path = StringField('备份存储根路径', default=Config.BACKUP_BASE_PATH, validators=[DataRequired()])
    backup_ssh_user = StringField('备份 SSH 用户名', default=Config.BACKUP_SSH_USER, validators=[DataRequired()])
    submit = SubmitField('完成设置')

class SettingsForm(FlaskForm):
    backup_base_path = StringField('备份存储根路径', validators=[DataRequired()])
    backup_ssh_user = StringField('备份 SSH 用户名', validators=[DataRequired()])
    notification_email = StringField('通知邮箱', [Optional(), Email()])
    notification_webhook_url = StringField('通知 Webhook URL', [Optional(), URL()])
    smtp_host = StringField('SMTP 主机')
    smtp_port = IntegerField('SMTP 端口', [Optional(), NumberRange(min=1, max=65535)])
    smtp_use_tls = BooleanField('使用 TLS')
    smtp_username = StringField('SMTP 用户名')
    smtp_password = PasswordField('SMTP 密码 (仅在需要更改时填写)') # Not required, only for update
    default_retention_days = IntegerField('默认备份保留天数', [DataRequired(), NumberRange(min=1)], default=Config.DEFAULT_RETENTION_DAYS)
    submit = SubmitField('保存设置')

class ChangePasswordForm(FlaskForm):
    current_password = PasswordField('当前密码', validators=[DataRequired()])
    new_password = PasswordField('新密码', validators=[DataRequired(), Length(min=8)])
    confirm_new_password = PasswordField('确认新密码', validators=[DataRequired(), EqualTo('new_password', message='新密码必须匹配')])
    submit = SubmitField('更改密码')


class ClientForm(FlaskForm):
    # Usually clients register themselves, but allow manual add/edit? Maybe just edit name?
    name = StringField('客户端名称', validators=[DataRequired(), Length(max=100)])
    submit = SubmitField('保存更改')


# Cron Validator
def validate_cron(form, field):
    try:
        if not croniter.is_valid(field.data):
            raise ValueError("无效的 Cron 表达式格式。")
        # Optional: Check frequency? (e.g., prevent every second?)
    except Exception as e:
        raise ValueError(f"Cron 表达式验证失败: {e}")

class BackupJobForm(FlaskForm):
    name = StringField('任务名称', validators=[DataRequired(), Length(max=100)])
    job_type = SelectField('任务类型', choices=[(t.value, t.name.title()) for t in BackupJobType], validators=[DataRequired()])
    source_path = StringField('源路径 (用于目录类型)', validators=[Optional()]) # Make required based on type in route
    db_name = StringField('数据库名 (用于数据库类型)', validators=[Optional()])
    db_user = StringField('数据库用户名', validators=[Optional()])
    db_password = PasswordField('数据库密码 (仅在需要设置或更改时填写)') # Not required, only for update
    db_host = StringField('数据库主机', default='localhost', validators=[Optional()])
    db_port = IntegerField('数据库端口', validators=[Optional(), NumberRange(min=1, max=65535)])
    target_subdirectory = StringField('目标子目录 (可选, 留空自动生成)', validators=[Optional(), Regexp(r'^[a-zA-Z0-9_\-\/]*$', message="只允许字母、数字、下划线、连字符和斜杠")])
    cron_schedule = StringField('Cron 调度计划 (例如 "0 2 * * *")', default="0 2 * * *", validators=[DataRequired(), validate_cron])
    bandwidth_limit_kbps = IntegerField('带宽限制 (KB/s, 0=无限制)', default=0, validators=[Optional(), NumberRange(min=0)])
    rsync_options = StringField('附加 Rsync 选项', validators=[Optional()])
    pre_backup_script = TextAreaField('备份前执行脚本 (在客户端)', validators=[Optional()])
    post_backup_script = TextAreaField('备份后执行脚本 (在客户端)', validators=[Optional()])
    enabled = BooleanField('启用任务', default=True)
    retention_days = IntegerField('保留天数 (0=使用全局默认)', default=0, validators=[Optional(), NumberRange(min=0)])
    # retention_count = IntegerField('保留数量 (0=不限制)', default=0, validators=[Optional(), NumberRange(min=0)]) # Add later if needed
    client_id = HiddenField() # To associate with the client
    submit = SubmitField('保存任务')

    # Add custom validation based on type
    def validate(self, extra_validators=None):
        if not super().validate(extra_validators):
            return False
        if self.job_type.data == BackupJobType.DIRECTORY.value:
            if not self.source_path.data:
                self.source_path.errors.append("目录备份类型需要源路径。")
                return False
        elif self.job_type.data in [BackupJobType.MYSQL.value, BackupJobType.POSTGRESQL.value]:
            if not self.db_name.data:
                self.db_name.errors.append("数据库备份类型需要数据库名。")
                return False
            # User/Pass might be optional if using socket auth etc. but good defaults
            if not self.db_user.data:
                # Check if it's an existing job being edited without password change
                is_editing = hasattr(self, '_obj') and self._obj and self._obj.id
                if not is_editing or not self._obj.db_user: # Require user if new or previously unset
                     self.db_user.errors.append("数据库备份类型通常需要用户名。")
                     # return False # Be lenient maybe?

        return True

class RestoreForm(FlaskForm):
    snapshot = SelectField('选择备份快照', choices=[], validators=[DataRequired()]) # Choices populated dynamically
    # For simplicity, restore everything from snapshot first. Add item selection later.
    # source_items = TextAreaField('要恢复的相对路径 (每行一个, 留空恢复所有)', default='/', validators=[Optional()])
    target_path = StringField('恢复到客户端的目标绝对路径', validators=[DataRequired()])
    client_id = HiddenField()
    job_id = HiddenField()
    submit = SubmitField('开始恢复')


# --- Application Factory ---
def create_app(config_name='production'):
    app = Flask(__name__, instance_relative_config=True)

    # Load config: default, then from file, then env vars override?
    # Using instance_relative_config=True looks for config.py in instance folder
    # Let's prioritize environment variables, then instance file, then defaults
    app_config = config_by_name.get(config_name, ProductionConfig) # Get base config class
    app.config.from_object(app_config) # Load defaults from class

    # Try loading config from instance/production.cfg (use a .py file for flexibility)
    # For simplicity, let's assume important things like SECRET_KEY are ENV VARS for production.
    # We can load MAIL settings etc. from DB later.
    # config_py = os.path.join(app.instance_path, 'production.cfg') # Treat as python file
    # try:
    #     app.config.from_pyfile(config_py)
    #     print(f"Loaded config from {config_py}")
    # except FileNotFoundError:
    #     print(f"Instance config file not found at {config_py}, using defaults/env vars.")
    # except Exception as e:
    #      print(f"Error loading instance config file {config_py}: {e}")

    # Ensure SECRET_KEY is set, especially for production
    if app.config['ENV'] == 'production' and not app.config.get('SECRET_KEY'):
         raise ValueError("PRODUCTION ERROR: SECRET_KEY is not set. Set the SECRET_KEY environment variable.")
    elif not app.config.get('SECRET_KEY'):
         print("WARNING: SECRET_KEY is not set. Using a temporary one. SET a permanent SECRET_KEY environment variable.")
         app.config['SECRET_KEY'] = secrets.token_hex(32) # Generate temp key if missing in dev


    # Setup Logging
    configure_logging(app)
    app.logger.info(f"Starting Simbak Master in {app.config['ENV']} mode.")
    app.logger.info(f"Database URI: {app.config['SQLALCHEMY_DATABASE_URI']}")


    # Initialize extensions
    db.init_app(app)
    csrf.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login' # Route name for the login page
    login_manager.login_message = "请登录以访问此页面。"
    login_manager.login_message_category = "info"
    migrate.init_app(app, db)

    # Initialize Flask-Mail if configured
    if app.config.get('MAIL_SERVER'):
        try:
            from flask_mail import Mail
            mail = Mail(app)
            app.extensions['mail'] = mail # Store for access in utils
            app.logger.info(f"Flask-Mail initialized for server {app.config['MAIL_SERVER']}:{app.config['MAIL_PORT']}")
        except ImportError:
            app.logger.warning("Flask-Mail configuration found but package not installed. Email notifications disabled.")
        except Exception as e:
            app.logger.error(f"Failed to initialize Flask-Mail: {e}")


    with app.app_context():
        # Create database tables if they don't exist (or use migrations)
        # db.create_all() # Prefer using `flask db upgrade`

        # Initialize scheduler only once
        if not scheduler.running:
            # Add background jobs
            # 1. Retention policy job (runs daily?)
            scheduler.add_job(
                func=run_retention_policy,
                trigger=CronTrigger(hour=3, minute=30), # Run daily at 3:30 AM UTC
                id='retention_policy_job',
                name='Delete old backups based on retention policy',
                replace_existing=True,
                misfire_grace_time=3600 # Allow 1 hour delay if missed
            )
            # 2. Check for offline clients (runs every 5 minutes?)
            scheduler.add_job(
                 func=check_offline_clients,
                 trigger='interval',
                 minutes=5,
                 id='offline_client_check_job',
                 name='Check for clients that missed heartbeat',
                 replace_existing=True
            )

            scheduler.start()
            app.logger.info("Background scheduler started.")
            # Make scheduler accessible
            app.scheduler = scheduler


    # --- Login Manager User Loader ---
    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    # --- Blueprints / Routes ---

    # Authentication Routes
    from .auth import auth_bp # Use a separate file for auth routes
    app.register_blueprint(auth_bp)

    # Main Application Routes (Dashboard, Clients, Settings etc.)
    from .main_routes import main_bp # Use a separate file for main app routes
    app.register_blueprint(main_bp)

    # API Routes (for clients)
    from .api_routes import api_bp # Use a separate file for API routes
    app.register_blueprint(api_bp, url_prefix='/api')


    # --- Global Error Handlers ---
    @app.errorhandler(404)
    def page_not_found(e):
        app.logger.warning(f"404 Not Found: {request.path}")
        return render_template('errors/404.html'), 404

    @app.errorhandler(500)
    def internal_server_error(e):
        app.logger.error(f"500 Internal Server Error: {e}", exc_info=True)
        # Don't leak detailed errors in production
        message = "服务器内部错误，请稍后重试或联系管理员。"
        # Send notification on critical errors?
        settings = Setting.query.first()
        if settings:
             send_notification(
                 subject="Simbak Master Internal Error",
                 recipient_email=settings.notification_email,
                 webhook_url=settings.notification_webhook_url,
                 text_body=f"An internal server error occurred: {e}\nRequest path: {request.path}"
             )
        return render_template('errors/500.html', message=message), 500

    @app.errorhandler(403)
    def forbidden(e):
        app.logger.warning(f"403 Forbidden: Access denied for {request.path}")
        return render_template('errors/403.html'), 403

    @app.errorhandler(401) # Sometimes useful for API errors if not handled by API handlers
    def unauthorized(e):
         app.logger.warning(f"401 Unauthorized: {request.path}")
         # If API request, return JSON
         if request.path.startswith('/api/'):
             return jsonify(error="Unauthorized", message="Valid API key required"), 401
         # Otherwise redirect to login for web UI
         flash("需要认证才能访问。", "warning")
         return redirect(url_for('auth.login', next=request.url))

    @app.errorhandler(HTTPException) # Generic handler for other HTTP errors
    def handle_http_exception(e):
        app.logger.warning(f"HTTP Exception {e.code}: {e.name} - {e.description} for {request.path}")
        # Render a generic error page or specific ones based on e.code
        return render_template('errors/generic.html', error=e), e.code


    # --- Template Context Processors ---
    @app.context_processor
    def inject_global_vars():
        # Inject things needed in most templates
        return dict(
            app_version="0.1.0", # Get from a file or config?
            current_year=datetime.datetime.utcnow().year
        )

    return app


# --- Logging Configuration ---
def configure_logging(app):
    # Remove default Flask handler
    # from flask.logging import default_handler
    # app.logger.removeHandler(default_handler) # Be careful if other extensions rely on it

    log_level = app.config.get('LOG_LEVEL', logging.INFO)
    log_file = app.config.get('LOG_FILE')

    formatter = logging.Formatter('%(asctime)s [%(levelname)s] [%(name)s] %(message)s (%(pathname)s:%(lineno)d)')

    # File Handler (Rotating)
    if log_file:
        file_handler = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5) # 10MB per file, 5 backups
        file_handler.setFormatter(formatter)
        file_handler.setLevel(log_level)
        app.logger.addHandler(file_handler)

    # Console Handler (useful for development and container logs)
    # Gunicorn/Waitress often handle stdout/stderr, so maybe only add in dev?
    # Or always add it but let the WSGI server manage output.
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(formatter)
    stream_handler.setLevel(log_level)
    if not any(isinstance(h, logging.StreamHandler) for h in app.logger.handlers):
         app.logger.addHandler(stream_handler)

    app.logger.setLevel(log_level)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING) # Quieten SQLAlchemy logs unless debugging
    logging.getLogger('apscheduler').setLevel(logging.INFO) # Keep scheduler logs reasonable

    app.logger.info(f"Logging configured. Level: {logging.getLevelName(log_level)}. File: {log_file}")


# --- Background Task Functions ---
def run_retention_policy():
    """Background job to delete old backups based on job/global retention policies."""
    app = Flask(__name__) # Create a dummy app to get context
    # This is tricky when run outside request context. A better way is needed.
    # Option 1: Pass the app instance to the scheduler setup.
    # Option 2: Use Flask-APScheduler extension which handles context better.
    # Option 3: Re-create app context here. (Simplest for now, but less efficient)

    # Let's assume the app context is managed correctly by Flask-APScheduler or similar
    # If using raw APScheduler, we need to push context manually.
    # The `create_app` function now stores scheduler on app, let's try to get app context.
    # This needs Flask-APScheduler or a better setup.

    # --- TEMPORARY WORKAROUND for running outside request ---
    # This assumes create_app was called and configured the main app.
    # It's fragile. Flask-APScheduler is recommended.
    try:
        # Attempt to get the current app if possible (e.g., if using Flask-APScheduler)
        from flask import current_app as scheduler_app
        if not scheduler_app:
             raise RuntimeError("No app context")
        _app = scheduler_app

    except RuntimeError:
         # Fallback: create a temporary app instance JUST for this task
         # This requires the configuration (especially DB URI and SECRET_KEY) to be readable
         # e.g., from environment variables.
         print("Retention job running outside request context, creating temporary app.")
         temp_app_config_name = os.getenv('FLASK_CONFIG', 'production')
         _app = create_app(config_name=temp_app_config_name) # Recreate app (inefficient)


    with _app.app_context():
        _app.logger.info("Running retention policy job...")
        settings = Setting.query.first()
        if not settings:
            _app.logger.warning("Retention policy: Cannot run, settings not found in DB.")
            return

        base_path = settings.backup_base_path
        global_retention_days = settings.default_retention_days
        now = datetime.datetime.utcnow()

        if not os.path.isdir(base_path):
            _app.logger.warning(f"Retention policy: Base backup path '{base_path}' does not exist.")
            return

        clients = Client.query.filter(Client.status != ClientStatus.UNKNOWN).all() # Process active/known clients
        for client in clients:
            client_backup_path = os.path.join(base_path, client.uuid)
            if not os.path.isdir(client_backup_path):
                continue

            jobs = BackupJob.query.filter_by(client_id=client.id).all()
            for job in jobs:
                job_path = job.get_target_path(base_path, client.uuid)
                if not os.path.isdir(job_path):
                    continue

                retention_days = job.retention_days if job.retention_days is not None and job.retention_days > 0 else global_retention_days

                if retention_days <= 0:
                    _app.logger.debug(f"Retention policy: Skipping job '{job.name}' for client '{client.name}' (retention <= 0).")
                    continue

                cutoff_date = now - datetime.timedelta(days=retention_days)
                _app.logger.debug(f"Retention policy: Checking job '{job.name}' (Client: {client.name}) in '{job_path}'. Keeping backups newer than {cutoff_date} ({retention_days} days).")

                deleted_count = 0
                try:
                    # Assuming backups are stored in timestamped directories like YYYY-MM-DD_HH-MM-SS
                    # List directories, parse timestamp, compare with cutoff
                    for item_name in os.listdir(job_path):
                        item_path = os.path.join(job_path, item_name)
                        if os.path.isdir(item_path): # Only consider directories as snapshots
                            try:
                                # Attempt to parse common timestamp formats
                                snapshot_time = None
                                formats_to_try = [
                                    "%Y-%m-%d_%H-%M-%S",
                                    "%Y%m%d_%H%M%S",
                                    "%Y-%m-%d-%H%M%S"
                                ]
                                for fmt in formats_to_try:
                                    try:
                                        snapshot_time = datetime.datetime.strptime(item_name, fmt)
                                        break # Success
                                    except ValueError:
                                        continue # Try next format

                                if snapshot_time and snapshot_time < cutoff_date:
                                    _app.logger.info(f"Retention policy: Deleting old backup snapshot '{item_path}' (older than {cutoff_date}).")
                                    # Use shutil.rmtree for directories
                                    import shutil
                                    shutil.rmtree(item_path)
                                    deleted_count += 1
                                elif not snapshot_time:
                                     _app.logger.warning(f"Retention policy: Could not parse timestamp from directory name '{item_name}' in '{job_path}'. Skipping.")

                            except Exception as parse_err:
                                _app.logger.error(f"Retention policy: Error processing item '{item_path}': {parse_err}")

                    if deleted_count > 0:
                         _app.logger.info(f"Retention policy: Deleted {deleted_count} old snapshots for job '{job.name}' (Client: {client.name}).")

                except OSError as e:
                    _app.logger.error(f"Retention policy: Error accessing job path '{job_path}': {e}")
                except Exception as e:
                    _app.logger.error(f"Retention policy: Unexpected error processing job '{job.name}' for client '{client.name}': {e}", exc_info=True)

        _app.logger.info("Retention policy job finished.")


def check_offline_clients():
    """Background job to mark clients as offline if they haven't sent a heartbeat recently."""
     # Similar context issue as run_retention_policy, needs proper handling
    try:
        from flask import current_app as scheduler_app
        if not scheduler_app: raise RuntimeError("No app context")
        _app = scheduler_app
    except RuntimeError:
         print("Offline check running outside request context, creating temporary app.")
         temp_app_config_name = os.getenv('FLASK_CONFIG', 'production')
         _app = create_app(config_name=temp_app_config_name) # Recreate app

    with _app.app_context():
        _app.logger.debug("Running offline client check...")
        offline_threshold_minutes = 10 # Consider client offline if no heartbeat for 10 mins
        offline_cutoff = datetime.datetime.utcnow() - datetime.timedelta(minutes=offline_threshold_minutes)

        clients_to_check = Client.query.filter(Client.status == ClientStatus.ONLINE).all()
        settings = Setting.query.first() # For notifications

        for client in clients_to_check:
            if client.last_heartbeat is None or client.last_heartbeat < offline_cutoff:
                _app.logger.warning(f"Client '{client.name}' (UUID: {client.uuid}) appears offline. Last heartbeat: {client.last_heartbeat or 'Never'}. Threshold: {offline_cutoff}")
                client.status = ClientStatus.OFFLINE
                db.session.add(client)

                # Send notification
                if settings:
                     send_notification(
                         subject=f"Client Offline: {client.name}",
                         recipient_email=settings.notification_email,
                         webhook_url=settings.notification_webhook_url,
                         text_body=f"Client '{client.name}' (Hostname: {client.hostname or 'N/A'}) has gone offline. Last heartbeat was at {client.last_heartbeat or 'Never'}.",
                         # template='notifications/client_offline', # Optional template
                         context={'client': client, 'offline_cutoff': offline_cutoff}
                     )

        try:
            db.session.commit()
        except Exception as e:
            db.session.rollback()
            _app.logger.error(f"Error committing offline status changes: {e}", exc_info=True)

        _app.logger.debug("Offline client check finished.")


# --- Helper Functions ---

def is_safe_path(base, path, follow_symlinks=True):
    """Check if the combined path is safely within the base directory."""
    # resolves symbolic links
    if follow_symlinks:
        matchpath = os.path.realpath(path)
    else:
        matchpath = os.path.abspath(path)
    return base == os.path.commonpath((base, matchpath))


def list_directory_recursive(path, base_path_len):
    """Recursively list directory contents, suitable for JSON tree."""
    tree = []
    try:
        for entry in os.scandir(path):
            # Relative path for display and ID
            rel_path = entry.path[base_path_len:].lstrip(os.sep)
            # Sanitize path for use in HTML IDs etc. Replace problematic chars.
            safe_id_path = bleach.clean(rel_path.replace(os.sep, '_').replace('.', '_dot_'), tags=[], strip=True)

            node = {
                "id": safe_id_path, # ID for jsTree
                "text": entry.name, # Display name
                "data": { # Custom data payload
                    "full_path": entry.path,
                     "relative_path": rel_path,
                     "is_dir": entry.is_dir(),
                     "size": entry.stat().st_size if entry.is_file() else None,
                     "modified": datetime.datetime.fromtimestamp(entry.stat().st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                 }
            }
            if entry.is_dir():
                node["icon"] = "fas fa-folder text-warning" # FontAwesome folder icon
                # node["children"] = list_directory_recursive(entry.path, base_path_len) # Load children recursively (can be slow!)
                # For large directories, load children on demand (jsTree AJAX)
                node["children"] = True # Tell jstree this node has children to load via AJAX
                node["a_attr"] = {"href": "#", "class": "folder-link"} # Prevent default link action
            else:
                node["icon"] = "fas fa-file text-secondary" # FontAwesome file icon
                node["a_attr"] = {"href": "#", "class": "file-link"}

            tree.append(node)
        # Sort by type (folders first), then name
        tree.sort(key=lambda x: (not x['data']['is_dir'], x['text'].lower()))
    except FileNotFoundError:
        return [] # Return empty list if path doesn't exist
    except OSError as e:
        current_app.logger.error(f"Error listing directory '{path}': {e}")
        return [{"id": "error", "text": f"Error reading directory: {e}", "icon": "fas fa-exclamation-triangle text-danger"}]
    return tree

def add_ssh_key_to_authorized(ssh_user, public_key, client_uuid, client_ip=None):
    """Safely adds a public key to the specified user's authorized_keys file."""
    app = current_app # Need app context for logger
    try:
        user_info = pwd.getpwnam(ssh_user)
        home_dir = user_info.pw_dir
        ssh_dir = os.path.join(home_dir, '.ssh')
        auth_keys_file = os.path.join(ssh_dir, 'authorized_keys')

        # Ensure .ssh directory exists and has correct permissions
        if not os.path.exists(ssh_dir):
            os.makedirs(ssh_dir, mode=0o700)
            os.chown(ssh_dir, user_info.pw_uid, user_info.pw_gid)
        elif os.stat(ssh_dir).st_mode & 0o777 != 0o700:
             app.logger.warning(f"Correcting permissions for {ssh_dir} to 700")
             os.chmod(ssh_dir, 0o700)

        # Prepare key entry with restrictions
        # Restrict to specific client UUID and potentially IP
        # Use a comment to identify the key easily
        key_comment = f"simbak_client_{client_uuid}"
        # Restrictions: prevent port forwarding, X11 forwarding, agent forwarding, PTY allocation
        # Force a specific command (rsync server mode) if possible (more complex to set up reliably across versions)
        # from="ip_address" is another good restriction if IP is static
        restrictions = f'no-port-forwarding,no-X11-forwarding,no-agent-forwarding,no-pty'
        # Command restriction (use with caution, ensure it works with your rsync version):
        # command="/path/to/rsync --server --sender -vlogDtpre.iLsfxC . /" # Example, needs careful crafting
        # For simplicity, let's start without command restriction, relying on backup dir permissions.
        key_line = f"{restrictions} {public_key.strip()} {key_comment}\n"


        # File locking to prevent race conditions if multiple clients register at once
        lock_file_path = auth_keys_file + ".lock"
        try:
            # Use a simple file lock mechanism
            lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(lock_fd) # Just created it, now we own the lock

            # Read existing keys, check if key already exists
            existing_keys = set()
            if os.path.exists(auth_keys_file):
                 # Ensure file permissions are correct
                 if os.stat(auth_keys_file).st_mode & 0o777 != 0o600:
                     app.logger.warning(f"Correcting permissions for {auth_keys_file} to 600")
                     os.chmod(auth_keys_file, 0o600)
                 # Ensure ownership is correct
                 if os.stat(auth_keys_file).st_uid != user_info.pw_uid or os.stat(auth_keys_file).st_gid != user_info.pw_gid:
                     app.logger.warning(f"Correcting ownership for {auth_keys_file} to {ssh_user}")
                     os.chown(auth_keys_file, user_info.pw_uid, user_info.pw_gid)

                 with open(auth_keys_file, 'r') as f:
                     for line in f:
                         # Normalize whitespace and ignore comments/empty lines
                         parts = line.strip().split()
                         if len(parts) >= 2 and not parts[0].startswith('#'):
                             existing_keys.add(parts[1]) # Add the key part for comparison

            # Check if the key part itself is already present
            new_key_part = public_key.strip().split()[1] if len(public_key.strip().split()) > 1 else None
            if new_key_part and new_key_part in existing_keys:
                app.logger.info(f"SSH Public key for client {client_uuid} already exists in {auth_keys_file}.")
                # Optionally update restrictions or comment here if needed
                return True # Key already present

            # Append the new key line
            with open(auth_keys_file, 'a') as f:
                f.write(key_line)

            # Set correct permissions and ownership for the authorized_keys file
            os.chmod(auth_keys_file, 0o600)
            os.chown(auth_keys_file, user_info.pw_uid, user_info.pw_gid)
            app.logger.info(f"Successfully added SSH key for client {client_uuid} to {auth_keys_file}")
            return True

        except FileExistsError:
             app.logger.warning(f"Could not acquire lock for {auth_keys_file}. Another process might be modifying it. Retrying later might be needed.")
             # Implement retry logic if necessary
             return False
        except Exception as e:
            app.logger.error(f"Error adding SSH key to {auth_keys_file}: {e}", exc_info=True)
            return False
        finally:
            # Ensure lock file is removed
            if os.path.exists(lock_file_path):
                try:
                    os.remove(lock_file_path)
                except OSError as e:
                     app.logger.error(f"Error removing lock file {lock_file_path}: {e}")


    except KeyError:
        app.logger.error(f"SSH user '{ssh_user}' not found on the system.")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error during SSH key management for user '{ssh_user}': {e}", exc_info=True)
        return False
    finally:
         # Clean up lock file just in case it was left by error before finally block
        lock_file_path = os.path.join(pwd.getpwnam(ssh_user).pw_dir, '.ssh', 'authorized_keys.lock')
        if os.path.exists(lock_file_path):
            try:
                os.remove(lock_file_path)
            except OSError: pass # Ignore error if removal fails here

def remove_ssh_key_from_authorized(ssh_user, client_uuid):
    """Removes an SSH key identified by its comment from authorized_keys."""
    app = current_app
    try:
        user_info = pwd.getpwnam(ssh_user)
        home_dir = user_info.pw_dir
        ssh_dir = os.path.join(home_dir, '.ssh')
        auth_keys_file = os.path.join(ssh_dir, 'authorized_keys')
        key_comment = f"simbak_client_{client_uuid}"

        if not os.path.exists(auth_keys_file):
            app.logger.warning(f"Cannot remove key for {client_uuid}: {auth_keys_file} does not exist.")
            return True # Nothing to remove

        lock_file_path = auth_keys_file + ".lock"
        new_content = []
        removed = False

        try:
            lock_fd = os.open(lock_file_path, os.O_CREAT | os.O_EXCL | os.O_WRONLY)
            os.close(lock_fd)

            with open(auth_keys_file, 'r') as f:
                for line in f:
                    if line.strip().endswith(key_comment):
                        removed = True
                        app.logger.info(f"Removing SSH key for client {client_uuid} from {auth_keys_file}.")
                    else:
                        new_content.append(line)

            if removed:
                with open(auth_keys_file, 'w') as f:
                    f.writelines(new_content)
                os.chmod(auth_keys_file, 0o600)
                os.chown(auth_keys_file, user_info.pw_uid, user_info.pw_gid)
                app.logger.info(f"Successfully removed SSH key for client {client_uuid}.")
            else:
                 app.logger.info(f"SSH key for client {client_uuid} not found in {auth_keys_file}. No changes made.")

            return True

        except FileExistsError:
             app.logger.warning(f"Could not acquire lock for {auth_keys_file} during key removal. Retrying later might be needed.")
             return False
        except Exception as e:
            app.logger.error(f"Error removing SSH key from {auth_keys_file}: {e}", exc_info=True)
            return False
        finally:
            if os.path.exists(lock_file_path):
                try:
                    os.remove(lock_file_path)
                except OSError as e:
                     app.logger.error(f"Error removing lock file {lock_file_path} after key removal: {e}")

    except KeyError:
        app.logger.error(f"SSH user '{ssh_user}' not found on the system during key removal.")
        return False
    except Exception as e:
        app.logger.error(f"Unexpected error during SSH key removal for user '{ssh_user}': {e}", exc_info=True)
        return False
    finally:
        # Clean up lock file
        lock_file_path = os.path.join(pwd.getpwnam(ssh_user).pw_dir, '.ssh', 'authorized_keys.lock')
        if os.path.exists(lock_file_path):
             try:
                 os.remove(lock_file_path)
             except OSError: pass

# --- Need to import Blueprints AFTER app, db, forms etc. are defined ---
# These imports should ideally be inside create_app() to avoid circular imports
# Moved imports inside create_app()

# --- Import pwd for SSH key management ---
import pwd
