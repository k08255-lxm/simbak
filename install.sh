#!/bin/bash

# Simbak Installation Script (v2 - More Robust)

# --- Configuration ---
PROJECT_NAME="simbak"
GITHUB_REPO="k08255-lxm/simbak" # Your actual GitHub repo
DEFAULT_INSTALL_DIR="/opt/${PROJECT_NAME}"
PYTHON_CMD="python3"
PIP_CMD="pip3"
LOG_FILE="/var/log/${PROJECT_NAME}_install.log"
BACKUP_USER="${PROJECT_NAME}" # Dedicated user for receiving backups via SSH

# --- Mode Flags ---
MODE="" # master or client
MASTER_URL_ARG=""
TOKEN_ARG=""
SSH_USER_ARG="${BACKUP_USER}" # Default SSH user is the backup user
SKIP_PROMPT=false

# --- Helper Functions ---
log() {
    echo "[Simbak Install] $(date '+%Y-%m-%d %H:%M:%S') - $1" | tee -a "$LOG_FILE"
}

error_exit() {
    log "错误: $1"
    log "安装失败。请检查日志文件: ${LOG_FILE}"
    exit 1
}

check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        error_exit "此脚本需要 root 权限运行。请使用 sudo。"
    fi
}

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si | tr '[:upper:]' '[:lower:]')
    elif [ -f /etc/debian_version ]; then
        OS=debian
    elif [ -f /etc/redhat-release ]; then
        OS=$(awk '{print tolower($1)}' /etc/redhat-release | sed 's/"//g') # Handle variations
         if [[ "$OS" == "centos" || "$OS" == "red" ]]; then OS="centos"; fi # Normalize RHEL/CentOS
         if [[ "$OS" == "alma" ]]; then OS="almalinux"; fi
         if [[ "$OS" == "rocky" ]]; then OS="rocky"; fi
    else
        error_exit "无法检测到 Linux 发行版。"
    fi
    log "检测到系统: $OS"
}

get_package_manager() {
    case "$OS" in
        ubuntu|debian) echo "apt-get";;
        centos|rhel|fedora|almalinux|rocky)
            if command -v dnf >/dev/null 2>&1; then echo "dnf"; else echo "yum"; fi
            ;;
        *) error_exit "不支持的发行版 '$OS' 进行包管理。" ;;
    esac
}

install_packages() {
    local pkgs="$@"
    local pm
    pm=$(get_package_manager)
    log "正在使用 $pm 安装: $pkgs"

    case "$pm" in
        apt-get)
            apt-get update -qq >> "$LOG_FILE" 2>&1 || log "apt-get update 失败 (可能无网络?)"
            apt-get install -y -qq $pkgs >> "$LOG_FILE" 2>&1
            ;;
        dnf|yum)
            # Install EPEL for CentOS/RHEL if needed (Nginx, Certbot often require it)
            if [[ "$OS" == "centos" || "$OS" == "rhel" ]] && ! rpm -q epel-release >/dev/null 2>&1; then
                log "正在安装 epel-release..."
                $pm install -y epel-release >> "$LOG_FILE" 2>&1 || log "安装 epel-release 可能已存在或失败"
            fi
             # RHEL/CentOS 7 might need specific python3 packages like python36
            if [[ "$OS" == "centos" || "$OS" == "rhel" ]] && [[ "$(rpm -E %{rhel})" == "7" ]]; then
                 log "检测到 RHEL/CentOS 7, 可能需要安装 SCL python3"
                 # Add logic for SCL if strictly needed, otherwise assume system python3 is sufficient
            fi
            $pm install -y $pkgs >> "$LOG_FILE" 2>&1
            ;;
    esac

    if [ $? -ne 0 ]; then
        # Attempt to install one by one for better debugging
        log "包安装失败，尝试逐个安装..."
        for pkg in $pkgs; do
            log "尝试安装 $pkg..."
            case "$pm" in
                apt-get) apt-get install -y -qq "$pkg" >> "$LOG_FILE" 2>&1 ;;
                dnf|yum) $pm install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
            esac
             if [ $? -ne 0 ]; then
                 error_exit "安装依赖包 '$pkg' 失败。请检查日志 ${LOG_FILE} 和网络连接。"
             fi
        done
        log "依赖包逐个安装完成。"
    else
        log "依赖包安装成功。"
    fi
}

setup_python_venv() {
    local venv_dir="$1"
    local owner_user="${2:-root}" # Default to root, change if running service as different user
    log "设置 Python 虚拟环境: $venv_dir (所有者: $owner_user)"
    if ! command -v $PYTHON_CMD >/dev/null 2>&1; then
        error_exit "找不到 $PYTHON_CMD。请确保已安装 Python 3。"
    fi
    # Ensure parent directory exists and has correct permissions if needed
    mkdir -p "$(dirname "$venv_dir")"
    # chown -R "$owner_user:$owner_user" "$(dirname "$venv_dir")" # Adjust ownership if needed

    $PYTHON_CMD -m venv "$venv_dir" >> "$LOG_FILE" 2>&1 || error_exit "创建 Python 虚拟环境失败。"
    chown -R "$owner_user:$owner_user" "$venv_dir" # Set venv ownership
    log "Python 虚拟环境创建成功。"
}

install_python_deps() {
    local venv_dir="$1"
    local requirements_file="$2"
    log "在 $venv_dir 中安装 Python 依赖从 $requirements_file ..."
    # Activate venv and install
    # shellcheck source=/dev/null
    source "${venv_dir}/bin/activate" && \
    "$PIP_CMD" install --upgrade pip >> "$LOG_FILE" 2>&1 && \
    "$PIP_CMD" install -r "$requirements_file" >> "$LOG_FILE" 2>&1 && \
    deactivate || { log "安装 Python 依赖失败。"; deactivate; return 1; } # Ensure deactivate runs on failure

    log "Python 依赖安装成功。"
}

# --- Argument Parsing ---
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --mode) MODE="$2"; shift ;;
        --master-url) MASTER_URL_ARG="$2"; shift ;;
        --token) TOKEN_ARG="$2"; shift ;;
        --ssh-user) SSH_USER_ARG="$2"; shift ;;
        --install-dir) DEFAULT_INSTALL_DIR="$2"; shift ;;
        --yes) SKIP_PROMPT=true ;;
        -h|--help)
            echo "用法: sudo bash $0 [--mode <master|client>] [--master-url <url>] [--token <token>] [--ssh-user <user>] [--install-dir <path>] [--yes]"
            echo "  --mode: 指定安装模式 (master 或 client)"
            echo "  --master-url: (仅限 client) 主控服务器 URL"
            echo "  --token: (仅限 client) 主控提供的注册令牌"
            echo "  --ssh-user: (仅限 client) 连接主控 SSH 的用户名 (默认: ${BACKUP_USER})"
            echo "  --install-dir: 安装的目标目录 (默认: ${DEFAULT_INSTALL_DIR})"
            echo "  --yes: 跳过所有确认提示"
            echo "  -h, --help: 显示此帮助信息"
            exit 0
            ;;
        *) echo "未知参数: $1"; exit 1 ;;
    esac
    shift
done

INSTALL_DIR="$DEFAULT_INSTALL_DIR"
VENV_DIR="${INSTALL_DIR}/venv"
MASTER_SERVICE_NAME="${PROJECT_NAME}-master"
CLIENT_SERVICE_NAME="${PROJECT_NAME}-client"

# --- Main Logic ---
touch "$LOG_FILE" # Create log file early
chmod 600 "$LOG_FILE" # Restrict access
log "Simbak 安装开始..."
log "安装目录: ${INSTALL_DIR}"

check_root
detect_distro

# --- Ask User Role if not provided ---
if [ -z "$MODE" ]; then
    if $SKIP_PROMPT; then
        error_exit "需要指定 --mode (master 或 client) 才能跳过提示。"
    fi
    echo "您想要安装哪个组件?"
    echo "1) 主控 (Master Server)"
    echo "2) 被控 (Client Agent)"
    read -p "请输入选项 (1 或 2): " ROLE_CHOICE
    if [ "$ROLE_CHOICE" == "1" ]; then MODE="master"; fi
    if [ "$ROLE_CHOICE" == "2" ]; then MODE="client"; fi
fi

if [ "$MODE" != "master" ] && [ "$MODE" != "client" ]; then
    error_exit "无效的模式 '$MODE'。请选择 'master' 或 'client'。"
fi

log "选择的安装模式: $MODE"

# --- Common Dependencies ---
log "安装通用依赖..."
COMMON_DEPS="git python3 python3-pip python3-venv rsync openssh-client curl"
# Add OS-specific build tools needed for some Python packages
case "$OS" in
    ubuntu|debian) COMMON_DEPS="$COMMON_DEPS python3-dev build-essential libssl-dev libffi-dev";;
    centos|rhel|fedora|almalinux|rocky) COMMON_DEPS="$COMMON_DEPS python3-devel gcc openssl-devel libffi-devel";;
esac
install_packages $COMMON_DEPS

# --- Download Project Code ---
if [ -d "$INSTALL_DIR" ]; then
    if $SKIP_PROMPT; then
        log "安装目录 '$INSTALL_DIR' 已存在，将覆盖。"
        rm -rf "$INSTALL_DIR" || error_exit "无法删除旧的安装目录 $INSTALL_DIR"
    else
        read -p "安装目录 '$INSTALL_DIR' 已存在。是否覆盖? (y/N): " OVERWRITE
        if [[ "$OVERWRITE" =~ ^[Yy]$ ]]; then
            log "删除旧的安装目录: $INSTALL_DIR"
            rm -rf "$INSTALL_DIR" || error_exit "无法删除旧的安装目录 $INSTALL_DIR"
        else
            log "安装已取消。"
            exit 0
        fi
    fi
fi
log "正在从 GitHub 克隆项目 (https://github.com/${GITHUB_REPO}.git)..."
git clone --depth 1 "https://github.com/${GITHUB_REPO}.git" "$INSTALL_DIR" >> "$LOG_FILE" 2>&1 || error_exit "克隆仓库失败。请检查网络连接和仓库地址 (${GITHUB_REPO})。"
cd "$INSTALL_DIR" || error_exit "无法进入安装目录 $INSTALL_DIR"

# --- Master Installation ---
if [ "$MODE" == "master" ]; then
    log "开始安装主控..."

    # Master OS Dependencies
    MASTER_OS_DEPS="openssh-server" # For receiving rsync
    FLASK_USER="${PROJECT_NAME}" # Run Flask app as this user
    FLASK_GROUP="${PROJECT_NAME}"
    NGINX_SETUP=false

    # Create dedicated user for the Flask app and backups
    if ! id -u "$FLASK_USER" >/dev/null 2>&1; then
        log "创建 Simbak 服务用户: $FLASK_USER"
        # System user, no login shell, create home dir (though we use INSTALL_DIR mostly)
        useradd -r -s /usr/sbin/nologin -d "$INSTALL_DIR" "$FLASK_USER" || \
        useradd -r -s /sbin/nologin -d "$INSTALL_DIR" "$FLASK_USER" || \
        error_exit "无法创建用户 $FLASK_USER"
        log "用户 $FLASK_USER 创建成功。"
    else
        log "服务用户 $FLASK_USER 已存在。"
    fi

    # Backup User (might be the same as FLASK_USER, but separate for clarity)
    BACKUP_STORAGE_DEFAULT="${INSTALL_DIR}/backups"
    if ! id -u "$BACKUP_USER" >/dev/null 2>&1; then
         log "创建 Simbak 备份用户: $BACKUP_USER"
         useradd -r -m -d "$BACKUP_STORAGE_DEFAULT" -s /usr/sbin/nologin "$BACKUP_USER" || \
         useradd -r -m -d "$BACKUP_STORAGE_DEFAULT" -s /sbin/nologin "$BACKUP_USER" || \
         error_exit "无法创建备份用户 $BACKUP_USER"
         log "备份用户 $BACKUP_USER 创建成功，备份目录: $BACKUP_STORAGE_DEFAULT"
    else
        log "备份用户 $BACKUP_USER 已存在。"
        # Ensure backup dir exists if user already existed
        if [ ! -d "$BACKUP_STORAGE_DEFAULT" ]; then
            mkdir -p "$BACKUP_STORAGE_DEFAULT"
            chown "$BACKUP_USER:$BACKUP_USER" "$BACKUP_STORAGE_DEFAULT"
        fi
    fi

    # Setup SSH for Backup User
    BACKUP_USER_HOME=$(eval echo ~$BACKUP_USER) # Get home dir reliably
    SSH_DIR="${BACKUP_USER_HOME}/.ssh"
    AUTH_KEYS_FILE="${SSH_DIR}/authorized_keys"
    mkdir -p "$SSH_DIR"
    touch "$AUTH_KEYS_FILE"
    chown -R "$BACKUP_USER:$BACKUP_USER" "$SSH_DIR"
    chmod 700 "$SSH_DIR"
    chmod 600 "$AUTH_KEYS_FILE"
    log "备份用户 SSH 目录和 authorized_keys 文件已设置: $AUTH_KEYS_FILE"
    log "客户端公钥将需要添加到此文件中。"

    # Optional Nginx setup
    if ! $SKIP_PROMPT; then
        read -p "是否安装并配置 Nginx 作为反向代理? (建议用于生产环境) (y/N): " INSTALL_NGINX_PROMPT
        if [[ "$INSTALL_NGINX_PROMPT" =~ ^[Yy]$ ]]; then NGINX_SETUP=true; fi
    elif [[ -z "$INSTALL_NGINX_PROMPT" ]]; then # Handle --yes case, default to no nginx maybe? Or require another flag?
        log "在 --yes 模式下，默认不安装 Nginx。如需安装，请取消 --yes 并手动确认，或添加 --install-nginx 标志 (未实现)"
        # NGINX_SETUP=false # Explicitly set
    fi

    if $NGINX_SETUP; then
         MASTER_OS_DEPS="$MASTER_OS_DEPS nginx python3-certbot-nginx" # Or certbot if distro needs it separately
         log "将安装 Nginx 和 Certbot 插件。"
    fi
    install_packages $MASTER_OS_DEPS

    # Setup Python Environment (owned by FLASK_USER)
    setup_python_venv "$VENV_DIR" "$FLASK_USER"
    install_python_deps "$VENV_DIR" "${INSTALL_DIR}/master/requirements.txt" || error_exit "安装 Master Python 依赖失败。"

    # Create instance directory (owned by FLASK_USER)
    INSTANCE_DIR="${INSTALL_DIR}/master/instance"
    mkdir -p "$INSTANCE_DIR"
    chown -R "$FLASK_USER:$FLASK_GROUP" "$INSTANCE_DIR"
    chmod 770 "$INSTANCE_DIR" # Group write access might be needed by webserver/app

    # Set ownership of the entire installation directory (carefully)
    # Give FLASK_USER ownership of necessary parts, BACKUP_USER ownership of backup storage
    log "设置目录权限..."
    chown -R "$FLASK_USER:$FLASK_GROUP" "$INSTALL_DIR" # App user owns the code
    chown -R "$BACKUP_USER:$BACKUP_USER" "$BACKUP_STORAGE_DEFAULT" # Backup user owns storage
    # Ensure app user can potentially write logs if needed outside instance/
    # chmod -R g+w "${INSTALL_DIR}/some_log_dir" # If applicable

    # Create Systemd service file
    log "配置主控 Systemd 服务 (${MASTER_SERVICE_NAME})..."
    GUNICORN_SOCK="${INSTANCE_DIR}/simbak.sock"
    cat > "/etc/systemd/system/${MASTER_SERVICE_NAME}.service" << EOL
[Unit]
Description=Simbak Master Service
After=network.target

[Service]
User=${FLASK_USER}
Group=${FLASK_GROUP}
WorkingDirectory=${INSTALL_DIR}/master
Environment="FLASK_APP=app:create_app()" # Use factory pattern
Environment="FLASK_ENV=production"
Environment="SIMBAK_CONFIG=${INSTANCE_DIR}/production.cfg"
ExecStart=${VENV_DIR}/bin/gunicorn --workers 3 --bind unix:${GUNICORN_SOCK} -m 007 wsgi:app --log-level info --access-logfile ${INSTANCE_DIR}/gunicorn-access.log --error-logfile ${INSTANCE_DIR}/gunicorn-error.log
# Permissions for the socket are set by Gunicorn (-m 007) to allow nginx (usually www-data) to connect
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
EOL

    # Configure Nginx (if selected)
    if $NGINX_SETUP; then
        log "配置 Nginx..."
        NGINX_CONF="/etc/nginx/sites-available/${PROJECT_NAME}"
        NGINX_LINK="/etc/nginx/sites-enabled/${PROJECT_NAME}"
        # Basic Nginx config - Needs user to set server_name!
        cat > "$NGINX_CONF" << EOL
server {
    listen 80;
    # listen [::]:80;
    server_name _; # IMPORTANT: Replace with your domain or IP address!

    # For large file uploads/downloads if needed in future
    # client_max_body_size 100M;

    location / {
        try_files \$uri @proxy_to_app;
    }

    location @proxy_to_app {
        proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_set_header Host \$http_host;
        # Uncomment the following line if using HTTPS and proxying over HTTP
        # proxy_set_header X-Forwarded-Ssl on;
        proxy_redirect off;
        proxy_pass http://unix:${GUNICORN_SOCK};
        # Increase timeouts if backups take long to report? Usually not needed here.
        # proxy_connect_timeout 60s;
        # proxy_send_timeout 60s;
        # proxy_read_timeout 60s;
    }

    location /static {
        alias ${INSTALL_DIR}/master/static;
        expires 30d;
        access_log off;
    }

    # Optional: Enable Gzip compression
    # gzip on;
    # gzip_vary on;
    # gzip_proxied any;
    # gzip_comp_level 6;
    # gzip_types text/plain text/css application/json application/javascript text/xml application/xml application/xml+rss text/javascript;

    # Optional: Security Headers (Uncomment and customize)
    # add_header X-Frame-Options "SAMEORIGIN" always;
    # add_header X-XSS-Protection "1; mode=block" always;
    # add_header X-Content-Type-Options "nosniff" always;
    # add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    # add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self';" always;
    # add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always; # Only if using HTTPS
}
EOL
        ln -sf "$NGINX_CONF" "$NGINX_LINK"
        # Remove default site if it exists
        if [ -f /etc/nginx/sites-enabled/default ]; then
            log "删除默认 Nginx 站点配置..."
            rm -f /etc/nginx/sites-enabled/default
        fi

        log "测试 Nginx 配置..."
        nginx -t
        if [ $? -eq 0 ]; then
            log "Nginx 配置测试成功。"
            systemctl restart nginx || log "重启 Nginx 失败。"
            log "Nginx 配置完成。请务必修改 ${NGINX_CONF} 中的 'server_name' 为您的域名或 IP 地址！"
            log "为了使用 HTTPS (强烈推荐)，请使用 Certbot: sudo certbot --nginx"
        else
            error_exit "Nginx 配置测试失败。请检查 ${NGINX_CONF}。"
        fi
    fi

    # Enable and Start Master Service
    log "启用并启动主控服务..."
    systemctl daemon-reload
    systemctl enable "$MASTER_SERVICE_NAME"
    systemctl start "$MASTER_SERVICE_NAME" || error_exit "启动 ${MASTER_SERVICE_NAME} 服务失败。请检查日志: journalctl -u ${MASTER_SERVICE_NAME}"

    log "----------------------------------------"
    log "主控安装完成！"
    log "----------------------------------------"
    log "服务用户: ${FLASK_USER}"
    log "备份用户: ${BACKUP_USER}"
    log "备份存储目录: ${BACKUP_STORAGE_DEFAULT}"
    log "服务配置文件: /etc/systemd/system/${MASTER_SERVICE_NAME}.service"
    log "应用配置文件 (首次访问时创建): ${INSTANCE_DIR}/production.cfg"
    log "应用数据库 (首次访问时创建): ${INSTANCE_DIR}/simbak.db"
    if $NGINX_SETUP; then
        log "请通过 Web 浏览器访问 Nginx 配置的 server_name (修改后) 来完成初始设置。"
        log "确保防火墙允许端口 80 (和 443 如果配置了 HTTPS)。"
    else
        log "警告：未使用 Nginx。Gunicorn 直接监听 Socket ${GUNICORN_SOCK}。"
        log "这种方式不建议用于生产环境，因为它缺少反向代理功能。"
        log "请考虑手动配置 Nginx 或其他反向代理指向 ${GUNICORN_SOCK}。"
    fi
    log "首次访问将引导您创建管理员账户和进行基本配置。"
    log "请确保 SSH 服务在主控上运行，并允许备份用户 '${BACKUP_USER}' 通过 SSH key 登录 (公钥需添加到 ${AUTH_KEYS_FILE})。"


# --- Client Installation ---
elif [ "$MODE" == "client" ]; then
    log "开始安装被控端..."

    # Validate required arguments for client mode
    if [ -z "$MASTER_URL_ARG" ] || [ -z "$TOKEN_ARG" ]; then
        if $SKIP_PROMPT; then
            error_exit "客户端模式下 --master-url 和 --token 是必需参数 (使用 --yes 时)。"
        else
             read -p "请输入主控服务器地址 (例如: https://backup.example.com): " MASTER_URL_ARG
             read -p "请输入主控提供的注册令牌 (Token): " TOKEN_ARG
             read -p "请输入用于 SSH 连接到主控的用户名 (默认: ${SSH_USER_ARG}): " SSH_USER_INPUT
             if [ -n "$SSH_USER_INPUT" ]; then SSH_USER_ARG="$SSH_USER_INPUT"; fi # Allow override

             if [ -z "$MASTER_URL_ARG" ] || [ -z "$TOKEN_ARG" ]; then
                error_exit "主控地址和令牌不能为空。"
             fi
        fi
    fi
    log "主控地址: ${MASTER_URL_ARG}"
    log "SSH 用户: ${SSH_USER_ARG}"

    # Client OS Dependencies (Minimal)
    CLIENT_OS_DEPS="" # Base is already installed
    # Check for DB dump tools based on potential need (User might install manually later)
    DB_CLIENT_PACKAGES=""
    case "$OS" in
        ubuntu|debian) DB_CLIENT_PACKAGES="default-mysql-client postgresql-client";;
        centos|rhel|fedora|almalinux|rocky) DB_CLIENT_PACKAGES="mysql postgresql";; # Adjust package names as needed
    esac
    log "正在检查数据库客户端工具 (mysqldump, pg_dump)..."
    install_packages $DB_CLIENT_PACKAGES # Install common ones, user configures jobs later

    # Setup Python Environment (owned by root, as agent likely needs root privileges)
    setup_python_venv "$VENV_DIR" "root"
    install_python_deps "$VENV_DIR" "${INSTALL_DIR}/client/requirements.txt" || error_exit "安装 Client Python 依赖失败。"

    # Create necessary directories and set permissions
    mkdir -p "${INSTALL_DIR}/client/.ssh"
    chmod 700 "${INSTALL_DIR}/client/.ssh"
    chown -R root:root "${INSTALL_DIR}/client" # Agent runs as root

    # Generate SSH key pair for the client if it doesn't exist
    CLIENT_SSH_KEY_PATH="${INSTALL_DIR}/client/.ssh/id_rsa_simbak"
    if [ ! -f "$CLIENT_SSH_KEY_PATH" ]; then
        log "为被控端生成 SSH 密钥对 (无密码)..."
        ssh-keygen -t rsa -b 4096 -f "$CLIENT_SSH_KEY_PATH" -N "" >> "$LOG_FILE" 2>&1 || error_exit "生成 SSH 密钥失败。"
        chmod 600 "$CLIENT_SSH_KEY_PATH"
        chmod 644 "${CLIENT_SSH_KEY_PATH}.pub"
        log "SSH 密钥对生成在: $CLIENT_SSH_KEY_PATH"
    else
        log "SSH 密钥对已存在: $CLIENT_SSH_KEY_PATH"
    fi
    CLIENT_PUBLIC_KEY=$(cat "${CLIENT_SSH_KEY_PATH}.pub")

    # Configure Client Agent (Create config file)
    log "配置被控端代理..."
    CLIENT_CONFIG_FILE="${INSTALL_DIR}/client/config_client.ini"
    # Use cryptography to potentially store API key more securely if desired later
    cat > "$CLIENT_CONFIG_FILE" << EOL
[main]
master_url = ${MASTER_URL_ARG}
registration_token = ${TOKEN_ARG}
# api_key and client_id will be filled after successful registration
api_key =
client_id =
verify_ssl = True
log_file = ${INSTALL_DIR}/client/agent.log
log_level = INFO

[ssh]
master_ssh_user = ${MASTER_SSH_USER_ARG}
private_key_path = ${CLIENT_SSH_KEY_PATH}
# master_ssh_port = 22 # Optional, defaults to 22 in agent
known_hosts_file = ${INSTALL_DIR}/client/.ssh/known_hosts

[tasks]
# Example: Define where mysqldump or other tools are if not in PATH
# mysqldump_path = /usr/bin/mysqldump
EOL
    chmod 600 "$CLIENT_CONFIG_FILE" # Restrict access
    chown root:root "$CLIENT_CONFIG_FILE"

    # Register with Master
    log "尝试向主控注册..."
    # shellcheck source=/dev/null
    source "${VENV_DIR}/bin/activate"
    REGISTER_OUTPUT=$($PYTHON_CMD "${INSTALL_DIR}/client/agent.py" --config "$CLIENT_CONFIG_FILE" --register 2>&1)
    REGISTRATION_STATUS=$?
    deactivate

    log "注册脚本输出:\n$REGISTER_OUTPUT" # Log output regardless of status

    if [ $REGISTRATION_STATUS -eq 0 ]; then
        log "被控端注册成功！API Key 和 Client ID 已自动保存到 $CLIENT_CONFIG_FILE。"
        log "主控服务器现在应该可以看到此被控端。"
        # Registration should handle adding master's host key to known_hosts
        log "请登录主控 WebUI，确认客户端已显示，并配置备份任务。"
        log "重要：主控需要手动将此客户端的公钥添加到备份用户的 authorized_keys 文件 (${AUTH_KEYS_FILE} 在主控上)。"
        echo "-------------------- 客户端公钥 (请添加到主控) --------------------"
        echo "$CLIENT_PUBLIC_KEY"
        echo "-------------------------------------------------------------------"
    else
        error_exit "被控端注册失败。请检查主控地址、令牌、网络连接以及 ${LOG_FILE} 和上面的注册输出。"
    fi

    # Create Systemd service for Client Agent
    log "配置被控端 Systemd 服务 (${CLIENT_SERVICE_NAME})..."
    cat > "/etc/systemd/system/${CLIENT_SERVICE_NAME}.service" << EOL
[Unit]
Description=Simbak Client Agent Service
After=network.target network-online.target
Requires=network-online.target # Ensure network is really up

[Service]
User=root # WARNING: Running as root. Consider a less privileged user with specific sudo rules for production.
Group=root
WorkingDirectory=${INSTALL_DIR}/client
# Run as daemon, logging handled by agent.py based on config
ExecStart=${VENV_DIR}/bin/python3 ${INSTALL_DIR}/client/agent.py --config ${CLIENT_CONFIG_FILE} --run-daemon
Restart=on-failure
RestartSec=60s # Restart after 1 minute if it crashes

[Install]
WantedBy=multi-user.target
EOL

    # Enable and Start Client Service
    log "启用并启动被控端服务..."
    systemctl daemon-reload
    systemctl enable "$CLIENT_SERVICE_NAME"
    systemctl start "$CLIENT_SERVICE_NAME" || log "启动 ${CLIENT_SERVICE_NAME} 服务失败。请检查日志: journalctl -u ${CLIENT_SERVICE_NAME} 和 ${INSTALL_DIR}/client/agent.log"

    log "----------------------------------------"
    log "被控端安装完成！"
    log "----------------------------------------"
    log "服务配置文件: /etc/systemd/system/${CLIENT_SERVICE_NAME}.service"
    log "代理配置文件: ${CLIENT_CONFIG_FILE}"
    log "代理日志文件: ${INSTALL_DIR}/client/agent.log"
    log "SSH 私钥: ${CLIENT_SSH_KEY_PATH}"
    log "代理服务 (${CLIENT_SERVICE_NAME}) 已启动并配置为开机自启。"
    log "请返回主控 WebUI 配置备份任务。"

else
    error_exit "未知的安装模式: $MODE" # Should not happen due to earlier check
fi

log "Simbak 安装脚本执行完毕。"
exit 0
