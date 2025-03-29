# Simbak - 轻量级文件/数据库定时备份系统

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/k08255-lxm/simbak)](https://github.com/k08255-lxm/simbak/commits/main)
[![GitHub Release](https://img.shields.io/github/v/release/k08255-lxm/simbak)](https://github.com/k08255-lxm/simbak/releases)

[![Python](https://img.shields.io/badge/Python-3.x-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-%23000.svg?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Bootstrap](https://img.shields.io/badge/Bootstrap-5.x-blueviolet.svg)](https://getbootstrap.com/)
[![SQLite](https://img.shields.io/badge/SQLite-%2307405e.svg?style=for-the-badge&logo=sqlite&logoColor=white)](https://www.sqlite.org/)
[![Rsync](https://img.shields.io/badge/Rsync-lightgrey)](https://rsync.samba.org/)
[![Cron](https://img.shields.io/badge/Cron-yellow)](https://en.wikipedia.org/wiki/Cron)
[![Install Script](https://img.shields.io/badge/Install-Automated-brightgreen.svg)](https://github.com/k08255-lxm/simbak/blob/main/install.sh)
[![Web UI](https://img.shields.io/badge/UI-Web-blue.svg)](https://github.com/k08255-lxm/simbak)
[![GitHub Stars](https://img.shields.io/github/stars/k08255-lxm/simbak)](https://github.com/k08255-lxm/simbak/stargazers)
[![GitHub Forks](https://img.shields.io/github/forks/k08255-lxm/simbak)](https://github.com/k08255-lxm/simbak/network/members)


Simbak (Simple Backup) 是一个轻量级、易于部署和使用的客户端/服务器架构的备份系统，旨在定期将指定的文件、目录或数据库备份到中央主控服务器。

## 主要功能

*   **自动化安装:** 提供 Shell 脚本 (`install.sh`)，自动检测主流 Linux 发行版并安装所需环境、项目程序。
*   **Web 用户界面 (主控):**
    *   简洁美观的 Web UI，方便管理。
    *   仪表盘概览客户端状态、备份情况。
    *   客户端管理：添加（生成一键安装命令）、查看状态、删除。
    *   备份任务管理：为每个客户端配置多个备份任务（目录、MySQL、PostgreSQL）。
    *   灵活的调度：使用 Cron 表达式定义备份频率。
    *   备份文件浏览：在线浏览已备份的文件和目录结构。
    *   一键恢复：选择备份快照并将文件恢复到客户端指定路径。
    *   备份日志查看：集中查看所有客户端的备份日志。
    *   系统设置：配置备份存储、SSH 用户、通知方式等。
*   **轻量级被控端:**
    *   通过一键命令快速安装部署。
    *   资源占用低，后台静默运行。
    *   自动从主控获取备份任务并按计划执行。
    *   支持 Rsync 高效增量备份。
    *   支持 `mysqldump` 和 `pg_dump` 进行数据库备份。
    *   自动上报心跳、状态和日志到主控。
*   **新增高级功能:**
    *   **带宽限制:** 可为每个备份任务设置 Rsync 带宽限制。
    *   **备份保留策略:** 主控自动清理过期的备份快照（基于天数）。
    *   **通知:** 支持通过 Email 和 Webhook 发送备份成功/失败、客户端离线等通知。

## 技术栈

*   **主控后端:** Python 3, Flask
*   **主控前端:** HTML5, CSS3 (Bootstrap 5), JavaScript (jQuery optional)
*   **数据库 (主控):** SQLite (默认)
*   **被控代理:** Python 3
*   **核心传输:** Rsync over SSH
*   **任务调度 (被控):** 内部调度 (基于 croniter) 或 Systemd Timer/Cron (安装脚本配置 Systemd 服务)
*   **后台任务 (主控):** APScheduler (用于保留策略清理等)

## 安装

**警告:** 直接在生产环境使用前，请务必进行充分测试并根据您的环境调整配置，特别是安全相关设置。

1.  **准备:**
    *   两台 Linux 服务器：一台作为主控 (Master)，一台或多台作为被控 (Client)。
    *   主控服务器需要有公网 IP 或与被控端网络互通。
    *   确保服务器已安装 `git` 和 `curl`。
    *   **强烈建议** 为主控配置域名和 HTTPS。

2.  **安装主控:**
    *   登录到 **主控** 服务器。
    *   下载安装脚本并执行 (需要 `sudo` 或 `root` 权限):
        ```bash
        curl -sSL https://raw.githubusercontent.com/k08255-lxm/simbak/main/install.sh -o simbak_install.sh
        sudo bash simbak_install.sh --mode master [--install-dir /opt/simbak] [--yes]
        ```
        
        *   `--install-dir`: 可选，指定安装路径 (默认 `/opt/simbak`)。
        *   `--yes`: 可选，跳过交互式确认 (如 Nginx 安装提示)。
    *   脚本会自动安装依赖、下载代码、创建用户 (`simbak` 服务用户和 `simbak` 备份用户)、设置 Systemd 服务，并根据提示可选安装配置 Nginx。
    *   **首次访问:** 通过浏览器访问主控的 IP 地址或域名。如果是首次运行，系统会引导您创建管理员账户并完成基本设置（如备份存储路径）。
    *   **防火墙:** 确保防火墙允许 Web 访问端口 (80/443) 和 SSH 端口 (默认 22)。

3.  **安装被控:**
    
    *   登录到 **主控** Web UI。
    *   导航到 "客户端管理" -> "新增客户端"。
    *   系统会生成一个包含注册令牌和主控地址的一键安装命令。
    *   复制该命令。
    *   登录到 **被控** 服务器。
    *   粘贴并执行复制的命令 (通常需要 `sudo`):
        ```bash
        # 示例命令 (实际命令从主控 WebUI 复制)
        curl -sSL https://raw.githubusercontent.com/k08255-lxm/simbak/main/install.sh | sudo bash -s -- --mode client --master-url https://your-master.com --token YOUR_REGISTRATION_TOKEN [--ssh-user simbak]
        ```
    *   脚本会自动安装依赖、下载代码、生成 SSH 密钥、配置代理，并尝试向主控注册。
    *   **重要:** 注册成功后，安装脚本会显示客户端的 **SSH 公钥**。您需要 **手动** 将此公钥添加到 **主控** 服务器上备份用户的 `authorized_keys` 文件中 (路径通常在安装脚本的输出日志中提示，默认为 `/home/simbak/.ssh/authorized_keys` 或 `/opt/simbak/backups/.ssh/authorized_keys`，取决于备份用户家目录)。
    *   返回主控 Web UI，刷新客户端列表，应能看到新注册的客户端。

## 使用

1.  **登录主控 Web UI。**
2.  **客户端管理:** 查看在线状态，如有需要可编辑客户端名称或删除。
3.  **配置备份任务:**
    *   进入客户端详情页面。
    *   点击 "添加备份任务"。
    *   选择任务类型（目录、MySQL、PostgreSQL）。
    *   填写源路径（目录）或数据库连接信息（名称、用户、密码等）。
    *   设置 Cron 调度表达式（如 `0 3 * * *` 表示每天凌晨 3 点）。
    *   配置带宽限制、保留天数等选项。
    *   保存任务。
4.  **监控:**
    *   在仪表盘查看整体状态。
    *   在客户端详情页查看该客户端的备份日志。
    *   在 "系统日志" 页面查看主控和所有客户端的详细日志。
5.  **文件浏览与恢复:**
    *   在客户端详情页面，找到 "文件浏览/恢复" 部分（或类似选项）。
    *   选择要浏览的备份任务。
    *   选择一个备份快照（按时间戳）。
    *   浏览文件结构。
    *   (TODO: 实现下载按钮)
    *   如需恢复，选择快照，填写客户端上的目标恢复路径，点击 "开始恢复"。

## 安全提示

*   **HTTPS:** 务必为主控 Web UI 配置 HTTPS。安装脚本可协助安装 Certbot。
*   **密钥安全:** 保护好主控的 `SECRET_KEY` 和数据库中的加密数据。保护好客户端的 API Key 和 SSH 私钥。
*   **SSH 访问:** 确保主控的 SSH 服务安全配置。`authorized_keys` 文件权限应为 `600`，`.ssh` 目录权限为 `700`，所有者为对应的备份用户。脚本会自动添加 SSH key 限制 (`no-port-forwarding` 等)。
*   **用户权限:**
    *   主控 Flask 应用不应以 root 运行（安装脚本会创建 `simbak` 用户）。
    *   备份用户 (`simbak`) 应限制登录权限 (`nologin` shell)。
    *   **客户端代理默认以 root 运行** 以便访问文件和执行 `mysqldump/pg_dump`。这存在安全风险。在严格的生产环境中，考虑配置具有特定 `sudo` 权限的非 root 用户运行代理。
*   **输入验证:** Web UI 和 API 都应进行严格的输入验证。
*   **依赖更新:** 定期更新所有系统和 Python 依赖库。

## 贡献

欢迎提交 Pull Requests 或 Issues。

## 许可证

本项目采用 [MIT 许可证](LICENSE)。
