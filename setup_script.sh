#!/bin/bash

set -e

# Comprehensive Bash script for Ubuntu/Debian LAMP setup with optimizations and monitoring

# Global variables
LOG_FILE="/var/log/setup_script.log"
USERNAME=""
PASSWORD=""
SIGNOZ_URL=""
SIGNOZ_KEY=""

# Logging function with timestamps
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S') - $1"
    echo "$message" | tee -a "$LOG_FILE"
}

# Function to detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$ID
        VER=$VERSION_ID
    else
        log "ERROR: Cannot detect OS."
        exit 1
    fi
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        log "ERROR: This script supports only Ubuntu and Debian."
        exit 1
    fi
    log "Detected OS: $OS $VER"
}

# Function to check if a package is installed
is_installed() {
    dpkg -l | grep -q "$1"
}

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function for pre-flight checks
pre_flight_checks() {
    log "Starting pre-flight checks..."

    # Update package list
    sudo apt update -y

    # List of required packages
    required_pkgs=("sudo" "openssh-server" "git" "curl" "wget" "ufw" "fail2ban")

    for pkg in "${required_pkgs[@]}"; do
        if ! is_installed "$pkg"; then
            log "Installing $pkg..."
            sudo apt install -y "$pkg"
        else
            log "$pkg is already installed."
        fi
    done

    # Check and create user
    if id "$USERNAME" &>/dev/null; then
        log "User $USERNAME already exists."
    else
        log "Creating user $USERNAME..."
        sudo useradd -m -s /bin/bash "$USERNAME"
        echo "$USERNAME:$PASSWORD" | sudo chpasswd
        sudo usermod -aG sudo "$USERNAME"
        log "User $USERNAME created and added to sudo group."
    fi

    log "Pre-flight checks completed."
}

# Function to install and configure NGINX
install_nginx() {
    log "Starting NGINX installation and optimization..."

    # Add NGINX stable repository (for latest with modules)
    if ! is_installed "nginx"; then
        sudo apt install -y software-properties-common
        if [ "$OS" = "ubuntu" ]; then
            sudo add-apt-repository -y ppa:nginx/stable
        else # Debian
            echo "deb http://nginx.org/packages/debian/ $VERSION_CODENAME nginx" | sudo tee /etc/apt/sources.list.d/nginx.list
            curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key
            sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        fi
        sudo apt update -y
        sudo apt install -y nginx
    else
        log "NGINX is already installed."
    fi

    # Install Brotli module if not present
    if ! nginx -V 2>&1 | grep -q ngx_brotli; then
        sudo apt install -y libbrotli-dev
        # Note: May need to build NGINX with Brotli for full support
        log "Brotli module installation may require custom build. Skipping for simplicity."
    fi

    # Configure NGINX
    sudo mkdir -p /etc/nginx/conf.d
    cat <<EOF | sudo tee /etc/nginx/conf.d/optimizations.conf
# Brotli compression
brotli on;
brotli_comp_level 6;
brotli_types text/plain text/css application/javascript application/x-javascript text/xml application/xml application/xml+rss text/javascript;

# HTTP/3 (QUIC)
listen 443 quic reuseport;
http3 on;

# SSL optimizations
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers HIGH:!aNULL:!MD5;
ssl_stapling on;
ssl_stapling_verify on;

# Caching and rate limiting
proxy_cache_path /var/cache/nginx levels=1:2 keys_zone=my_cache:10m max_size=10g inactive=60m use_temp_path=off;
limit_req_zone \$binary_remote_addr zone=one:10m rate=1r/s;

# Static file optimizations
location ~* \.(css|js|ts)$ {
    gzip on;
    gzip_types text/css application/javascript application/x-typescript;
    expires 1y;
    add_header Cache-Control "public";
}
EOF

    sudo nginx -t && sudo systemctl reload nginx
    log "NGINX configured and reloaded."
}

# Function to install and configure PHP
install_php() {
    log "Starting PHP installation and optimization..."

    # Add PHP repository
    if [ "$OS" = "ubuntu" ]; then
        sudo add-apt-repository -y ppa:ondrej/php
    else # Debian
        sudo apt install -y lsb-release apt-transport-https ca-certificates
        wget -O /etc/apt/trusted.gpg.d/php.gpg https://packages.sury.org/php/apt.gpg
        echo "deb https://packages.sury.org/php/ $(lsb_release -sc) main" | sudo tee /etc/apt/sources.list.d/php.list
    fi
    sudo apt update -y

    PHP_VERSION="8.3" # Latest stable as of now
    if ! is_installed "php$PHP_VERSION"; then
        sudo apt install -y php$PHP_VERSION php$PHP_VERSION-fpm php$PHP_VERSION-cli php$PHP_VERSION-curl php$PHP_VERSION-mysql php$PHP_VERSION-pgsql php$PHP_VERSION-mbstring php$PHP_VERSION-xml php$PHP_VERSION-zip php$PHP_VERSION-gd php$PHP_VERSION-mail php$PHP_VERSION-opcache
    else
        log "PHP $PHP_VERSION is already installed."
    fi

    # Optimize php.ini
    sudo sed -i 's/;opcache.enable=1/opcache.enable=1/' /etc/php/$PHP_VERSION/fpm/php.ini
    sudo sed -i 's/expose_php = On/expose_php = Off/' /etc/php/$PHP_VERSION/fpm/php.ini
    sudo sed -i 's/disable_functions =/disable_functions = phpinfo,eval,system,exec,shell_exec,passthru/' /etc/php/$PHP_VERSION/fpm/php.ini

    # Optimize PHP-FPM pool
    sudo sed -i 's/pm = dynamic/pm = ondemand/' /etc/php/$PHP_VERSION/fpm/pool.d/www.conf
    sudo sed -i 's/pm.max_children = 5/pm.max_children = 50/' /etc/php/$PHP_VERSION/fpm/pool.d/www.conf

    sudo systemctl restart php$PHP_VERSION-fpm
    log "PHP configured and restarted."
}

# Function to install and configure databases
install_databases() {
    log "Starting database installation..."

    # MariaDB
    if ! is_installed "mariadb-server"; then
        sudo apt install -y mariadb-server
        sudo mysql_secure_installation
    else
        log "MariaDB is already installed."
    fi

    # Tune MariaDB
    cat <<EOF | sudo tee -a /etc/mysql/my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
EOF
    sudo systemctl restart mariadb

    # PostgreSQL
    if ! is_installed "postgresql"; then
        sudo apt install -y postgresql
        sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$(openssl rand -base64 12)';"
        # Secure: similar to mysql_secure_installation, manual steps
        log "PostgreSQL installed. Run manual security steps if needed."
    else
        log "PostgreSQL is already installed."
    fi

    # Tune PostgreSQL
    sudo sed -i 's/#shared_buffers = 128MB/shared_buffers = 256MB/' /etc/postgresql/*/main/postgresql.conf
    sudo sed -i 's/#effective_cache_size = 4GB/effective_cache_size = 1GB/' /etc/postgresql/*/main/postgresql.conf
    sudo systemctl restart postgresql

    log "Databases configured and restarted."
}

# Function to configure security tools
configure_security() {
    log "Starting security tools configuration..."

    # UFW
    sudo ufw allow OpenSSH
    sudo ufw allow http
    sudo ufw allow https
    sudo ufw --force enable

    # Fail2Ban
    if ! is_installed "fail2ban"; then
        sudo apt install -y fail2ban
    fi

    cat <<EOF | sudo tee /etc/fail2ban/jail.d/sshd.local
[sshd]
enabled = true
EOF

    cat <<EOF | sudo tee /etc/fail2ban/jail.d/nginx-http-auth.local
[nginx-http-auth]
enabled = true
EOF

    sudo systemctl restart fail2ban
    log "Security tools configured."
}

# Function to install OpenTelemetry Collector
install_otel() {
    log "Starting OpenTelemetry installation..."

    if [ -z "$SIGNOZ_URL" ]; then
        read -p "Enter SigNoz instance URL (default: http://localhost:4317): " SIGNOZ_URL
        SIGNOZ_URL=${SIGNOZ_URL:-http://localhost:4317}
    fi

    if [ -z "$SIGNOZ_KEY" ]; then
        read -p "Enter SigNoz authentication key (or press enter to generate): " SIGNOZ_KEY
        if [ -z "$SIGNOZ_KEY" ]; then
            SIGNOZ_KEY=$(openssl rand -hex 16)
            log "Generated SigNoz key: $SIGNOZ_KEY"
        fi
    fi

    # Download and install OTel Collector
    if ! command_exists otelcol; then
        curl -sSfL https://github.com/open-telemetry/opentelemetry-collector/releases/download/cmd/otelcol/v0.88.0/otelcol_0.88.0_linux_amd64.tar.gz -o otelcol.tar.gz
        tar -xzf otelcol.tar.gz
        sudo mv otelcol /usr/local/bin/
        rm otelcol.tar.gz
    else
        log "OTel Collector already installed."
    fi

    # Configure
    cat <<EOF | sudo tee /etc/otelcol/config.yaml
receivers:
  otlp:
    protocols:
      grpc:
      http:

processors:
  batch:

exporters:
  otlp:
    endpoint: "$SIGNOZ_URL"
    headers:
      "signoz-access-token": "$SIGNOZ_KEY"

service:
  pipelines:
    traces:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp]
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp]
    logs:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp]
EOF

    # Create systemd service
    cat <<EOF | sudo tee /etc/systemd/system/otelcol.service
[Unit]
Description=OpenTelemetry Collector

[Service]
ExecStart=/usr/local/bin/otelcol --config=/etc/otelcol/config.yaml
Restart=always

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    sudo systemctl enable otelcol
    sudo systemctl start otelcol
    log "OpenTelemetry Collector configured and started."
}

# Main function
main() {
    # Prompt for username
    read -p "Enter username: " USERNAME

    # Prompt for password
    read -s -p "Enter password for $USERNAME: " PASSWORD
    echo

    detect_os
    pre_flight_checks
    install_nginx
    install_php
    install_databases
    configure_security
    install_otel

    log "Setup completed successfully."
}

main
