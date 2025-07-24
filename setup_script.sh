#!/bin/bash

set -e

# Comprehensive Bash script for Ubuntu/Debian LAMP setup with optimizations and monitoring

# Global variables
LOG_FILE="/var/log/setup_script.log"
USERNAME=""
PASSWORD=""
SIGNOZ_REGION=""
SIGNOZ_INGESTION_KEY=""

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
        CODENAME=$VERSION_CODENAME

        # Handle Ubuntu 25.04 codename if not recognized
        if [[ "$OS" == "ubuntu" && "$VER" == "25.04" && -z "$CODENAME" ]]; then
            CODENAME="lunar"
        fi
    else
        log "ERROR: Cannot detect OS."
        exit 1
    fi
    if [[ "$OS" != "ubuntu" && "$OS" != "debian" ]]; then
        log "ERROR: This script supports only Ubuntu and Debian."
        exit 1
    fi
    log "Detected OS: $OS $VER (Codename: $CODENAME)"
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
    required_pkgs=("sudo" "openssh-server" "git" "curl" "wget" "ufw" "fail2ban" "software-properties-common" "lsb-release" "apt-transport-https" "ca-certificates")

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

# Function to remove invalid nginx PPA and add correct one
fix_nginx_ppa() {
    if [ "$OS" = "ubuntu" ]; then
        log "Fixing invalid nginx PPA if present..."

        # Remove any PPA files containing 'oracular' explicitly
        sudo find /etc/apt/sources.list.d/ -type f -name "*.list" -exec grep -l "oracular" {} \; | xargs -r sudo rm -f

        # Just in case, remove the nginx stable PPA if it exists
        sudo add-apt-repository --remove ppa:nginx/stable

        # Remove any existing nginx stable PPA entries from sources.list and sources.list.d
        sudo sed -i '/nginx/d' /etc/apt/sources.list
        sudo rm -f /etc/apt/sources.list.d/nginx-*.list

        # Validate CODENAME against known Ubuntu codenames
        valid_codenames=("bionic" "focal" "jammy" "kinetic" "lunar" "mantic" "noble" "impish" "hirsute" "groovy" "lunar" "mantic" "noble" "impish" "hirsute" "groovy" "focal" "eoan" "disco" "cosmic" "bionic" "xenial" "lunar")
        if [[ " ${valid_codenames[*]} " == *" $CODENAME "* ]]; then
            log "Ubuntu codename $CODENAME is valid. Adding nginx stable PPA."
            sudo add-apt-repository -y ppa:nginx/stable
            sudo apt update -y
            log "nginx PPA fixed and updated."
        else
            log "WARNING: Ubuntu codename '$CODENAME' is not recognized as valid. Skipping adding nginx stable PPA to avoid 404 errors."
            log "Please verify your system's codename or update the script accordingly."
        fi
    else
        log "OS is '$CODENAME' version of Ubuntu, skipping nginx PPA fix."
    fi
}

# Call fix_nginx_ppa before install_nginx
fix_nginx_ppa

# Function to install and configure NGINX with Brotli and HTTP/3
install_nginx() {
    log "Starting NGINX installation and optimization..."

    # Check if NGINX is installed with required modules
    if command_exists nginx && nginx -V 2>&1 | grep -q ngx_brotli && nginx -V 2>&1 | grep -q http_v3_module; then
        log "NGINX is already installed with Brotli and HTTP/3 support."
    else
        log "Building NGINX from source with Brotli and HTTP/3 support..."

        # Install build dependencies
        sudo apt update -y
        sudo apt install -y build-essential libpcre3 libpcre3-dev zlib1g zlib1g-dev libssl-dev git cmake

        # Fetch the latest stable version of NGINX dynamically
        NGINX_VERSION=$(curl -s https://nginx.org/en/download.html | grep -oP 'nginx-\K[0-9]+\.[0-9]+\.[0-9]+' | head -1)
        if [ -z "$NGINX_VERSION" ]; then
            log "ERROR: Unable to fetch the latest NGINX version. Exiting."
            exit 1
        fi
        echo "Latest NGINX version found: $NGINX_VERSION"
        sleep 5
        wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz
        tar -zxf nginx-${NGINX_VERSION}.tar.gz
        cd nginx-${NGINX_VERSION}


        # Create build directory
        #BUILD_DIR="$(pwd)/build/nginx-${NGINX_VERSION}"
        #mkdir -p "$BUILD_DIR"
        #cd "$BUILD_DIR"


        # Remove existing ngx_brotli directory if it exists to avoid clone errors
        if [ -d "ngx_brotli" ]; then
            rm -rf ngx_brotli
        fi

        # Clone ngx_brotli
        git clone --depth 1 --recursive https://github.com/google/ngx_brotli.git
        cd ngx_brotli
        git submodule update --init --recursive
        cd deps/brotli
        mkdir -p out
        cd out
        if ! cmake ..; then
            log "ERROR: cmake configuration failed in brotli build."
            exit 1
        fi
        if ! make; then
            log "ERROR: make failed in brotli build."
            exit 1
        fi
        # Do not install brotli system-wide; keep libraries local for linking
        # sudo make install

        # Debugging output: list brotli out directory contents
        echo "Brotli out directory contents:"
        ls -l

        cd "$HOME/nginx-${NGINX_VERSION}"

    # Display the current directory
    echo "Current directory: $(pwd)"

    # Pause for 5 seconds
    sleep 5
        # Configure NGINX
        # Set linker and compiler flags to find brotli libraries in the out directory
        BROTLI_DIR="$(pwd)/ngx_brotli/deps/brotli/out"
        export LDFLAGS="-L${BROTLI_DIR} $LDFLAGS"
        export CPPFLAGS="-I${BROTLI_DIR}/include $CPPFLAGS"
        echo "Running configure with LDFLAGS=$LDFLAGS and CPPFLAGS=$CPPFLAGS"
        ./configure \
            --prefix=/etc/nginx \
            --sbin-path=/usr/sbin/nginx \
            --modules-path=/usr/lib/nginx/modules \
            --conf-path=/etc/nginx/nginx.conf \
            --error-log-path=/var/log/nginx/error.log \
            --http-log-path=/var/log/nginx/access.log \
            --pid-path=/var/run/nginx.pid \
            --lock-path=/var/run/nginx.lock \
            --user=nginx \
            --group=nginx \
            --with-compat \
            --add-dynamic-module=ngx_brotli \
            --with-http_ssl_module \
            --with-http_v2_module \
            --with-http_v3_module \
            --with-stream \
            --with-stream_ssl_module \
            --with-stream_realip_module \
            --with-stream_ssl_preread_module \
            --with-http_gzip_static_module \
            --with-http_stub_status_module \
            --with-threads \
            --with-file-aio

        # Build and install
        make
        sudo make install

        # Clean up
        cd ../../..
        # rm -rf "$(dirname "$BUILD_DIR")"

        # Create nginx user and group if not exists
        if ! getent group nginx >/dev/null; then
            sudo addgroup --system nginx
        fi
        if ! getent passwd nginx >/dev/null; then
            sudo adduser --system --no-create-home --shell /bin/false --gid nginx nginx
        fi

        # Set up systemd service
        cat <<EOF | sudo tee /etc/systemd/system/nginx.service
[Unit]
Description=NGINX Open Source - high performance web server
After=network-online.target remote-fs.target nss-lookup.target
Wants=network-online.target

[Service]
Type=forking
ExecStart=/usr/sbin/nginx -c /etc/nginx/nginx.conf
ExecReload=/usr/sbin/nginx -s reload
ExecStop=/usr/sbin/nginx -s stop
PIDFile=/var/run/nginx.pid
Restart=always
RestartSec=1s

[Install]
WantedBy=multi-user.target
EOF

        sudo systemctl daemon-reload
        sudo systemctl enable nginx
        sudo systemctl start nginx

        log "NGINX built and installed with Brotli and HTTP/3 support."
    fi

    # Add load modules to nginx.conf if not present
    if ! grep -q "load_module /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so;" /etc/nginx/nginx.conf; then
        sudo sed -i '1i load_module /usr/lib/nginx/modules/ngx_http_brotli_filter_module.so;' /etc/nginx/nginx.conf
        sudo sed -i '2i load_module /usr/lib/nginx/modules/ngx_http_brotli_static_module.so;' /etc/nginx/nginx.conf
    fi

    # Configure NGINX optimizations
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
    sudo apt install -y software-properties-common lsb-release apt-transport-https ca-certificates wget
    if [ "$OS" = "ubuntu" ]; then
        sudo add-apt-repository -y ppa:ondrej/php
    else # Debian
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
        # Non-interactive mysql_secure_installation
        sudo mysql_secure_installation <<EOF

y
y
y
y
y
y
EOF
        log "MariaDB secured non-interactively."
    else
        log "MariaDB is already installed."
    fi

    # Tune MariaDB
    cat <<EOF | sudo tee -a /etc/mysql/my.cnf
[mysqld]
innodb_buffer_pool_size = 1G
max_connections = 200
query_cache_size = 0
query_cache_type = 0
log_error = /var/log/mysql/error.log
EOF
    sudo systemctl restart mariadb

    # PostgreSQL
    if ! is_installed "postgresql"; then
        sudo apt install -y postgresql
        PG_PASSWORD=$(openssl rand -base64 12)
        sudo -u postgres psql -c "ALTER USER postgres WITH PASSWORD '$PG_PASSWORD';"
        log "PostgreSQL password set to $PG_PASSWORD (save this securely)."
        # Secure PostgreSQL
        sudo -u postgres psql <<EOF
DROP DATABASE IF EXISTS test;
REVOKE ALL PRIVILEGES ON SCHEMA public FROM public;
\q
EOF
        log "PostgreSQL secured."
    else
        log "PostgreSQL is already installed."
    fi

    # Tune PostgreSQL
    sudo sed -i 's/#shared_buffers = 128MB/shared_buffers = 256MB/' /etc/postgresql/*/main/postgresql.conf
    sudo sed -i 's/#effective_cache_size = 4GB/effective_cache_size = 1GB/' /etc/postgresql/*/main/postgresql.conf
    sudo sed -i 's/#work_mem = 4MB/work_mem = 16MB/' /etc/postgresql/*/main/postgresql.conf
    sudo sed -i 's/#max_connections = 100/max_connections = 200/' /etc/postgresql/*/main/postgresql.conf
    sudo systemctl restart postgresql

    log "Databases configured and restarted."
}

# Function to configure security tools
configure_security() {
    log "Starting security tools configuration..."

    # UFW
    if sudo ufw status | grep -q "Status: inactive"; then
        sudo ufw allow OpenSSH
        sudo ufw allow http
        sudo ufw allow https
        sudo ufw --force enable
        log "UFW enabled with basic rules."
    else
        log "UFW is already enabled."
    fi

    # Fail2Ban
    if ! is_installed "fail2ban"; then
        sudo apt install -y fail2ban
    fi

    cat <<EOF | sudo tee /etc/fail2ban/jail.d/sshd.local
[sshd]
enabled = true
maxretry = 5
findtime = 10m
bantime = 1h
ignoreip = 127.0.0.1/8
EOF

    cat <<EOF | sudo tee /etc/fail2ban/jail.d/nginx-http-auth.local
[nginx-http-auth]
enabled = true
maxretry = 5
findtime = 10m
bantime = 1h
EOF

    sudo systemctl restart fail2ban
    log "Security tools configured."
}

# Function to install OpenTelemetry Collector
install_otel() {
    log "Starting OpenTelemetry installation..."

    # Prompt for SigNoz details
    if [ -z "$SIGNOZ_REGION" ]; then
        read -p "Enter SigNoz region (e.g., us, eu, in): " SIGNOZ_REGION
        SIGNOZ_REGION=${SIGNOZ_REGION:-us}
    fi

    if [ -z "$SIGNOZ_INGESTION_KEY" ]; then
        read -p "Enter SigNoz ingestion key: " SIGNOZ_INGESTION_KEY
        if [ -z "$SIGNOZ_INGESTION_KEY" ]; then
            log "SigNoz ingestion key is required. Exiting."
            exit 1
        fi
    fi

    OTEL_VERSION="0.116.0"
    OTEL_DIR="/opt/otelcol-contrib"

    # Download and install OTel Collector if not present
    if ! command_exists otelcol-contrib; then
        wget https://github.com/open-telemetry/opentelemetry-collector-releases/releases/download/v${OTEL_VERSION}/otelcol-contrib_${OTEL_VERSION}_linux_amd64.tar.gz
        sudo mkdir -p "$OTEL_DIR"
        sudo tar xvzf otelcol-contrib_${OTEL_VERSION}_linux_amd64.tar.gz -C "$OTEL_DIR"
        rm otelcol-contrib_${OTEL_VERSION}_linux_amd64.tar.gz
        sudo ln -s "$OTEL_DIR/otelcol-contrib" /usr/local/bin/otelcol-contrib
        log "OpenTelemetry Collector installed."
    else
        log "OpenTelemetry Collector already installed."
    fi

    # Configure
    cat <<EOF | sudo tee "$OTEL_DIR/config.yaml"
receivers:
  otlp:
    protocols:
      grpc:
        endpoint: 0.0.0.0:4317
      http:
        endpoint: 0.0.0.0:4318
  hostmetrics:
    collection_interval: 60s
    scrapers:
      cpu: {}
      disk: {}
      load: {}
      filesystem: {}
      memory: {}
      network: {}
      paging: {}
      process:
        mute_process_name_error: true
        mute_process_exe_error: true
        mute_process_io_error: true
      processes: {}
  prometheus:
    config:
      global:
        scrape_interval: 60s
      scrape_configs:
        - job_name: otel-collector-binary
          static_configs:
            - targets:
                # - localhost:8888

processors:
  batch:
    send_batch_size: 1000
    timeout: 10s
  resourcedetection:
    detectors: [env, system]
    timeout: 2s
    system:
      hostname_sources: [os]

extensions:
  health_check: {}
  zpages: {}

exporters:
  otlp:
    endpoint: "ingest.${SIGNOZ_REGION}.signoz.cloud:443"
    tls:
      insecure: false
    headers:
      "signoz-ingestion-key": "${SIGNOZ_INGESTION_KEY}"
  debug:
    verbosity: normal

service:
  telemetry:
    metrics:
      address: 0.0.0.0:8888
  extensions: [health_check, zpages]
  pipelines:
    metrics:
      receivers: [otlp]
      processors: [batch]
      exporters: [otlp]
    metrics/internal:
      receivers: [prometheus, hostmetrics]
      processors: [resourcedetection, batch]
      exporters: [otlp]
    traces:
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
After=network.target

[Service]
ExecStart=/usr/local/bin/otelcol-contrib --config=${OTEL_DIR}/config.yaml
Restart=always
User=root
Group=root
Environment=SYSTEMD_LOG_LEVEL=debug

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
