#!/bin/bash
#
# Honeypot Automated Installation Script
# For Ubuntu 20.04+ servers with Tailscale support
#
# Usage: sudo bash install.sh [docker|native]
#

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/honeypot"
HONEYPOT_USER="honeypot"
DEPLOYMENT_METHOD="${1:-docker}"  # Default to docker
TAILSCALE_IP=""
USE_TAILSCALE=false

# Functions
print_header() {
    echo -e "\n${BLUE}================================================${NC}"
    echo -e "${BLUE}$1${NC}"
    echo -e "${BLUE}================================================${NC}\n"
}

print_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

print_error() {
    echo -e "${RED}[✗]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[i]${NC} $1"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root (use sudo)"
        exit 1
    fi
}

check_ubuntu() {
    if ! grep -q "Ubuntu" /etc/os-release; then
        print_warning "This script is designed for Ubuntu. Your OS may not be supported."
        read -p "Continue anyway? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 1
        fi
    fi
}

detect_tailscale() {
    print_header "Checking for Tailscale"
    
    if command -v tailscale &> /dev/null; then
        TAILSCALE_IP=$(tailscale ip -4 2>/dev/null || echo "")
        
        if [[ -n "$TAILSCALE_IP" ]]; then
            USE_TAILSCALE=true
            print_success "Tailscale detected! IP: $TAILSCALE_IP"
            print_info "This is the IP you'll use for SSH management"
            echo ""
            print_info "Benefits of using Tailscale:"
            echo "  - Secure encrypted tunnel for management"
            echo "  - Works from any IP address"
            echo "  - SSH honeypot can safely run on port 22"
            echo ""
            read -p "Configure SSH to only listen on Tailscale IP? (recommended) (y/n) " -n 1 -r
            echo
            if [[ $REPLY =~ ^[Yy]$ ]]; then
                CONFIGURE_SSH_TAILSCALE=true
            else
                CONFIGURE_SSH_TAILSCALE=false
            fi
        else
            print_warning "Tailscale is installed but not connected"
            print_info "Run: tailscale up"
            print_info "Then re-run this installer"
            exit 1
        fi
    else
        print_info "Tailscale not detected"
        print_warning "For secure management with dynamic IP, consider installing Tailscale first"
        echo ""
        print_info "Quick install: curl -fsSL https://tailscale.com/install.sh | sh"
        echo ""
        read -p "Continue without Tailscale? (y/n) " -n 1 -r
        echo
        if [[ ! $REPLY =~ ^[Yy]$ ]]; then
            exit 0
        fi
    fi
}

detect_architecture() {
    ARCH=$(uname -m)
    if [[ "$ARCH" != "x86_64" ]] && [[ "$ARCH" != "aarch64" ]]; then
        print_warning "Architecture $ARCH may not be fully supported"
    fi
}

check_existing_ssh() {
    SSH_PORT=$(ss -tlnp | grep sshd | grep -oP ':\K\d+' | head -1)
    
    if [[ "$USE_TAILSCALE" == true ]]; then
        print_success "Using Tailscale for SSH management"
        print_info "SSH honeypot can safely run on port 22"
        print_info "Your management SSH will be configured to listen only on Tailscale"
        return
    fi
    
    if [[ "$SSH_PORT" == "22" ]]; then
        print_warning "SSH is currently running on port 22"
        print_warning "The honeypot SSH will also want to use port 22"
        echo ""
        print_info "Options:"
        echo "  1. Change your SSH to another port (e.g., 2222)"
        echo "  2. Run honeypot SSH on alternate port (e.g., 2222)"
        echo "  3. Skip SSH honeypot entirely"
        echo ""
        read -p "Would you like to change your SSH port to 2222 now? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            change_ssh_port
        else
            print_info "You'll need to configure this manually later"
        fi
    fi
}

change_ssh_port() {
    print_info "Backing up SSH config..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    print_info "Changing SSH port to 2222..."
    sed -i 's/^#Port 22/Port 2222/' /etc/ssh/sshd_config
    sed -i 's/^Port 22/Port 2222/' /etc/ssh/sshd_config
    
    # Add if not exists
    if ! grep -q "^Port" /etc/ssh/sshd_config; then
        echo "Port 2222" >> /etc/ssh/sshd_config
    fi
    
    print_info "Restarting SSH (Ubuntu uses 'ssh' service)..."
    systemctl restart ssh
    
    print_success "SSH moved to port 2222"
    print_warning "IMPORTANT: Open a new terminal and test SSH on port 2222 before closing this session!"
    print_info "Test with: ssh -p 2222 $SUDO_USER@localhost"
    echo ""
    read -p "Press Enter when you've confirmed SSH works on port 2222..."
}

install_dependencies() {
    print_info "Updating system packages..."
    apt update
    apt upgrade -y
    
    print_info "Installing base dependencies..."
    apt install -y \
        curl \
        wget \
        git \
        net-tools \
        jq
    
    print_success "Base dependencies installed"
    print_info "Note: Firewall management should be done via Digital Ocean Cloud Firewall"
}

install_docker() {
    print_header "Installing Docker"
    
    if command -v docker &> /dev/null; then
        print_success "Docker already installed"
        docker --version
    else
        print_info "Downloading Docker installation script..."
        curl -fsSL https://get.docker.com -o get-docker.sh
        
        print_info "Installing Docker..."
        sh get-docker.sh
        rm get-docker.sh
        
        print_success "Docker installed"
        docker --version
    fi
    
    # Install Docker Compose
    if command -v docker-compose &> /dev/null; then
        print_success "Docker Compose already installed"
        docker-compose --version
    else
        print_info "Installing Docker Compose..."
        COMPOSE_VERSION=$(curl -s https://api.github.com/repos/docker/compose/releases/latest | grep 'tag_name' | cut -d\" -f4)
        curl -L "https://github.com/docker/compose/releases/download/${COMPOSE_VERSION}/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
        chmod +x /usr/local/bin/docker-compose
        
        print_success "Docker Compose installed"
        docker-compose --version
    fi
    
    # Add user to docker group
    if [[ -n "$SUDO_USER" ]]; then
        usermod -aG docker $SUDO_USER
        print_success "Added $SUDO_USER to docker group"
    fi
}

install_python() {
    print_header "Installing Python Environment"
    
    print_info "Installing Python 3.11 and dependencies..."
    apt install -y \
        python3.11 \
        python3.11-venv \
        python3-pip \
        build-essential \
        libssl-dev \
        libffi-dev \
        python3-dev
    
    # Set python3.11 as default python3
    update-alternatives --install /usr/bin/python3 python3 /usr/bin/python3.11 1
    
    print_success "Python environment installed"
    python3 --version
}

create_honeypot_user() {
    if id "$HONEYPOT_USER" &>/dev/null; then
        print_success "User $HONEYPOT_USER already exists"
    else
        print_info "Creating honeypot user..."
        useradd -r -s /bin/bash -d $INSTALL_DIR -m $HONEYPOT_USER
        print_success "User $HONEYPOT_USER created"
    fi
}

setup_docker_deployment() {
    print_header "Setting up Docker Deployment"
    
    # Create installation directory
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    
    # Extract honeypot files (assume they're in current directory or /tmp)
    if [[ -f "/tmp/honeypot.tar.gz" ]]; then
        print_info "Extracting honeypot files from /tmp..."
        tar -xzf /tmp/honeypot.tar.gz --strip-components=1 -C $INSTALL_DIR
    elif [[ -f "$(pwd)/honeypot.tar.gz" ]]; then
        print_info "Extracting honeypot files from current directory..."
        tar -xzf "$(pwd)/honeypot.tar.gz" --strip-components=1 -C $INSTALL_DIR
    else
        print_error "honeypot.tar.gz not found in /tmp or current directory"
        print_info "Please place honeypot.tar.gz in /tmp or the current directory"
        exit 1
    fi
    
    print_success "Honeypot files extracted"
    
    # Create data directory
    mkdir -p $INSTALL_DIR/honeypot_data
    
    # Set permissions
    chown -R $SUDO_USER:$SUDO_USER $INSTALL_DIR
    
    print_info "Building Docker images..."
    cd $INSTALL_DIR
    docker-compose build
    
    print_success "Docker images built"
}

setup_native_deployment() {
    print_header "Setting up Native Deployment"
    
    # Create installation directory
    mkdir -p $INSTALL_DIR
    cd $INSTALL_DIR
    
    # Extract honeypot files
    if [[ -f "/tmp/honeypot.tar.gz" ]]; then
        print_info "Extracting honeypot files from /tmp..."
        tar -xzf /tmp/honeypot.tar.gz --strip-components=1 -C $INSTALL_DIR
    elif [[ -f "$(pwd)/honeypot.tar.gz" ]]; then
        print_info "Extracting honeypot files from current directory..."
        tar -xzf "$(pwd)/honeypot.tar.gz" --strip-components=1 -C $INSTALL_DIR
    else
        print_error "honeypot.tar.gz not found in /tmp or current directory"
        exit 1
    fi
    
    print_success "Honeypot files extracted"
    
    # Create virtual environment
    print_info "Creating Python virtual environment..."
    python3.11 -m venv $INSTALL_DIR/venv
    
    # Install Python packages
    print_info "Installing Python packages..."
    $INSTALL_DIR/venv/bin/pip install --upgrade pip
    $INSTALL_DIR/venv/bin/pip install -r $INSTALL_DIR/requirements.txt
    
    print_success "Python packages installed"
    
    # Create data directory
    mkdir -p $INSTALL_DIR/honeypot_data
    
    # Set permissions
    chown -R $HONEYPOT_USER:$HONEYPOT_USER $INSTALL_DIR
    
    # Generate default config
    print_info "Generating default configuration..."
    sudo -u $HONEYPOT_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/honeypot.py &
    sleep 3
    pkill -f honeypot.py
    
    # Allow Python to bind privileged ports
    print_info "Configuring port binding capabilities..."
    setcap 'cap_net_bind_service=+ep' $INSTALL_DIR/venv/bin/python3.11
    
    print_success "Native deployment configured"
}

create_systemd_service() {
    print_header "Creating Systemd Service"
    
    if [[ "$DEPLOYMENT_METHOD" == "docker" ]]; then
        # Docker service
        cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=INetSim Honeypot (Docker)
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
WorkingDirectory=$INSTALL_DIR
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
User=$SUDO_USER

[Install]
WantedBy=multi-user.target
EOF
    else
        # Native service
        cat > /etc/systemd/system/honeypot.service << EOF
[Unit]
Description=INetSim Honeypot
After=network.target

[Service]
Type=simple
User=$HONEYPOT_USER
WorkingDirectory=$INSTALL_DIR
Environment="PATH=$INSTALL_DIR/venv/bin"
ExecStart=$INSTALL_DIR/venv/bin/python $INSTALL_DIR/honeypot.py
Restart=always
RestartSec=10
StandardOutput=append:$INSTALL_DIR/honeypot.log
StandardError=append:$INSTALL_DIR/honeypot.log

# Security hardening
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=$INSTALL_DIR/honeypot_data
AmbientCapabilities=CAP_NET_BIND_SERVICE

[Install]
WantedBy=multi-user.target
EOF
    fi
    
    systemctl daemon-reload
    systemctl enable honeypot
    
    print_success "Systemd service created and enabled"
}

configure_ssh_for_tailscale() {
    if [[ "$USE_TAILSCALE" != true ]] || [[ "$CONFIGURE_SSH_TAILSCALE" != true ]]; then
        return
    fi
    
    print_header "Configuring SSH for Tailscale Only"
    
    print_info "Backing up SSH config..."
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.tailscale-backup
    
    print_info "Configuring SSH to listen only on Tailscale IP: $TAILSCALE_IP"
    
    # Add ListenAddress for Tailscale
    if ! grep -q "^ListenAddress $TAILSCALE_IP" /etc/ssh/sshd_config; then
        echo "" >> /etc/ssh/sshd_config
        echo "# Listen only on Tailscale interface" >> /etc/ssh/sshd_config
        echo "ListenAddress $TAILSCALE_IP" >> /etc/ssh/sshd_config
    fi
    
    print_info "Testing SSH configuration..."
    if sshd -t; then
        print_success "SSH configuration is valid"
        
        print_warning "About to restart SSH service"
        print_warning "Make sure you can connect via Tailscale IP: $TAILSCALE_IP"
        echo ""
        print_info "Test in a NEW terminal BEFORE continuing:"
        print_info "  ssh root@$TAILSCALE_IP"
        echo ""
        read -p "Press Enter when you've confirmed Tailscale SSH works..."
        
        print_info "Restarting SSH..."
        systemctl restart ssh
        
        print_success "SSH now only listens on Tailscale!"
        print_success "Management: ssh root@$TAILSCALE_IP"
        print_success "Port 22 public traffic will go to honeypot"
    else
        print_error "SSH configuration test failed!"
        print_info "Restoring backup..."
        cp /etc/ssh/sshd_config.tailscale-backup /etc/ssh/sshd_config
        systemctl restart ssh
    fi
}

show_firewall_instructions() {
    print_header "Digital Ocean Firewall Configuration"
    
    if [[ "$USE_TAILSCALE" == true ]]; then
        print_success "Using Tailscale - Firewall setup is simple!"
        echo ""
        print_info "Configure your Digital Ocean Cloud Firewall with these rules:"
        echo ""
        echo "Inbound Rules:"
        echo "  Type        Protocol    Ports       Sources"
        echo "  ─────────────────────────────────────────────────────"
        echo "  Custom      TCP         80          All IPv4, All IPv6"
        echo "  Custom      TCP         21          All IPv4, All IPv6"
        echo "  Custom      TCP         22          All IPv4, All IPv6"
        echo "  Custom      TCP         53          All IPv4, All IPv6"
        echo "  Custom      TCP         5601        All IPv4, All IPv6 (Kibana - optional)"
        echo ""
        echo "Outbound Rules:"
        echo "  All TCP     TCP         All         All IPv4, All IPv6"
        echo "  All UDP     UDP         All         All IPv4, All IPv6"
        echo ""
        print_info "Your SSH is protected via Tailscale tunnel!"
        print_success "Management: ssh root@$TAILSCALE_IP"
    else
        print_warning "Tailscale not configured"
        echo ""
        print_info "Configure your Digital Ocean Cloud Firewall:"
        echo ""
        echo "Inbound Rules:"
        echo "  Type        Protocol    Ports       Sources"
        echo "  ─────────────────────────────────────────────────────"
        
        if [[ "$SSH_PORT" == "2222" ]]; then
            echo "  SSH         TCP         2222        Your IP only"
        else
            echo "  SSH         TCP         22          Your IP only"
        fi
        
        echo "  Custom      TCP         80          All IPv4, All IPv6"
        echo "  Custom      TCP         21          All IPv4, All IPv6"
        echo "  Custom      TCP         53          All IPv4, All IPv6"
        echo "  Custom      TCP         5601        All IPv4, All IPv6 (optional)"
        echo ""
        print_warning "Make sure to restrict SSH to your IP address only!"
    fi
    
    echo ""
    print_info "To configure:"
    echo "  1. Go to Digital Ocean Dashboard"
    echo "  2. Networking → Firewalls"
    echo "  3. Create or update firewall with rules above"
    echo "  4. Apply to your honeypot droplet"
    echo ""
}

setup_logrotate() {
    print_header "Configuring Log Rotation"
    
    cat > /etc/logrotate.d/honeypot << EOF
$INSTALL_DIR/honeypot.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 0644 $HONEYPOT_USER $HONEYPOT_USER
}

$INSTALL_DIR/honeypot_data/events.jsonl {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
}
EOF
    
    print_success "Log rotation configured"
}

create_helper_scripts() {
    print_header "Creating Helper Scripts"
    
    # Status script
    cat > /usr/local/bin/honeypot-status << 'EOF'
#!/bin/bash
echo "=== Honeypot Status ==="
systemctl status honeypot --no-pager
echo ""
echo "=== Recent Events ==="
tail -5 /opt/honeypot/honeypot_data/events.jsonl 2>/dev/null | jq -r '.event_type + " from " + .source_ip'
echo ""
echo "=== Disk Usage ==="
du -sh /opt/honeypot/honeypot_data/* 2>/dev/null
EOF
    chmod +x /usr/local/bin/honeypot-status
    
    # Report script
    cat > /usr/local/bin/honeypot-report << 'EOF'
#!/bin/bash
cd /opt/honeypot
if [[ "$1" == "docker" ]]; then
    docker-compose exec honeypot python analyze_telemetry.py ./honeypot_data
else
    source venv/bin/activate
    python analyze_telemetry.py ./honeypot_data
fi
EOF
    chmod +x /usr/local/bin/honeypot-report
    
    # Logs script
    cat > /usr/local/bin/honeypot-logs << 'EOF'
#!/bin/bash
if [[ "$1" == "docker" ]]; then
    docker-compose -f /opt/honeypot/docker-compose.yml logs -f honeypot
else
    journalctl -u honeypot -f
fi
EOF
    chmod +x /usr/local/bin/honeypot-logs
    
    print_success "Helper scripts created"
    print_info "  honeypot-status  - View status and recent events"
    print_info "  honeypot-report  - Generate analysis report"
    print_info "  honeypot-logs    - View live logs"
}

start_honeypot() {
    print_header "Starting Honeypot"
    
    systemctl start honeypot
    sleep 3
    
    if systemctl is-active --quiet honeypot; then
        print_success "Honeypot started successfully"
    else
        print_error "Honeypot failed to start"
        print_info "Check logs with: journalctl -u honeypot -n 50"
        exit 1
    fi
}

run_tests() {
    print_header "Running Tests"
    
    print_info "Waiting for services to initialize..."
    sleep 5
    
    if [[ "$DEPLOYMENT_METHOD" == "docker" ]]; then
        print_info "Testing services..."
        docker-compose -f $INSTALL_DIR/docker-compose.yml exec -T honeypot python test_honeypot.py || true
    else
        print_info "Testing services..."
        sudo -u $HONEYPOT_USER $INSTALL_DIR/venv/bin/python $INSTALL_DIR/test_honeypot.py || true
    fi
}

print_summary() {
    print_header "Installation Complete!"
    
    echo -e "${GREEN}Honeypot is now running!${NC}"
    echo ""
    echo "=== Service Information ==="
    echo "  Method: $DEPLOYMENT_METHOD"
    echo "  Location: $INSTALL_DIR"
    echo "  Data: $INSTALL_DIR/honeypot_data"
    echo ""
    
    if [[ "$USE_TAILSCALE" == true ]]; then
        echo "=== Tailscale Configuration ==="
        echo "  Tailscale IP: $TAILSCALE_IP"
        echo "  Management SSH: ssh root@$TAILSCALE_IP"
        echo ""
        print_success "Your SSH is secured via Tailscale!"
        echo ""
    fi
    
    echo "=== Active Services ==="
    echo "  HTTP:  Port 80"
    echo "  SSH:   Port 22"
    echo "  FTP:   Port 21"
    echo "  DNS:   Port 53"
    echo ""
    
    if [[ "$DEPLOYMENT_METHOD" == "docker" ]]; then
        echo "=== Optional Services ==="
        echo "  ElasticSearch: http://localhost:9200"
        
        if [[ "$USE_TAILSCALE" == true ]]; then
            PUBLIC_IP=$(curl -s https://api.ipify.org || echo "YOUR_DROPLET_IP")
            echo "  Kibana:        http://$PUBLIC_IP:5601"
        else
            echo "  Kibana:        http://$(hostname -I | awk '{print $1}'):5601"
        fi
        echo ""
    fi
    
    echo "=== Management Commands ==="
    echo "  View status:     honeypot-status"
    echo "  Generate report: honeypot-report $DEPLOYMENT_METHOD"
    echo "  View logs:       honeypot-logs $DEPLOYMENT_METHOD"
    echo ""
    echo "  Start:           sudo systemctl start honeypot"
    echo "  Stop:            sudo systemctl stop honeypot"
    echo "  Restart:         sudo systemctl restart honeypot"
    echo "  Status:          sudo systemctl status honeypot"
    echo ""
    echo "=== Data Locations ==="
    echo "  Events:  $INSTALL_DIR/honeypot_data/events.jsonl"
    echo "  Samples: $INSTALL_DIR/honeypot_data/samples/"
    echo "  Logs:    $INSTALL_DIR/honeypot.log"
    echo ""
    
    print_warning "Important Security Notes:"
    echo "  - This honeypot will attract attackers"
    echo "  - Monitor disk space regularly"
    echo "  - Review captured data frequently"
    
    if [[ "$USE_TAILSCALE" == true ]]; then
        echo "  - Always connect via Tailscale: ssh root@$TAILSCALE_IP"
        echo "  - Your real SSH is NOT exposed to the public internet"
    else
        echo "  - Keep your management SSH secure"
        echo "  - Use Digital Ocean Cloud Firewall to restrict SSH access"
    fi
    echo ""
    
    print_info "Next Steps:"
    echo "  1. Configure Digital Ocean Cloud Firewall (see instructions above)"
    echo "  2. Monitor events: tail -f $INSTALL_DIR/honeypot_data/events.jsonl"
    echo "  3. Generate report: honeypot-report $DEPLOYMENT_METHOD"
    
    if [[ "$DEPLOYMENT_METHOD" == "docker" ]]; then
        PUBLIC_IP=$(curl -s https://api.ipify.org || echo "YOUR_DROPLET_IP")
        echo "  4. Access Kibana: http://$PUBLIC_IP:5601"
    fi
    
    if [[ "$USE_TAILSCALE" == true ]]; then
        echo ""
        print_success "Remember: ssh root@$TAILSCALE_IP for management"
    fi
    echo ""
    
    print_success "Happy hunting!"
}

# Main installation flow
main() {
    print_header "INetSim Honeypot Installer"
    
    echo "Deployment method: $DEPLOYMENT_METHOD"
    echo ""
    
    check_root
    check_ubuntu
    detect_architecture
    detect_tailscale
    
    # Prompt for confirmation
    read -p "Continue with installation? (y/n) " -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        exit 0
    fi
    
    # Installation steps
    check_existing_ssh
    install_dependencies
    
    if [[ "$DEPLOYMENT_METHOD" == "docker" ]]; then
        install_docker
        setup_docker_deployment
    else
        install_python
        create_honeypot_user
        setup_native_deployment
    fi
    
    create_systemd_service
    configure_ssh_for_tailscale
    show_firewall_instructions
    setup_logrotate
    create_helper_scripts
    start_honeypot
    run_tests
    print_summary
}

# Show usage if help requested
if [[ "$1" == "-h" ]] || [[ "$1" == "--help" ]]; then
    echo "Usage: sudo bash install.sh [docker|native]"
    echo ""
    echo "Options:"
    echo "  docker  - Install using Docker (recommended)"
    echo "  native  - Install using native Python"
    echo ""
    echo "Prerequisites:"
    echo "  - Ubuntu 20.04 or newer"
    echo "  - Root access"
    echo "  - honeypot.tar.gz in /tmp or current directory"
    echo ""
    exit 0
fi

# Run main installation
main
