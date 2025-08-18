# Teleport JIT Access Request Watcher

An automated policy enforcement system for Teleport Just-in-Time access requests that provides configurable resource limits and environment separation controls.

## Features

- **Auto-approval**: Automatically approves compliant access requests
- **Real-time enforcement**: Configurable polling for near real-time policy enforcement  
- **Environment separation**: Prevents users from having both production and research access
- **Resource limits**: Enforces maximum number of approved resources per user
- **Smart locking**: Locks older requests when policies are violated
- **Comprehensive logging**: Debug output shows policy decisions and enforcement actions

## Policies Enforced

### 1. Resource Limit Policy
Users can have a maximum of 3 approved resources at any time. When this limit is exceeded, older requests are locked while the newest requests remain active.

### 2. Environment Conflict Policy
Users cannot have both production and research access simultaneously. The system detects conflicts by matching "prod" and "research" patterns in role names. Single requests containing both environment types are automatically denied, while multi-request conflicts result in older requests being locked.

## Installation

### Prerequisites
- Go 1.21 or later
- Teleport Machine ID identity with appropriate permissions
- Access to Teleport Auth API

### Required Teleport Permissions
Your Machine ID identity requires these permissions:
```yaml
rules:
- resources: ['access_request']
  verbs: ['list', 'read', 'update']
- resources: ['lock']  
  verbs: ['create', 'read', 'update', 'delete']
```

### Build and Deploy

**Build locally and deploy:**
```bash
# Build for your platform
go build -o watcher main.go

# Cross-compile for Linux (if building on Mac/Windows)
GOOS=linux GOARCH=amd64 go build -o watcher-linux main.go
```

**Direct deployment:**
```bash
git clone <your-repo>
cd teleport-jit-watcher
go build -o watcher main.go
```

## Usage

### Basic Usage
```bash
# Run with default settings (checks every 30s, max 3 resources)
./watcher -p your-teleport.example.com:443 -i /path/to/identity

# Enable debug output
./watcher -p your-teleport.example.com:443 -i /path/to/identity -d

# Faster polling for near real-time (every 10 seconds)
./watcher -p your-teleport.example.com:443 -i /path/to/identity -poll-interval=10s
```

### Configuration Options
```bash
-p, --proxy           Teleport auth service address (required)
-i, --identity-file   Path to Machine ID identity file (required)
-m, --max-resources   Maximum resources per user (default: 3)
--poll-interval       How often to check for violations (default: 30s)
--resource-limit      Enable/disable resource limit checking (default: true)
--role-conflicts      Enable/disable environment conflict checking (default: true)
-d, --debug           Enable debug output
```
