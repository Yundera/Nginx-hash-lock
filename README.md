# NGINX Hash Lock

A lightweight NGINX-based authentication proxy that protects web applications using **hash-based authentication**, **username/password authentication**, and **dynamic path allowlisting** for backend services.

## What It Does

NGINX Hash Lock sits in front of your application and provides flexible authentication options:

1. **Hash Authentication**: Block requests unless they include `?hash=YOUR_SECRET_HASH`
2. **Username/Password Authentication**: Show a login page requiring credentials
3. **Both Methods**: Accept either hash parameter OR valid login session
4. **Dynamic Path Allowlisting**: Automatically grant temporary access to specific resources
5. **No Authentication**: Optionally disable security entirely

## Quick Start

### Environment Variables

**Core Settings:**
```yaml
environment:
  BACKEND_HOST: "your-app"               # Required: Backend service hostname
  BACKEND_PORT: "8080"                   # Required: Backend service port
  LISTEN_PORT: "3000"                    # Required: Port NGINX listens on
```

**Authentication Options:**
```yaml
  # Hash-based authentication (automatically provided by CasaOS)
  AUTH_HASH: $AUTH_HASH                  # Optional: For hash-based auth (CasaOS provides this)
                                         # Important: Also add /?hash=$AUTH_HASH to x-casaos.index

  # Username/Password authentication
  USER: "admin"                          # Optional: Username for login page
  PASSWORD: "your-secure-password"       # Optional: Password for login page
  SESSION_DURATION_HOURS: "720"          # Optional: Session duration in hours (default: 720 = 30 days)
```

**Bypass Options:**
```yaml
  ALLOWED_EXTENSIONS: "js,css,png,ico"   # Optional: Allow static files without auth
  ALLOWED_PATHS: "login,api/health"      # Optional: Allow specific paths without auth
```

**Dynamic Path Allowlisting:**
```yaml
  DYNAMIC_PATHS_FILE: "/tmp/dynamic_paths/allowed.txt"  # Optional: Enable dynamic allowlisting
  DYNAMIC_PATHS_TTL: "300"                              # Optional: TTL in seconds (default: 300)
```

## Authentication Modes

The system automatically selects the authentication mode based on which environment variables are configured:

| AUTH_HASH | USER/PASSWORD | Mode | Behavior |
|-----------|---------------|------|----------|
| ✅ Defined | ❌ Undefined | **Hash Only** | Require `?hash=` parameter, show 403 page on failure |
| ❌ Undefined | ✅ Defined | **Credentials Only** | Show login page, require username/password, no hash option |
| ✅ Defined | ✅ Defined | **Both Methods** | Accept either hash parameter OR valid login session |
| ❌ Undefined | ❌ Undefined | **No Authentication** | Allow all requests (security disabled) |

### Important for CasaOS Deployments

**`$AUTH_HASH` is automatically provided by Yundera's CasaOS** - you don't need to manually configure it. However, you must:

1. **Include `$AUTH_HASH` in the environment** (CasaOS will populate it)
2. **Add `?hash=$AUTH_HASH` to the index** in x-casaos metadata

Example:
```yaml
environment:
  AUTH_HASH: $AUTH_HASH  # CasaOS provides this automatically

x-casaos:
  index: /?hash=$AUTH_HASH  # Important! Pass hash to URL
```

This ensures the Dashboard button automatically includes the authentication hash.

## Docker Compose Examples

### Example 1: Hash-Only Authentication (CasaOS)

```yaml
services:
  hashlock:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # CasaOS provides this
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "3000"
    ports:
      - "3000:3000"
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /?hash=$AUTH_HASH             # IMPORTANT: Include hash in URL
  webui_port: 3000
```

**CasaOS Dashboard button:** Automatically opens with authentication hash

### Example 2: Username/Password Only (CasaOS)

```yaml
services:
  hashlock:
    image: krizcold/nginxhashlock:latest
    environment:
      USER: $USER                      # Set in CasaOS or compose
      PASSWORD: $PASSWORD              # Set in CasaOS or compose
      SESSION_DURATION_HOURS: "168"    # 1 week
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "3000"
    ports:
      - "3000:3000"
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /                             # No hash needed - shows login page
  webui_port: 3000
```

**CasaOS Dashboard button:** Opens login page → Enter credentials → 1-week session

### Example 3: Both Methods (Hash OR Login) - CasaOS

```yaml
services:
  hashlock:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # Option 1: CasaOS hash
      USER: $USER                      # Option 2: Password auth
      PASSWORD: $PASSWORD
      SESSION_DURATION_HOURS: "720"    # 30 days
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "3000"
    ports:
      - "3000:3000"
    depends_on:
      - myapp

  myapp:
    image: your-app:latest

x-casaos:
  main: hashlock
  index: /?hash=$AUTH_HASH             # Dashboard uses hash (quick access)
  webui_port: 3000
```

**CasaOS Dashboard button:** Opens with hash (quick access)
**Alternative:** Visit without hash → Login page → Enter credentials → 30-day session

## How It Works

### Hash Authentication Mode
1. **With correct hash**: `http://yourserver:3000/?hash=my-secret-123` → Access granted
2. **Without hash**: Returns 403 Forbidden with custom error page

### Username/Password Mode
1. **First visit**: Shows login page
2. **Enter credentials**: Username and password validated (2-second delay on failure for anti-brute-force)
3. **Session created**: Secure cookie with configurable expiration (default: 30 days)
4. **Subsequent visits**: Automatic access with valid session cookie

### Both Methods Mode
1. **With hash parameter**: Instant access (no login required)
2. **With valid session**: Access granted
3. **Without either**: Redirected to login page

## Optional Features

### Allow Static Assets (No Hash Required)

Useful for CSS, JavaScript, images:

```yaml
ALLOWED_EXTENSIONS: "js,css,png,ico,svg,woff,woff2"
```

Now `/styles/app.css` works without a hash, but `/admin` still requires it.

### Allow Public Paths (No Hash Required)

Useful for login pages or public APIs:

```yaml
ALLOWED_PATHS: "login,about,api/health,api/public"
```

Now `/login` and `/api/health` work without a hash, but `/dashboard` still requires it.

**Important - Reserved Paths:**
- `/nhl-auth/` is reserved for internal authentication endpoints and cannot be used in ALLOWED_PATHS
- `/login` is reserved for the login page
- All other paths are available for use in ALLOWED_PATHS
- The `/auth` path is now available for your application (previously reserved)

## Dynamic Path Allowlisting (Advanced Feature)

### What Problem Does It Solve?

Many applications have backend services that need to access specific resources but cannot authenticate:
- **Media servers**: FFmpeg/transcoder needs to access video files for streaming
- **Download managers**: Backend services need to fetch files
- **API consumers**: Services that cannot handle cookies or auth tokens
- **Content processors**: Tools that need temporary access to specific resources

### How It Works

The dynamic allowlist system automatically grants temporary access to paths matching a specific pattern (40-character hexadecimal strings) after an authenticated user first accesses them.

#### Architecture
```
1. Authenticated user → Requests /abc123.../file → Auto-added to allowlist
2. Backend service → Requests same path → Allowed (within TTL window)
3. After TTL expires → Path removed → Requires re-authentication
```

#### Path Pattern
The system detects paths containing 40-character hex strings:
- Git commit hashes: `/commits/a1b2c3d4e5f6789012345678901234567890abcd`
- File checksums: `/files/0123456789abcdef0123456789abcdef01234567`
- Torrent hashes: `/8187fed409fc90636a87a44b706ade4865e83bc9/video.mp4`
- Session tokens: `/api/session/fedcba9876543210fedcba9876543210fedcba98`

### Configuration

#### 1. Enable Dynamic Allowlisting
```yaml
environment:
  DYNAMIC_PATHS_FILE: "/tmp/dynamic_paths/allowed.txt"
  DYNAMIC_PATHS_TTL: "300"  # 5 minutes
```

#### 2. Share Volume Between Containers
```yaml
volumes:
  dynamic_paths:
    driver: local

services:
  authproxy:
    image: krizcold/nginxhashlock:latest
    volumes:
      - dynamic_paths:/tmp/dynamic_paths
    environment:
      DYNAMIC_PATHS_FILE: "/tmp/dynamic_paths/allowed.txt"

  backend:
    image: your-app:latest
    volumes:
      - dynamic_paths:/tmp/dynamic_paths  # Backend can read allowlist
```

### Real Example: Media Streaming with Authentication

```yaml
services:
  # Authentication proxy with dynamic allowlisting
  streamauth:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH
      BACKEND_HOST: "streamer"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "3000"
      # Enable dynamic allowlisting for media files
      DYNAMIC_PATHS_FILE: "/tmp/dynamic_paths/allowed.txt"
      DYNAMIC_PATHS_TTL: "600"  # 10 minutes for video streaming
      # Allow static assets without auth
      ALLOWED_EXTENSIONS: "js,css,png,jpg,ico,m3u8,ts"
      ALLOWED_PATHS: "api/status,health"
    volumes:
      - media_allowlist:/tmp/dynamic_paths
    ports:
      - "3000:3000"

  # Media server (e.g., Stremio, Jellyfin, Plex)
  streamer:
    image: media-server:latest
    volumes:
      - media_allowlist:/tmp/dynamic_paths
      - media_files:/media
```

#### How It Works in Practice:

1. **User visits**: `https://app.example.com/?hash=secret123`
   - Session established via hash authentication

2. **User clicks play** on video with hash `8187fed409fc90636a87a44b706ade4865e83bc9`
   - Browser requests: `/8187fed409fc90636a87a44b706ade4865e83bc9/video.mp4`
   - User is authenticated → Path added to allowlist
   - Video starts playing

3. **Transcoder needs access** (no authentication capability):
   - FFmpeg requests: `/8187fed409fc90636a87a44b706ade4865e83bc9/video.mp4`
   - Path is in allowlist → Access granted
   - Transcoding works without authentication

4. **After 10 minutes** (TTL expires):
   - Path removed from allowlist
   - Future requests require re-authentication

### Security Considerations

#### TTL Configuration
- **Shorter TTL (60-300s)**: More secure, may require re-authentication
- **Longer TTL (600-3600s)**: Better UX for long-running operations
- **Recommended**:
  - Media streaming: 5-10 minutes
  - File downloads: 15-30 minutes
  - API operations: 1-2 minutes

#### Path Security
- Only 40-character hex patterns are allowed (prevents arbitrary path exposure)
- Each path is individually allowlisted (not wildcards)
- Automatic cleanup of expired paths

#### Volume Security
- Allowlist file should be in a tmpfs or volatile mount
- Backend services need read access only
- Consider using Docker secrets for production

### Advanced: Custom Path Patterns

To match different patterns, modify the entrypoint.sh:

```bash
# Default: 40-character hex (git commits, checksums, etc.)
location ~ "^/[a-f0-9]{40}" {
    # Dynamic allowlist logic
}

# Custom: UUID pattern
location ~ "^/[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}" {
    # Dynamic allowlist logic
}

# Custom: Specific prefix
location ~ "^/downloads/[a-zA-Z0-9]{32}" {
    # Dynamic allowlist logic
}
```

### Monitoring Dynamic Allowlist

```bash
# View current allowed paths
docker exec streamauth cat /tmp/dynamic_paths/allowed.txt

# Count active paths
docker exec streamauth wc -l /tmp/dynamic_paths/allowed.txt

# Watch allowlist in real-time
docker exec streamauth tail -f /tmp/dynamic_paths/allowed.txt
```

### Troubleshooting

#### Media/Files Not Loading
1. Check if path matches pattern (40-char hex)
2. Verify allowlist file is accessible
3. Ensure TTL is appropriate for your use case
4. Check container logs for auth failures

#### Performance Issues
1. Increase TTL for frequently accessed resources
2. Use tmpfs for allowlist file (in-memory)
3. Monitor allowlist size (auto-cleanup keeps it small)

## Real-World Examples: Protected Terminal (CasaOS)

### Hash-Only Authentication (safe-terminal-app-nginxhashlock.yml)
Quick access via URL hash parameter - Dashboard button includes hash automatically:

```yaml
services:
  yunderaterminal:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # CasaOS provides this
      BACKEND_HOST: "ttyd"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "3000"
    depends_on:
      - ttyd

  ttyd:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminal
  index: /?hash=$AUTH_HASH             # IMPORTANT: Pass hash to URL
  webui_port: 3000
```

**CasaOS Dashboard:** Automatically opens with hash → Instant access

### Password Authentication (safe-terminal-app-nginxhashpass.yml)
Session-based login with username/password:

```yaml
services:
  yunderaterminalpass:
    image: krizcold/nginxhashlock:latest
    environment:
      USER: $USER                      # Set in CasaOS
      PASSWORD: $PASSWORD              # Set in CasaOS
      SESSION_DURATION_HOURS: "720"    # 30 days
      BACKEND_HOST: "ttydpass"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "3000"
    depends_on:
      - ttydpass

  ttydpass:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminalpass
  index: /                             # No hash - show login page
  webui_port: 3000
```

**CasaOS Dashboard:** Opens login page → Enter credentials → 30-day session

### Dual Authentication (safe-terminal-app-nginxhashboth.yml)
Accept BOTH hash OR password for maximum flexibility:

```yaml
services:
  yunderaterminalboth:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH            # Option 1: CasaOS hash (Dashboard)
      USER: $USER                      # Option 2: Login page
      PASSWORD: $PASSWORD
      SESSION_DURATION_HOURS: "168"    # 1 week
      BACKEND_HOST: "ttydboth"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "3000"
    depends_on:
      - ttydboth

  ttydboth:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "chroot", "/host", "bash"]

x-casaos:
  main: yunderaterminalboth
  index: /?hash=$AUTH_HASH             # Dashboard uses hash for quick access
  webui_port: 3000
```

**CasaOS Dashboard:** Opens with hash → Instant access
**Alternative:** Visit without hash parameter → Login page → 1-week session

## Security Features

### Username/Password Authentication
- **Session-based authentication**: Secure httpOnly cookies prevent XSS attacks
- **Anti-brute-force protection**: 2-second delay on failed login attempts
- **Configurable session duration**: Set `SESSION_DURATION_HOURS` to control session lifetime
- **Automatic session cleanup**: Expired sessions are automatically removed from memory

### Hash Authentication
- **URL parameter validation**: Simple and effective for trusted environments
- **No server-side state**: Stateless authentication

## Security Notes

- **Hash is visible in URLs**: This is simple authentication, not encryption. Use HTTPS in production.
- **Use HTTPS in production**: Prevents hash and cookie exposure over network
- **Strong passwords**: Use strong passwords for username/password authentication
- **Session security**: Sessions are stored in memory and cleared on container restart
- **Rotate credentials**: Change `AUTH_HASH` or `PASSWORD` if compromised
- **Not a replacement for OAuth/SAML**: Use for simple cases or as an additional protection layer

## Files

### Core Files
- `Dockerfile` - Debian NGINX container with Node.js
- `nginx.conf` - NGINX configuration template with auth_request support
- `entrypoint.sh` - Configures authentication mode and starts services
- `403.html` - Custom error page for hash authentication failures
- `login.html` - Login page for username/password authentication

### Authentication Service
- `auth-service/app.js` - Express.js authentication service
- `auth-service/package.json` - Node.js dependencies

### Dynamic Allowlist Services (when DYNAMIC_PATHS_FILE is set)
- `dynamic-auth-checker.sh` - Node.js service checking if paths are in allowlist (port 9998)
- `auto-add-hash.sh` - Node.js service for auto-adding authenticated paths (port 9997)
- Dynamic paths stored in file specified by `DYNAMIC_PATHS_FILE`
- Format: `hash:expiry_timestamp` (one per line)

## Configuration Details

The entrypoint script automatically:
1. Determines authentication mode based on environment variables
2. Starts the Node.js auth service if credentials are configured
3. Starts dynamic allowlist services if DYNAMIC_PATHS_FILE is set
4. Generates appropriate NGINX configuration for the selected auth mode
5. Configures optional allowed paths/extensions
6. Starts NGINX with the generated configuration

No manual configuration needed - just set environment variables and run.

### Services Started Based on Configuration

| Configuration | Auth Service<br>(port 9999) | Dynamic Checker<br>(port 9998) | Auto-Add Service<br>(port 9997) | NGINX |
|--------------|------------|----------------|-----------------|-------|
| Hash only | ❌ | ❌ | ❌ | ✅ |
| Credentials only | ✅ | ❌ | ❌ | ✅ |
| Both methods | ✅ | ❌ | ❌ | ✅ |
| Hash + Dynamic paths | ❌ | ✅ | ✅ | ✅ |
| Credentials + Dynamic paths | ✅ | ✅ | ✅ | ✅ |
| Both + Dynamic paths | ✅ | ✅ | ✅ | ✅ |

## Technical Architecture

### Authentication Flow

**Hash-Only Mode:**
```
Request → NGINX checks ?hash parameter → Grant/Deny → Backend/403
```

**Credentials-Only Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session → Backend
  └─ No/invalid session → Redirect to /login → Validate credentials → Set cookie → Backend
```

**Both Methods Mode:**
```
Request → NGINX auth_request to auth service → Check session cookie
  ├─ Valid session → Backend
  └─ No/invalid session → Check ?hash parameter
      ├─ Valid hash → Backend
      └─ Invalid/missing → Redirect to /login
```

**Dynamic Allowlist Mode (when enabled):**
```
Request matching /[40-hex-chars]/ pattern → Auto-Add Service (port 9997)
  ├─ Hash in allowlist → Grant access
  └─ Hash not in allowlist → Check authentication
      ├─ Authenticated → Add to allowlist → Grant access
      └─ Not authenticated → Deny (403)

Parallel: Dynamic Checker Service (port 9998)
  └─ Validates paths in allowlist for unauthenticated requests
```

### Session Management
- Sessions stored in-memory (Node.js auth service)
- Automatic cleanup of expired sessions every hour
- Session IDs are cryptographically secure (32 random bytes)
- Sessions survive nginx reload but not container restart

## Application Compatibility

NGINX Hash Lock with dynamic allowlisting has been tested with:
- **Stremio** - Media streaming with torrent hashes
- **Jellyfin/Emby** - Media servers with transcoding
- **Plex** - Media server with remote access
- **qBittorrent** - Download manager
- **Transmission** - Torrent client
- **File browsers** - Filebrowser, FileShelter
- **Code servers** - VS Code Server, code-server
- **Terminal apps** - ttyd, wetty, gotty

The dynamic allowlist feature is particularly useful for:
- Applications with background workers/transcoders
- Services that make unauthenticated API calls
- Media servers that need to stream content
- Download managers with web interfaces
- Any app where backend services need temporary resource access

## Quick note to update source code:

```bash
docker build -t krizcold/nginxhashlock:latest .
docker push krizcold/nginxhashlock:latest
```
