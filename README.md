# NGINX Hash Lock

A lightweight NGINX-based authentication proxy that protects web applications using URL hash parameters.

## What It Does

NGINX Hash Lock sits in front of your application and blocks all requests unless they include the correct hash parameter in the URL: `?hash=YOUR_SECRET_HASH`

## Quick Start

### Environment Variables

```yaml
environment:
  AUTH_HASH: "your-secret-hash-here"    # Required: The secret hash for authentication
  BACKEND_HOST: "your-app"               # Required: Backend service hostname
  BACKEND_PORT: "8080"                   # Required: Backend service port
  LISTEN_PORT: "3000"                    # Required: Port NGINX listens on
  ALLOWED_EXTENSIONS: "js,css,png,ico"   # Optional: Allow static files without hash
  ALLOWED_PATHS: "login,api/health"      # Optional: Allow specific paths without hash
```

### Docker Compose Example

```yaml
services:
  hashlock:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: "my-secret-123"
      BACKEND_HOST: "myapp"
      BACKEND_PORT: "8080"
      LISTEN_PORT: "3000"
    ports:
      - "3000:3000"
    depends_on:
      - myapp

  myapp:
    image: your-app:latest
    # No ports exposed - only accessible through hashlock
```

## How It Works

1. **All requests require the hash**: `http://yourserver:3000/?hash=my-secret-123`
2. **Without hash**: Returns 403 Forbidden with custom error page
3. **With correct hash**: Proxies request to your backend application

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

## Real-World Example: Protected Terminal

```yaml
services:
  hashlock:
    image: krizcold/nginxhashlock:latest
    environment:
      AUTH_HASH: $AUTH_HASH          # From CasaOS environment
      BACKEND_HOST: "ttyd"
      BACKEND_PORT: "7681"
      LISTEN_PORT: "3000"
    depends_on:
      - ttyd

  ttyd:
    image: tsl0922/ttyd:latest
    command: ["ttyd", "--writable", "bash"]
    # Not exposed to network - only accessible through hashlock
```

Access terminal at: `http://yourserver:3000/?hash=your-secret`

## Security Notes

- **Hash is visible in URLs**: This is simple authentication, not encryption
- **Use HTTPS in production**: Prevents hash exposure over network
- **Rotate hashes regularly**: Change `AUTH_HASH` if compromised
- **Not a replacement for proper auth**: Use for simple cases or additional protection layer

## Files

- `Dockerfile` - Alpine NGINX container setup
- `nginx.conf` - NGINX configuration template with placeholders
- `entrypoint.sh` - Replaces placeholders with environment variables at startup
- `403.html` - Custom error page shown when hash is missing/wrong

## Configuration Details

The entrypoint script automatically:
1. Reads environment variables
2. Configures NGINX with your settings
3. Sets up optional allowed paths/extensions
4. Starts NGINX

No manual configuration needed - just set environment variables and run.