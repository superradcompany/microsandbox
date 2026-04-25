## FAQ

### General

**What is microsandbox?**
Microsandbox is a lightweight, embeddable sandbox runtime that lets you spin up isolated microVMs in milliseconds. It runs locally on your machine with no server setup or lingering daemons required.

**What platforms are supported?**
- **Linux**: Requires KVM enabled (`/dev/kvm` must exist)
- **macOS**: Requires Apple Silicon (M1/M2/M3/M4)
- Windows is not currently supported

**Is microsandbox production-ready?**
Microsandbox is still in beta. Expect breaking changes, missing features, and rough edges. We recommend it for development and testing environments.

### Getting Started

**How do I install microsandbox?**
```sh
# Install the CLI
curl -fsSL https://install.microsandbox.dev | sh

# Or use npx for quick testing
npx microsandbox run debian
```

**How do I add microsandbox to my project?**
```sh
cargo add microsandbox    # Rust
uv add microsandbox       # Python
npm i microsandbox        # TypeScript
```

**What's the difference between the CLI and SDK?**
The CLI (`msb`) is for quick command-line usage. The SDK embeds microsandbox directly into your code, allowing you to spawn and manage sandboxes programmatically from Rust, Python, or TypeScript.

### Sandboxes

**How do I run a sandbox?**
```sh
msb run debian              # Boot a Debian microVM
msb run python:3.12         # Boot a Python sandbox
msb run ubuntu -- python -c "print('hello')"  # Run a command
```

**How do I execute commands in a running sandbox?**
```sh
msb exec my-sandbox -- python -c "import this"
msb exec my-sandbox -- curl https://example.com
```

**How do I manage sandbox lifecycle?**
```sh
msb ls                      # List all sandboxes
msb ps my-sandbox           # Show status
msb stop my-sandbox         # Stop a sandbox
msb start my-sandbox        # Start a stopped sandbox
msb rm my-sandbox           # Remove a sandbox
```

**Can sandboxes run in detached mode?**
Yes. Sandboxes can run in detached mode for long-lived sessions, making them suitable for persistent agent environments.

### Images

**What images can I use?**
Microsandbox runs standard OCI container images from Docker Hub, GHCR, or any OCI registry:
```sh
msb pull python:3.12        # Pull an image
msb image ls                # List cached images
msb image rm python:3.12    # Remove an image
```

**How do I use custom images?**
Build your OCI image normally and pull it via `msb pull`. Microsandbox supports any OCI-compatible image.

### AI Agents

**How do I connect AI agents to microsandbox?**
Two options:
1. **Agent Skills**: Install skills for your AI coding agent (Claude Code, Cursor, etc.)
   ```sh
   npx skills add superradcompany/skills
   ```
2. **MCP Server**: Connect any MCP-compatible agent
   ```sh
   claude mcp add --transport stdio microsandbox -- npx -y microsandbox-mcp
   ```

### Troubleshooting

**Sandbox fails to start with KVM error**
Ensure KVM is enabled on your Linux system:
```sh
# Check if /dev/kvm exists
ls -la /dev/kvm
# If missing, load the module
sudo modprobe kvm
```

**macOS sandbox fails to boot**
Verify you're running on Apple Silicon (M1/M2/M3/M4). Intel Macs are not supported.

**Image pull fails**
- Check your network connection
- Verify the image name is correct (e.g., `python:3.12` not `python3.12`)
- Try pulling a different image to isolate the issue

**Commands fail inside sandbox**
- Ensure the command exists in the image
- Check sandbox status with `msb ps <name>`
- Verify the sandbox is running before executing commands

**Performance is slow**
- Ensure your system meets requirements (KVM on Linux, Apple Silicon on macOS)
- Close other resource-intensive applications
- Check available disk space and memory

