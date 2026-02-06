
---

## Process Manipulation Detector

**File:** `src/detectors/process-manipulation.ts`

Detects attempts to manipulate running processes through debugging, injection, memory manipulation, and other process control techniques. These operations are commonly used by attackers to evade detection, escalate privileges, or inject malicious code.

### What It Detects

#### 1. Debugger Attachment

Attaching debuggers to running processes:

- **gdb attachment:**
  - `gdb -p 1234` - Attach to PID
  - `gdb --pid 1234`
  - `gdb --attach 1234`
  - `gdb /usr/bin/program 5678` - Attach to program with PID
  - `gdb -p $(pgrep ssh)` - Attach via pgrep

- **strace attachment:**
  - `strace -p 1234` - Trace system calls
  - `strace --attach 1234`
  - `strace -p $(pgrep nginx)`

- **lldb attachment:**
  - `lldb -p 1234`
  - `lldb --attach-pid 1234`
  - `lldb --attach-name nginx`

**Why dangerous:** Debugger attachment allows:
- Reading process memory (passwords, tokens, secrets)
- Modifying process behavior
- Injecting code
- Bypassing security controls
- Extracting proprietary algorithms

#### 2. Memory Dumping

Reading or dumping process memory:

- **gcore:**
  - `gcore 1234` - Generate core dump
  - `gcore -o dumpfile 5678`
  - `gcore $(pgrep sshd)`

- **/proc memory access:**
  - `cat /proc/1234/mem` - Read process memory
  - `cat /proc/$PID/mem`
  - `dd if=/proc/1234/mem of=dump.bin`
  - `strings /proc/1234/mem` - Extract strings

- **/proc/maps reading:**
  - `cat /proc/1234/maps` - Memory layout
  - `grep heap /proc/1234/maps`

- **Bulk scraping:**
  - `for pid in /proc/[0-9]*; do cat $pid/mem; done`
  - `find /proc -name mem`
  - `find /proc -name maps`

**Why dangerous:** Memory dumps reveal:
- Credentials in memory
- Encryption keys
- Session tokens
- Database passwords
- API keys
- Proprietary data

#### 3. ptrace Usage

Direct use of ptrace system call:

- `ptrace PTRACE_ATTACH`
- `ptrace PTRACE_PEEKDATA`
- Python: `import ptrace`, `ptrace.attach(1234)`
- Perl: `use ptrace`
- LD_PRELOAD with ptrace libraries

**Why dangerous:** ptrace enables:
- Low-level process control
- Memory manipulation
- System call interception
- Rootkit functionality

#### 4. Process Injection

Injecting code into running processes:

- **Writing to /proc/[pid]/mem:**
  - `echo "code" > /proc/1234/mem`
  - `printf "\\x90\\x90" > /proc/5678/mem`
  - `dd if=shellcode.bin of=/proc/1234/mem`

- **LD_PRELOAD injection:**
  - `LD_PRELOAD=/tmp/evil.so /proc/1234`
  - `export LD_PRELOAD=/tmp/hook.so && sudo ls`

- **Injection scripts:**
  - `python inject_shellcode.py 1234`
  - `perl ptrace_inject.pl 5678`
  - `ruby process_inject.rb 9999`

**Why dangerous:** Process injection allows:
- Code execution in other processes
- Privilege escalation
- Bypassing security boundaries
- Persistent access

#### 5. Process Hiding

Hiding processes from monitoring tools:

- **Mount manipulation:**
  - `mount --bind /tmp/fake /proc`
  - `umount /proc`

- **Kernel module loading:**
  - `insmod rootkit.ko`
  - `modprobe hide_process`

- **LD_PRELOAD hooking:**
  - `LD_PRELOAD=/tmp/hook.so ps`
  - `export LD_PRELOAD=/lib/hide.so`

**Why dangerous:** Process hiding enables:
- Evading detection
- Hiding malware
- Concealing backdoors
- Bypassing security tools

#### 6. Signal Abuse

Killing security and monitoring processes:

- **Killing security tools:**
  - `kill -9 $(pgrep osqueryd)`
  - `pkill -9 falco`
  - `killall -9 auditd`
  - `kill -9 $(pgrep aide)`

- **Killing logging:**
  - `kill -9 $(pgrep rsyslog)`
  - `pkill -9 syslog-ng`
  - `killall -9 systemd-journald`

- **Killing EDR agents:**
  - `kill -9 $(pgrep crowdstrike)`
  - `pkill -9 falcon-sensor`
  - `killall -9 wazuh-agent`

- **Suspending processes:**
  - `kill -STOP $(pgrep osqueryd)`
  - `kill -19 $(pgrep falco)`

**Why dangerous:** Killing security processes:
- Disables monitoring
- Prevents detection
- Allows malware to run undetected
- Violates security policies

#### 7. Core Dump Enabling

Enabling or manipulating core dumps:

- `ulimit -c unlimited` - Enable unlimited core dumps
- `echo "core.%p" > /proc/sys/kernel/core_pattern`
- `sysctl -w kernel.core_pattern=/tmp/core`
- `sysctl -w fs.suid_dumpable=1`

**Why dangerous:** Core dumps can:
- Extract sensitive data from memory
- Expose credentials
- Reveal encryption keys
- Bypass security restrictions

#### 8. Priority Manipulation

Manipulating process priority:

- **Very high nice priority:**
  - `nice -n -20 myprocess` - Highest priority
  - `renice -20 1234`

- **Real-time priority:**
  - `chrt -f 99 myprocess` - FIFO scheduling
  - `chrt -r 99 command` - Round-robin

- **I/O priority:**
  - `ionice -c 1 myprocess` - Real-time I/O

**Why dangerous:** Priority manipulation can:
- Starve other processes
- Cause denial of service
- Evade detection (low priority)
- Disrupt critical services

#### 9. Namespace Manipulation

Manipulating process namespaces:

- **unshare creating namespaces:**
  - `unshare -p bash` - PID namespace
  - `unshare -n bash` - Network namespace
  - `unshare -m bash` - Mount namespace

- **nsenter entering namespaces:**
  - `nsenter -t 1234 bash` - Enter PID namespace
  - `nsenter -m bash` - Enter mount namespace

- **ip netns:**
  - `ip netns add newns`
  - `ip netns exec myns bash`

**Why dangerous:** Namespace manipulation enables:
- Container escape
- Privilege escalation
- Isolation bypass
- Access to hidden processes

#### 10. LD_PRELOAD Injection

Injecting libraries via LD_PRELOAD:

- **From suspicious locations:**
  - `LD_PRELOAD=/tmp/evil.so ls`
  - `LD_PRELOAD=/dev/shm/malicious.so ps`
  - `export LD_PRELOAD=/tmp/hook.so`

- **With system binaries:**
  - `LD_PRELOAD=/lib/hook.so sudo ls`
  - `LD_PRELOAD=/tmp/evil.so ssh user@host`

- **LD_LIBRARY_PATH manipulation:**
  - `LD_LIBRARY_PATH=/tmp sudo`
  - `export LD_LIBRARY_PATH=/dev/shm`

**Why dangerous:** LD_PRELOAD allows:
- Function hooking
- System call interception
- Rootkit functionality
- Credential theft

### Safe Operations (Not Detected)

#### Safe Debugging

```bash
# ✓ Debugging own code
gdb ./myprogram
gdb --args ./myapp --debug
lldb ./myapp
strace ./myprogram
strace -f ./test

# ✓ Debugging with core files
gdb myprogram core
lldb --core core

# ✓ Development tools
gdb --batch -ex "bt" ./program
lldb --batch
strace -c ./program  # Count syscalls only
```

#### Safe Process Inspection

```bash
# ✓ System monitoring
top
htop
ps aux
ps -ef
pstree

# ✓ Performance monitoring
perf top
perf stat ls
perf record ./program
vmstat
iostat
sar

# ✓ Read-only inspection
lsof
fuser /file
pmap 1234
strace -e trace=open ls

# ✓ Reading own process info
cat /proc/self/maps
cat /proc/self/status
cat /proc/$$/maps
```

#### Safe LD_PRELOAD for Testing

```bash
# ✓ Local testing
LD_PRELOAD=./mylib.so ./test
export LD_PRELOAD=./debug.so && ./test_runner
```

#### Safe Namespace Operations

```bash
# ✓ Listing namespaces
ip netns list
ip netns identify 1234
```

### Examples

#### Dangerous (Trigger Detection)

```bash
# ✗ Debugger attachment
gdb -p 1234
strace -p 5678
lldb --attach-pid 9999

# ✗ Memory dumping
gcore 1234
cat /proc/1234/mem
cat /proc/5678/maps
strings /proc/9999/mem

# ✗ Process injection
echo "code" > /proc/1234/mem
python inject_shellcode.py 1234
LD_PRELOAD=/tmp/evil.so /proc/1234

# ✗ Process hiding
insmod rootkit.ko
mount --bind /tmp/fake /proc
LD_PRELOAD=/tmp/hook.so ps

# ✗ Killing security processes
kill -9 $(pgrep osqueryd)
pkill -9 falco
killall -9 auditd

# ✗ Core dump enabling
ulimit -c unlimited
echo "core.%p" > /proc/sys/kernel/core_pattern
sysctl -w fs.suid_dumpable=1

# ✗ Priority manipulation
nice -n -20 myprocess
renice -20 1234
chrt -f 99 command
ionice -c 1 program

# ✗ Namespace manipulation
unshare -p bash
nsenter -t 1234 bash
ip netns add newns

# ✗ LD_PRELOAD injection
LD_PRELOAD=/tmp/evil.so ls
LD_PRELOAD=/lib/hook.so sudo ls
LD_LIBRARY_PATH=/tmp sudo
```

#### Safe (No Detection)

```bash
# ✓ Debugging own code
gdb ./myprogram
strace ./myapp
lldb ./test

# ✓ System monitoring
top
ps aux
pstree

# ✓ Performance monitoring
perf top
vmstat
iostat

# ✓ Own process info
cat /proc/self/maps
cat /proc/$$/status

# ✓ Testing with LD_PRELOAD
LD_PRELOAD=./mylib.so ./test

# ✓ Namespace listing
ip netns list
```

### Why This Is Dangerous

Process manipulation is used by attackers to:

1. **Evade detection** - Hide processes from monitoring tools
2. **Extract credentials** - Read passwords/tokens from memory
3. **Escalate privileges** - Inject code into privileged processes
4. **Disable security** - Kill EDR/AV agents
5. **Maintain access** - Inject backdoors into running processes
6. **Steal data** - Dump proprietary information from memory
7. **Cause DoS** - Manipulate priorities to starve processes

Real-world attack examples:

- **LD_PRELOAD rootkits** - Hook system functions to hide malware
- **Process injection** - Inject malware into legitimate processes
- **Memory scraping** - Extract credentials from browser/SSH processes
- **EDR evasion** - Kill security agents before deploying malware
- **Privilege escalation** - Inject into SUID processes

### Severity

**High** - All process manipulation attempts are marked as high severity because:

- Common attacker technique
- Can lead to complete system compromise
- Difficult to detect once injected
- Often used to disable security tools
- Enables privilege escalation
- Violates security boundaries

### Test Coverage

The detector includes 44 comprehensive tests covering:

- ✅ gdb/strace/lldb attachment (5 tests)
- ✅ Memory dumping (gcore, /proc/mem, /proc/maps) (5 tests)
- ✅ ptrace usage (3 tests)
- ✅ Process injection (4 tests)
- ✅ Process hiding (4 tests)
- ✅ Signal abuse (killing security processes) (4 tests)
- ✅ Core dump enabling (3 tests)
- ✅ Priority manipulation (4 tests)
- ✅ Namespace manipulation (5 tests)
- ✅ LD_PRELOAD injection (3 tests)
- ❌ Safe debugging (own code) (1 test)
- ❌ Safe monitoring tools (3 tests)

### How to Customize

#### Disable Detector

```typescript
// In noexec.config.json
{
  "detectors": {
    "process-manipulation": {
      "enabled": false  // Disable entirely
    }
  }
}
```

#### Adjust Severity

```typescript
{
  "detectors": {
    "process-manipulation": {
      "enabled": true,
      "severity": "medium"  // Default: high
    }
  }
}
```

#### Add Safe Patterns

Edit `src/detectors/process-manipulation.ts`:

```typescript
const SAFE_DEBUGGING_PATTERNS = [
  // ... existing patterns ...

  // Add your development tools
  /\bmydebugtool\b/,
  /\bcustom-profiler\b/,
];
```

#### Whitelist Specific Processes

```typescript
export function detectProcessManipulation(
  toolUseData: ToolUseData,
  config?: ProcessManipulationConfig
): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Allow debugging specific processes
  if (/gdb.*myapp/.test(toolInput)) {
    return Promise.resolve(null);
  }

  // ... rest of detection logic
}
```

#### Disable Specific Checks

Comment out pattern arrays you don't need:

```typescript
const allPatterns = [
  ...DEBUGGER_ATTACHMENT_PATTERNS,
  ...MEMORY_DUMP_PATTERNS,
  // ...PTRACE_PATTERNS,  // Disable ptrace detection
  // ...PROCESS_INJECTION_PATTERNS,  // Disable injection detection
  ...SIGNAL_ABUSE_PATTERNS,
  // ... rest
];
```

---
