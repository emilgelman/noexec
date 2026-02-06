import type { Detection, ToolUseData } from '../types';
import type { ProcessManipulationConfig } from '../config/types';

/**
 * Detects attempts to manipulate running processes via debugging,
 * injection, or memory manipulation techniques
 */

// Debugger attachment patterns
const DEBUGGER_ATTACHMENT_PATTERNS = [
  // gdb attachment
  /\bgdb\s+(?:-p|--pid)\s+[0-9]+/,
  /\bgdb\s+--attach\s+[0-9]+/,
  /\bgdb\s+[^\s]*\s+[0-9]+/, // gdb program pid

  // strace attachment
  /\bstrace\s+(?:-p|--attach)\s+[0-9]+/,
  /\bstrace\s+-p\s*[0-9]+/,

  // lldb attachment
  /\blldb\s+(?:-p|--pid)\s+[0-9]+/,
  /\blldb\s+--attach-pid\s+[0-9]+/,
  /\blldb\s+--attach-name\s+\w+/,

  // Other debuggers
  /\bltrace\s+-p\s+[0-9]+/,
  /\bdbg\s+-p\s+[0-9]+/,
];

// Memory dumping patterns
const MEMORY_DUMP_PATTERNS = [
  // gcore (generate core dump)
  /\bgcore\s+[0-9]+/,
  /\bgcore\s+-o\s+[^\s]+\s+[0-9]+/,

  // /proc memory access
  /\bcat\s+\/proc\/[0-9]+\/mem\b/,
  /\bcat\s+\/proc\/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/mem\b/,
  /\bdd\s+[^\n]*if=\/proc\/[0-9]+\/mem/,
  /\bhead\s+\/proc\/[0-9]+\/mem\b/,
  /\btail\s+\/proc\/[0-9]+\/mem\b/,
  /\bless\s+\/proc\/[0-9]+\/mem\b/,
  /\bmore\s+\/proc\/[0-9]+\/mem\b/,

  // Reading process maps
  /\bcat\s+\/proc\/[0-9]+\/maps\b/,
  /\bcat\s+\/proc\/\$\{?[A-Za-z_][A-Za-z0-9_]*\}?\/maps\b/,
  /\bgrep\s+[^\n]*\/proc\/[0-9]+\/maps/,

  // Bulk process memory scraping
  /\bfor\s+[^\n]*\/proc\/[^\n]*\/mem\b/,
  /\bfind\s+\/proc[^\n]*-name\s+mem\b/,
  /\bfind\s+\/proc[^\n]*-name\s+maps\b/,

  // strings on process memory
  /\bstrings\s+\/proc\/[0-9]+\/mem\b/,
];

// ptrace usage patterns
const PTRACE_PATTERNS = [
  // Direct ptrace commands
  /\bptrace\s+[A-Z_]+/,
  /\bptrace\([A-Z_]+/,

  // Python ptrace
  /import\s+ptrace/,
  /from\s+ptrace\s+import/,
  /\bptrace\.attach\b/,
  /\bptrace\.syscall\b/,

  // Perl ptrace
  /use\s+ptrace/,
  /ptrace\s*\(/,

  // LD_PRELOAD with ptrace libraries
  /LD_PRELOAD=[^\s]*ptrace/,
  /export\s+LD_PRELOAD=[^\s]*ptrace/,
];

// Process injection patterns
const PROCESS_INJECTION_PATTERNS = [
  // Writing to /proc/[pid]/mem
  /\becho\s+[^\n]*>\s*\/proc\/[0-9]+\/mem/,
  /\bprintf\s+[^\n]*>\s*\/proc\/[0-9]+\/mem/,
  /\bdd\s+[^\n]*of=\/proc\/[0-9]+\/mem/,
  /\bcat\s+[^\n]*>\s*\/proc\/[0-9]+\/mem/,

  // LD_PRELOAD injection into other processes
  /LD_PRELOAD=[^\s]+\s+\/proc\/[0-9]+/,
  /export\s+LD_PRELOAD=[^\s]+.*(?:exec|su|sudo)/,

  // Injecting code via /proc/[pid]/fd
  /\becho\s+[^\n]*>\s*\/proc\/[0-9]+\/fd/,
  /\bcat\s+[^\n]*>\s*\/proc\/[0-9]+\/fd/,

  // Python/Perl/Ruby injection scripts
  /(?:python|perl|ruby)\s+[^\n]*inject[^\n]*\.py/i,
  /(?:python|perl|ruby)\s+[^\n]*ptrace[^\n]*\.py/i,
];

// Process hiding patterns
const PROCESS_HIDING_PATTERNS = [
  // Modifying /proc directly
  /\bmount\s+[^\n]*\/proc\b/,
  /\bumount\s+\/proc\b/,
  /\bmount\s+--bind[^\n]*\/proc/,

  // Kernel module loading (for rootkits)
  /\binsmod\s+[^\n]*(?:rootkit|hide|proc)/i,
  /\bmodprobe\s+[^\n]*(?:rootkit|hide|proc)/i,

  // LD_PRELOAD hooking
  /LD_PRELOAD=[^\s]*(?:hook|hide|stealth)/i,
  /export\s+LD_PRELOAD=[^\s]*(?:hook|hide|stealth)/i,

  // Manipulating /proc filesystem
  /\bmkdir\s+\/proc\/[^\s]+\/hide/,
  /\bln\s+[^\n]*\/proc\/[0-9]+/,
  /\bchmod\s+[^\n]*\/proc\/[0-9]+/,
];

// Signal abuse patterns
const SIGNAL_ABUSE_PATTERNS = [
  // Killing monitoring/security processes by name
  /\bkill\s+(?:-9|--signal=KILL|--signal=9)\s+[^\n]*\$\(/,
  /\bkill\s+(?:-9|-KILL)\s+\$\(pgrep\s+(?:osqueryd|falco|auditd|aide|tripwire|rkhunter|chkrootkit|samhain)\b/,
  /\bpkill\s+(?:-9|-KILL)\s+(?:osqueryd|falco|auditd|aide|tripwire|rkhunter|chkrootkit|samhain)\b/,
  /\bkillall\s+(?:-9|-KILL)\s+(?:osqueryd|falco|auditd|aide|tripwire|rkhunter|chkrootkit|samhain)\b/,

  // Killing syslog/logging
  /\bkill\s+(?:-9|-KILL)\s+\$\(pgrep\s+(?:rsyslog|syslog-ng|journald)\b/,
  /\bpkill\s+(?:-9|-KILL)\s+(?:rsyslog|syslog-ng|systemd-journald)\b/,
  /\bkillall\s+(?:-9|-KILL)\s+(?:rsyslog|syslog-ng|journalctl)\b/,

  // Killing EDR/antivirus agents
  /\bkill\s+(?:-9|-KILL)\s+\$\(pgrep\s+(?:crowdstrike|cb-sensor|wazuh|ossec|aide|clamav)\b/i,
  /\bpkill\s+(?:-9|-KILL)\s+(?:falcon-sensor|cb|wazuh-agent|ossec|clamd)\b/i,

  // Suspending critical processes (SIGSTOP)
  /\bkill\s+(?:-19|-STOP|--signal=STOP)\s+[^\n]*\$\(pgrep/,
  /\bkill\s+(?:-19|-STOP)\s+\$\(pgrep\s+(?:osqueryd|falco|auditd)\b/,
];

// Core dump enabling patterns
const CORE_DUMP_PATTERNS = [
  // ulimit -c unlimited (enable core dumps)
  /\bulimit\s+-c\s+unlimited\b/,
  /\bulimit\s+-c\s+[0-9]{7,}\b/, // Very large core limit

  // Setting core pattern to pipe or file
  /\becho\s+[^\n]*>\s*\/proc\/sys\/kernel\/core_pattern/,
  /\bsysctl\s+[^\n]*kernel\.core_pattern/,

  // Setting core dump location
  /\becho\s+[^\n]*>\s*\/proc\/sys\/kernel\/core_uses_pid/,

  // Disabling core dump restrictions
  /\bsysctl\s+-w\s+fs\.suid_dumpable=1/,
  /\becho\s+1\s*>\s*\/proc\/sys\/fs\/suid_dumpable/,
];

// Priority manipulation patterns
const PRIORITY_MANIPULATION_PATTERNS = [
  // Setting very high priority (can starve other processes)
  /\bnice\s+-n\s+-[12][0-9]\b/, // nice -n -10 to -20
  /\bnice\s+--adjustment=-[12][0-9]\b/,

  // Renice to very high priority
  /\brenice\s+-[12][0-9]\b/,
  /\brenice\s+--priority=-[12][0-9]\b/,
  /\brenice\s+-n\s+-[12][0-9]\b/,

  // Real-time priority (requires root, used by malware)
  /\bchrt\s+-[fr]\s+99\b/,
  /\bchrt\s+--fifo\s+99\b/,
  /\bchrt\s+--rr\s+99\b/,

  // ionice to real-time (can disrupt I/O)
  /\bionice\s+-c\s+1\b/, // Real-time I/O class
  /\bionice\s+--class\s+1\b/,
  /\bionice\s+-c\s+1\s+-n\s+0\b/, // Highest real-time priority
];

// Process namespace manipulation patterns
const NAMESPACE_MANIPULATION_PATTERNS = [
  // unshare creating new namespaces
  /\bunshare\s+[^\n]*(?:-p|--pid)\b/,
  /\bunshare\s+[^\n]*(?:-n|--net)\b/,
  /\bunshare\s+[^\n]*(?:-m|--mount)\b/,
  /\bunshare\s+[^\n]*(?:-u|--uts)\b/,
  /\bunshare\s+[^\n]*(?:-i|--ipc)\b/,
  /\bunshare\s+[^\n]*(?:-U|--user)\b/,

  // nsenter entering existing namespaces
  /\bnsenter\s+[^\n]*(?:-t|--target)\s+[0-9]+/,
  /\bnsenter\s+[^\n]*(?:-p|--pid)/,
  /\bnsenter\s+[^\n]*(?:-m|--mount)/,

  // ip netns commands
  /\bip\s+netns\s+(?:add|del|exec)\b/,
  /\bip\s+netns\s+attach\b/,

  // Manipulating namespace files directly
  /\bmount\s+[^\n]*\/proc\/[0-9]+\/ns/,
  /\bcat\s+\/proc\/[0-9]+\/ns\/[a-z]+/,
  /\becho\s+[^\n]*>\s*\/proc\/[0-9]+\/ns/,
];

// LD_PRELOAD injection patterns
const LD_PRELOAD_PATTERNS = [
  // LD_PRELOAD with suspicious library names
  /LD_PRELOAD=[^\s]*\.so(?:\.[0-9]+)?\s+(?!\.\/|test|debug)/,
  /export\s+LD_PRELOAD=[^\s]*\.so/,

  // LD_PRELOAD from suspicious locations
  /LD_PRELOAD=\/tmp\/[^\s]*\.so/,
  /LD_PRELOAD=\/dev\/shm\/[^\s]*\.so/,
  /LD_PRELOAD=\/var\/tmp\/[^\s]*\.so/,
  /export\s+LD_PRELOAD=\/tmp\/[^\s]*\.so/,

  // LD_PRELOAD with system binaries
  /LD_PRELOAD=[^\s]*\.so\s+(?:sudo|su|ssh|sshd|ps|top|netstat|ls)\b/,
  /export\s+LD_PRELOAD=[^\s]*\.so.*;.*(?:sudo|su|ssh)/,

  // LD_LIBRARY_PATH manipulation
  /LD_LIBRARY_PATH=\/tmp/,
  /LD_LIBRARY_PATH=\/dev\/shm/,
  /export\s+LD_LIBRARY_PATH=\/tmp/,
];

// Safe debugging patterns (excluded from detection)
const SAFE_DEBUGGING_PATTERNS = [
  // Debugging own code in current directory
  /\bgdb\s+\.\/[^\s]+$/,
  /\bgdb\s+--args\s+\.\/[^\s]+/,
  /\blldb\s+\.\/[^\s]+$/,
  /\blldb\s+--\s+\.\/[^\s]+/,

  // Debugging with core files
  /\bgdb\s+[^\s]+\s+core\b/,
  /\blldb\s+--core\s+core\b/,

  // strace on own process
  /\bstrace\s+\.\/[^\s]+/,
  /\bstrace\s+-f\s+\.\/[^\s]+/,

  // Reading own process info
  /\bcat\s+\/proc\/self\/maps\b/,
  /\bcat\s+\/proc\/self\/status\b/,
  /\bcat\s+\/proc\/\$\$\/maps\b/,

  // Development tools
  /\bgdb\s+--batch/,
  /\blldb\s+--batch/,
  /\bstrace\s+-c\b/, // Count system calls only

  // Safe LD_PRELOAD for testing
  /LD_PRELOAD=\.\/[^\s]*\.so\s+\.\/[^\s]+/,
  /export\s+LD_PRELOAD=\.\/[^\s]*\.so.*\.\/test/,
];

// Legitimate monitoring tools (excluded from detection)
const SAFE_MONITORING_PATTERNS = [
  // System monitoring
  /\btop\b/,
  /\bhtop\b/,
  /\bps\s+aux\b/,
  /\bps\s+-ef\b/,
  /\bps\s+--forest\b/,
  /\bpstree\b/,
  /\bpgrep\s+[^\s]+$/, // Simple pgrep without kill

  // Performance monitoring
  /\bperf\s+(?:top|stat|record)\b/,
  /\bsysstat\b/,
  /\bsar\b/,
  /\bvmstat\b/,
  /\biostat\b/,

  // Process inspection (read-only)
  /\blsof\b/,
  /\bfuser\b/,
  /\bpmap\s+[0-9]+$/,

  // strace for performance analysis (read-only)
  /\bstrace\s+-e\s+trace=(?:open|read|write|stat)\b/,

  // Safe namespace operations
  /\bip\s+netns\s+list\b/,
  /\bip\s+netns\s+identify\b/,
];

/**
 * Check if the command is a safe operation
 */
function isSafeOperation(command: string): boolean {
  return (
    SAFE_DEBUGGING_PATTERNS.some((pattern) => pattern.test(command)) ||
    SAFE_MONITORING_PATTERNS.some((pattern) => pattern.test(command))
  );
}

/**
 * Get the specific manipulation type being attempted
 */
function getManipulationType(command: string): string {
  if (DEBUGGER_ATTACHMENT_PATTERNS.some((p) => p.test(command))) {
    return 'debugger attachment to running process';
  }
  if (MEMORY_DUMP_PATTERNS.some((p) => p.test(command))) {
    return 'process memory dumping';
  }
  if (PTRACE_PATTERNS.some((p) => p.test(command))) {
    return 'ptrace system call usage';
  }
  if (PROCESS_INJECTION_PATTERNS.some((p) => p.test(command))) {
    return 'process injection attempt';
  }
  if (PROCESS_HIDING_PATTERNS.some((p) => p.test(command))) {
    return 'process hiding technique';
  }
  if (SIGNAL_ABUSE_PATTERNS.some((p) => p.test(command))) {
    return 'killing security/monitoring processes';
  }
  if (CORE_DUMP_PATTERNS.some((p) => p.test(command))) {
    return 'enabling core dumps';
  }
  if (PRIORITY_MANIPULATION_PATTERNS.some((p) => p.test(command))) {
    return 'process priority manipulation';
  }
  if (NAMESPACE_MANIPULATION_PATTERNS.some((p) => p.test(command))) {
    return 'process namespace manipulation';
  }
  if (LD_PRELOAD_PATTERNS.some((p) => p.test(command))) {
    return 'LD_PRELOAD library injection';
  }
  return 'process manipulation';
}

/**
 * Detect process manipulation attempts
 */
export function detectProcessManipulation(
  toolUseData: ToolUseData,
  config?: ProcessManipulationConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  // Check if this is a safe operation first
  if (isSafeOperation(toolInput)) {
    return Promise.resolve(null);
  }

  // Check all process manipulation patterns
  const allPatterns = [
    ...DEBUGGER_ATTACHMENT_PATTERNS,
    ...MEMORY_DUMP_PATTERNS,
    ...PTRACE_PATTERNS,
    ...PROCESS_INJECTION_PATTERNS,
    ...PROCESS_HIDING_PATTERNS,
    ...SIGNAL_ABUSE_PATTERNS,
    ...CORE_DUMP_PATTERNS,
    ...PRIORITY_MANIPULATION_PATTERNS,
    ...NAMESPACE_MANIPULATION_PATTERNS,
    ...LD_PRELOAD_PATTERNS,
  ];

  for (const pattern of allPatterns) {
    if (pattern.test(toolInput)) {
      const manipulationType = getManipulationType(toolInput);
      return Promise.resolve({
        severity,
        message: `Process manipulation detected: ${manipulationType}`,
        detector: 'process-manipulation',
      });
    }
  }

  return Promise.resolve(null);
}
