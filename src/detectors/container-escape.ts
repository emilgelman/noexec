import type { Detection, ToolUseData } from '../types';
import type { ContainerEscapeConfig } from '../config/types';

/**
 * Detects container escape attempts and dangerous container configurations
 * 
 * Container escapes allow attackers to break out of container isolation
 * and compromise the host system - CRITICAL severity threat.
 */

/**
 * Privileged container patterns
 * Running containers with --privileged gives them nearly all host capabilities
 */
const PRIVILEGED_CONTAINER_PATTERNS = [
  /\bdocker\s+run\b[^\n]*--privileged/,
  /\bdocker\s+container\s+run\b[^\n]*--privileged/,
  /\bpodman\s+run\b[^\n]*--privileged/,
  /\bnerdctl\s+run\b[^\n]*--privileged/,
  
  // Docker Compose privileged mode
  /privileged:\s*true/,
  
  // Kubernetes privileged containers
  /securityContext:[^\n]*\n[^\n]*privileged:\s*true/,
  /privileged:\s*true[^\n]*\n[^\n]*securityContext/,
];

/**
 * Docker socket mounting patterns
 * Mounting the Docker socket gives container control over the host's Docker daemon
 */
const DOCKER_SOCKET_MOUNT_PATTERNS = [
  // Direct socket mounts
  /\bdocker\s+run\b[^\n]*-v\s+\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/,
  /\bdocker\s+run\b[^\n]*--volume[=\s]+\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/,
  /\bpodman\s+run\b[^\n]*-v\s+\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/,
  
  // Docker Compose socket mounts (matches both literal newline and escaped \n)
  /volumes:\s*(\\n|[\r\n])\s*-\s*\/var\/run\/docker\.sock:\/var\/run\/docker\.sock/,
  /volumes:\s*(\\n|[\r\n])\s*-\s*["']\/var\/run\/docker\.sock:\/var\/run\/docker\.sock["']/,
  
  // Kubernetes hostPath mounts (flexible whitespace)
  /hostPath:[^\n]*(\\n|[\r\n])[^\n]*path:\s*["']?\/var\/run\/docker\.sock/,
  
  // Containerd socket
  /\bdocker\s+run\b[^\n]*-v\s+\/run\/containerd\/containerd\.sock/,
  /\bpodman\s+run\b[^\n]*-v\s+\/run\/containerd\/containerd\.sock/,
];

/**
 * Host namespace sharing patterns
 * Sharing host network/PID/IPC namespaces breaks container isolation
 */
const HOST_NAMESPACE_PATTERNS = [
  // Host network
  /\bdocker\s+run\b[^\n]*--network[=\s]+host/,
  /\bdocker\s+run\b[^\n]*--net[=\s]+host/,
  /\bpodman\s+run\b[^\n]*--network[=\s]+host/,
  /\bnerdctl\s+run\b[^\n]*--network[=\s]+host/,
  
  // Host PID namespace
  /\bdocker\s+run\b[^\n]*--pid[=\s]+host/,
  /\bpodman\s+run\b[^\n]*--pid[=\s]+host/,
  
  // Host IPC namespace
  /\bdocker\s+run\b[^\n]*--ipc[=\s]+host/,
  /\bpodman\s+run\b[^\n]*--ipc[=\s]+host/,
  
  // Docker Compose network mode
  /network_mode:\s*["']?host["']?/,
  
  // Kubernetes hostNetwork
  /hostNetwork:\s*true/,
  /hostPID:\s*true/,
  /hostIPC:\s*true/,
];

/**
 * Dangerous capability additions
 * Certain Linux capabilities enable container escapes
 */
const DANGEROUS_CAPABILITY_PATTERNS = [
  // SYS_ADMIN is the most dangerous - gives nearly root privileges
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+SYS_ADMIN/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+SYS_ADMIN/,
  
  // SYS_PTRACE allows process tracing, can be used to escape
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+SYS_PTRACE/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+SYS_PTRACE/,
  
  // SYS_MODULE allows loading kernel modules
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+SYS_MODULE/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+SYS_MODULE/,
  
  // DAC_READ_SEARCH bypasses file permission checks
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+DAC_READ_SEARCH/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+DAC_READ_SEARCH/,
  
  // DAC_OVERRIDE bypasses file write permission checks
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+DAC_OVERRIDE/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+DAC_OVERRIDE/,
  
  // Adding ALL capabilities
  /\bdocker\s+run\b[^\n]*--cap-add[=\s]+ALL/,
  /\bpodman\s+run\b[^\n]*--cap-add[=\s]+ALL/,
  
  // Kubernetes capabilities (flexible whitespace)
  /capabilities:[\s\S]*?add:[\s\S]*?-\s*SYS_ADMIN/,
  /capabilities:[\s\S]*?add:[\s\S]*?-\s*SYS_PTRACE/,
  /capabilities:[\s\S]*?add:[\s\S]*?-\s*SYS_MODULE/,
];

/**
 * cgroups manipulation patterns
 * Direct cgroups manipulation can enable container escapes
 */
const CGROUPS_MANIPULATION_PATTERNS = [
  // Writing to cgroup files
  /echo[^\n]*>\s*\/sys\/fs\/cgroup\//,
  /cat[^\n]*>\s*\/sys\/fs\/cgroup\//,
  /tee[^\n]*\/sys\/fs\/cgroup\//,
  
  // Modifying cgroup release_agent (classic escape)
  /\/sys\/fs\/cgroup\/[^\n]*\/release_agent/,
  /echo[^\n]*release_agent/,
  
  // Mounting cgroups
  /mount[^\n]*-t\s+cgroup/,
  /mount[^\n]*cgroup/,
  
  // Direct cgroup directory access in container
  /\bdocker\s+run\b[^\n]*-v\s+\/sys\/fs\/cgroup/,
  /\bpodman\s+run\b[^\n]*-v\s+\/sys\/fs\/cgroup/,
  
  // notify_on_release escape technique
  /notify_on_release\s*=\s*1/,
  /echo\s+1\s*>\s*[^\n]*notify_on_release/,
];

/**
 * Kernel module loading patterns
 * Loading kernel modules from containers can compromise the host
 */
const KERNEL_MODULE_PATTERNS = [
  /\bmodprobe\b/,
  /\binsmod\b/,
  /\brmmod\b/,
  /\bdepmod\b/,
  /\blsmod\b/,
  
  // Direct module loading
  /\/sbin\/modprobe/,
  /\/sbin\/insmod/,
  
  // Accessing module files
  /\/lib\/modules\//,
  /\/proc\/modules/,
  
  // Module loading in container startup
  /\bdocker\s+run\b[^\n]*modprobe/,
  /\bpodman\s+run\b[^\n]*insmod/,
];

/**
 * chroot escape patterns
 * Traditional chroot escape techniques
 */
const CHROOT_ESCAPE_PATTERNS = [
  // Classic chroot break technique
  /mkdir[^\n]*\.{2,}/,
  /chroot\s+\./,
  
  // Multiple chroots to escape
  /chroot[^\n]*chroot/,
  
  // Pivot_root manipulation
  /pivot_root/,
  
  // Breaking out via file descriptors
  /\/proc\/self\/root/,
  /\/proc\/1\/root/,
  
  // Directory traversal in chroot context
  /chroot[^\n]*\.\.[\/\\]/,
];

/**
 * nsenter abuse patterns
 * nsenter can be used to enter host namespaces from a container
 */
const NSENTER_PATTERNS = [
  // Entering PID 1 namespaces (host)
  /\bnsenter\s+[^\n]*-t\s+1\b/,
  /\bnsenter\s+[^\n]*--target[=\s]+1\b/,
  
  // Multiple namespace entry
  /\bnsenter\s+[^\n]*-m[^\n]*-u[^\n]*-n[^\n]*-i/,
  /\bnsenter\s+[^\n]*--mount[^\n]*--uts[^\n]*--net[^\n]*--ipc/,
  
  // Entering all namespaces
  /\bnsenter\s+[^\n]*-a\b/,
  /\bnsenter\s+[^\n]*--all\b/,
  
  // nsenter with target PID 1 (host init)
  /\bnsenter\s+[^\n]*-t\s+1[^\n]*-m/,
  /\bnsenter\s+[^\n]*-t\s+1[^\n]*bash/,
  /\bnsenter\s+[^\n]*-t\s+1[^\n]*sh/,
];

/**
 * core_pattern exploitation patterns
 * Writing to /proc/sys/kernel/core_pattern enables code execution on crash
 */
const CORE_PATTERN_EXPLOIT_PATTERNS = [
  // Writing to core_pattern
  /echo[^\n]*>\s*\/proc\/sys\/kernel\/core_pattern/,
  /cat[^\n]*>\s*\/proc\/sys\/kernel\/core_pattern/,
  /tee[^\n]*\/proc\/sys\/kernel\/core_pattern/,
  
  // Pipe character in core_pattern (executes program)
  /core_pattern[^\n]*\|/,
  /echo\s+['"]?\|[^\n]*>\s*[^\n]*core_pattern/,
  
  // Accessing core_pattern file
  /\/proc\/sys\/kernel\/core_pattern/,
];

/**
 * Host filesystem mount patterns
 * Mounting host filesystem gives access to host data
 */
const HOST_FILESYSTEM_MOUNT_PATTERNS = [
  // Mounting host root
  /\bdocker\s+run\b[^\n]*-v\s+\/:\/host/,
  /\bpodman\s+run\b[^\n]*-v\s+\/:\/host/,
  
  // Mounting /etc, /root, /home
  /\bdocker\s+run\b[^\n]*-v\s+\/etc:/,
  /\bdocker\s+run\b[^\n]*-v\s+\/root:/,
  /\bpodman\s+run\b[^\n]*-v\s+\/etc:/,
  /\bpodman\s+run\b[^\n]*-v\s+\/root:/,
  
  // Mounting /proc, /sys
  /\bdocker\s+run\b[^\n]*-v\s+\/proc:/,
  /\bdocker\s+run\b[^\n]*-v\s+\/sys:/,
  /\bpodman\s+run\b[^\n]*-v\s+\/proc:/,
  /\bpodman\s+run\b[^\n]*-v\s+\/sys:/,
  
  // Mounting /dev
  /\bdocker\s+run\b[^\n]*-v\s+\/dev:/,
  /\bpodman\s+run\b[^\n]*-v\s+\/dev:/,
  
  // Kubernetes hostPath dangerous mounts (flexible whitespace)
  /hostPath:[\s\S]*?path:\s*["']?\/etc["']?/,
  /hostPath:[\s\S]*?path:\s*["']?\/["']?\s*$/m,
];

/**
 * procfs/sysfs escape patterns
 * Manipulating /proc and /sys from containers
 */
const PROC_SYS_ESCAPE_PATTERNS = [
  // Writing to sensitive proc files
  /echo[^\n]*>\s*\/proc\/sys\//,
  /cat[^\n]*>\s*\/proc\/sys\//,
  /tee[^\n]*\/proc\/sys\//,
  
  // Accessing host processes via /proc
  /\/proc\/1\/[^\s]*/,
  /\/proc\/self\/root\//,
  
  // sysfs manipulation
  /echo[^\n]*>\s*\/sys\/[^\n]*/,
  /cat[^\n]*>\s*\/sys\/class\//,
  
  // Overwriting memory limits
  /\/sys\/fs\/cgroup\/memory\//,
];

/**
 * AppArmor/SELinux bypass patterns
 */
const SECURITY_BYPASS_PATTERNS = [
  // Disabling AppArmor
  /\bdocker\s+run\b[^\n]*--security-opt[=\s]+apparmor[=:]unconfined/,
  /\bpodman\s+run\b[^\n]*--security-opt[=\s]+apparmor[=:]unconfined/,
  
  // Disabling SELinux
  /\bdocker\s+run\b[^\n]*--security-opt[=\s]+label[=:]disable/,
  /\bpodman\s+run\b[^\n]*--security-opt[=\s]+label[=:]disable/,
  
  // Disabling seccomp
  /\bdocker\s+run\b[^\n]*--security-opt[=\s]+seccomp[=:]unconfined/,
  /\bpodman\s+run\b[^\n]*--security-opt[=\s]+seccomp[=:]unconfined/,
  
  // No new privileges disabled
  /\bdocker\s+run\b[^\n]*--security-opt[=\s]+no-new-privileges[=:]false/,
];

/**
 * Safe patterns that might trigger false positives
 */
const SAFE_PATTERNS = [
  // Docker-in-Docker for CI/CD (common legitimate use)
  /docker:dind/i,
  /docker:.*-dind/i,
  
  // GitLab Runner, Jenkins agents
  /gitlab-runner/i,
  /jenkins\/agent/i,
  
  // Development environments that need Docker access
  /devcontainer/i,
  /vscode.*remote/i,
];

interface DetectionDetails {
  pattern: string;
  message: string;
}

/**
 * Check if command contains safe patterns that justify risky config
 */
function hasSafeContext(command: string): boolean {
  return SAFE_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Detect container escape patterns
 */
export function detectContainerEscape(
  toolUseData: ToolUseData,
  config?: ContainerEscapeConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  const detections: DetectionDetails[] = [];

  // Check privileged containers
  if (PRIVILEGED_CONTAINER_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'privileged-container',
      message: 'Privileged container detected - grants nearly all host capabilities, enables container escape',
    });
  }

  // Check Docker socket mounting
  if (DOCKER_SOCKET_MOUNT_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'docker-socket-mount',
      message: 'Docker socket mount detected - gives container full control over host Docker daemon, equivalent to root access',
    });
  }

  // Check host namespace sharing
  if (HOST_NAMESPACE_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'host-namespace',
      message: 'Host namespace sharing detected - breaks container isolation, exposes host processes/network',
    });
  }

  // Check dangerous capabilities
  if (DANGEROUS_CAPABILITY_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'dangerous-capability',
      message: 'Dangerous Linux capability detected (SYS_ADMIN/SYS_PTRACE/SYS_MODULE) - enables container escape',
    });
  }

  // Check cgroups manipulation
  if (CGROUPS_MANIPULATION_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'cgroups-manipulation',
      message: 'cgroups manipulation detected - classic container escape technique via release_agent',
    });
  }

  // Check kernel module loading
  if (KERNEL_MODULE_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'kernel-module-loading',
      message: 'Kernel module loading detected - modules run in host kernel context, full system compromise',
    });
  }

  // Check chroot escape
  if (CHROOT_ESCAPE_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'chroot-escape',
      message: 'Chroot escape technique detected - attempts to break out of container filesystem isolation',
    });
  }

  // Check nsenter abuse
  if (NSENTER_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'nsenter-abuse',
      message: 'nsenter to host namespaces detected - enters host PID/network/mount namespaces, breaks isolation',
    });
  }

  // Check core_pattern exploitation
  if (CORE_PATTERN_EXPLOIT_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'core-pattern-exploit',
      message: 'core_pattern exploitation detected - executes attacker code when process crashes, container escape',
    });
  }

  // Check host filesystem mounts
  if (HOST_FILESYSTEM_MOUNT_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'host-filesystem-mount',
      message: 'Host filesystem mount detected - exposes sensitive host files (/etc, /proc, /sys), data exfiltration risk',
    });
  }

  // Check proc/sys escape
  if (PROC_SYS_ESCAPE_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'proc-sys-escape',
      message: 'procfs/sysfs manipulation detected - attempts to modify host kernel parameters or access host processes',
    });
  }

  // Check security bypasses
  if (SECURITY_BYPASS_PATTERNS.some((p) => p.test(toolInput))) {
    detections.push({
      pattern: 'security-bypass',
      message: 'Security feature bypass detected - disables AppArmor/SELinux/seccomp, removes container protections',
    });
  }

  // Return first detection (most critical)
  if (detections.length > 0) {
    const firstDetection = detections[0];
    return Promise.resolve({
      severity,
      message: `CONTAINER ESCAPE DETECTED: ${firstDetection.message}`,
      detector: 'container-escape',
    });
  }

  return Promise.resolve(null);
}
