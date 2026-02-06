import type { Detection, ToolUseData } from '../types';
import type { SecurityToolDisablingConfig } from '../config/types';

/**
 * Detects attempts to disable security protections
 */

const SECURITY_DISABLING_PATTERNS = [
  // Firewall disabling
  /\bufw\s+disable\b/,
  /\bufw\s+--force\s+disable\b/,
  /\biptables\s+-F\b/,
  /\biptables\s+--flush\b/,
  /\biptables\s+-X\b/,
  /\biptables\s+-t\s+\w+\s+-F\b/,
  /\bip6tables\s+-F\b/,
  /\bip6tables\s+--flush\b/,
  /\bfirewall-cmd\s+--remove-all\b/,
  /\bfirewall-cmd\s+--disable\b/,
  /\bnetsh\s+advfirewall\s+set\s+\w+\s+state\s+off\b/i,
  /\bSet-NetFirewallProfile\s+.*-Enabled\s+False\b/i,
  /\bDisable-NetFirewallRule\b/i,
  /\bnft\s+flush\s+ruleset\b/,
  /\bnft\s+delete\s+table\b/,

  // SELinux disabling
  /\bsetenforce\s+0\b/,
  /\bsetenforce\s+Permissive\b/i,
  /SELINUX=disabled/i,
  /SELINUX=permissive/i,
  />\s*\/etc\/selinux\/config/,
  /\bsed\b.*\/etc\/selinux\/config/,

  // AppArmor disabling
  /\bsystemctl\s+stop\s+apparmor\b/,
  /\bsystemctl\s+disable\s+apparmor\b/,
  /\bservice\s+apparmor\s+stop\b/,
  /\baa-disable\b/,
  /\bapparmor_parser\s+-R\b/,
  /\bln\s+-s\s+\/etc\/apparmor\.d\/\w+\s+\/etc\/apparmor\.d\/disable\//,
  /\bupdate-rc\.d\s+apparmor\s+disable\b/,

  // Antivirus disabling
  /\bSet-MpPreference\s+.*-DisableRealtimeMonitoring\s+\$?true\b/i,
  /\bSet-MpPreference\s+.*-DisableBehaviorMonitoring\s+\$?true\b/i,
  /\bSet-MpPreference\s+.*-DisableIOAVProtection\s+\$?true\b/i,
  /\bSet-MpPreference\s+.*-DisableScriptScanning\s+\$?true\b/i,
  /Add-MpPreference.*ExclusionPath.*C:/i,
  /\bNew-ItemProperty\b.*Windows Defender.*DisableAntiSpyware/i,
  /\bsystemctl\s+stop\s+clamav\b/,
  /\bsystemctl\s+disable\s+clamav\b/,
  /\bsystemctl\s+stop\s+clamd\b/,
  /\bsystemctl\s+stop\s+clamav-daemon\b/,
  /\bsystemctl\s+stop\s+clamav-freshclam\b/,
  /\bservice\s+clamav.*\s+stop\b/,
  /\bpkill\s+-9\s+clamd\b/,
  /\bkillall\s+clamd\b/,

  // Audit logging disabling
  /\bauditctl\s+-D\b/,
  /\bauditctl\s+--delete-all\b/,
  /\bauditctl\s+-e\s+0\b/,
  /\bsystemctl\s+stop\s+auditd\b/,
  /\bsystemctl\s+disable\s+auditd\b/,
  /\bservice\s+auditd\s+stop\b/,
  /\bchkconfig\s+auditd\s+off\b/,
  /\bpkill\s+-9\s+auditd\b/,

  // System logging disabling
  /\bsystemctl\s+stop\s+rsyslog\b/,
  /\bsystemctl\s+disable\s+rsyslog\b/,
  /\bsystemctl\s+stop\s+syslog\b/,
  /\bsystemctl\s+stop\s+journald\b/,
  /\bsystemctl\s+disable\s+systemd-journald\b/,
  /\bsystemctl\s+mask\s+systemd-journald\b/,
  /\bservice\s+rsyslog\s+stop\b/,
  /\bservice\s+syslog\s+stop\b/,
  /\bpkill\s+-9\s+rsyslogd\b/,
  /\brm\s+-rf?\s+\/var\/log\//,
  />\s*\/var\/log\/\w+/,

  // Security updates disabling
  /\bapt-mark\s+hold\b/,
  /\bapt-mark\s+unattended-upgrades\s+hold\b/,
  /\bsystemctl\s+stop\s+unattended-upgrades\b/,
  /\bsystemctl\s+disable\s+unattended-upgrades\b/,
  /\bsystemctl\s+stop\s+apt-daily\b/,
  /\bsystemctl\s+mask\s+apt-daily\b/,
  /\byum-config-manager\s+--disable\b/,
  /\byum-config-manager\s+--disable\s+\*\b/,
  /\bdnf\s+config-manager\s+--set-disabled\b/,
  /Update-Package-Lists.*0/,
  /Unattended-Upgrade.*0/,

  // Kernel security features disabling
  /\becho\s+0\s*>\s*\/proc\/sys\/kernel\/randomize_va_space\b/,
  /\bsysctl\s+-w\s+kernel\.randomize_va_space=0\b/,
  /\bsysctl\s+kernel\.randomize_va_space=0\b/,
  /\becho\s+0\s*>\s*\/proc\/sys\/kernel\/exec-shield\b/,
  /\bsysctl\s+-w\s+kernel\.exec-shield=0\b/,
  /\bsysctl\s+-w\s+kernel\.kptr_restrict=0\b/,
  /\bsysctl\s+-w\s+kernel\.dmesg_restrict=0\b/,
  /\bsysctl\s+-w\s+kernel\.yama\.ptrace_scope=0\b/,

  // Disabling MAC (Mandatory Access Control)
  /\bsysctl\s+-w\s+kernel\.grsecurity\.\w+=0\b/,
  /\bsysctl\s+-w\s+security\.\w+=0\b/,

  // Windows Security Center disabling
  /\bsc\s+stop\s+WinDefend\b/i,
  /\bsc\s+stop\s+SecurityHealthService\b/i,
  /\bsc\s+stop\s+wscsvc\b/i,
  /\bsc\s+config\s+WinDefend\s+start=disabled\b/i,

  // Disabling SecureBoot checks (Windows)
  /\bbcdedit\s+\/set\s+\{default\}\s+bootstatuspolicy\s+ignoreallfailures\b/i,
  /\bbcdedit\s+\/set\s+\{default\}\s+recoveryenabled\s+no\b/i,

  // Disabling system integrity checks
  /\bcsrutil\s+disable\b/i, // macOS SIP
  /\bspctl\s+--master-disable\b/i, // macOS Gatekeeper
];

/**
 * Safe operations that check status without disabling
 */
const SAFE_PATTERNS = [
  /\bufw\s+status\b/,
  /\bsystemctl\s+status\s+\w+\b/,
  /\bservice\s+\w+\s+status\b/,
  /\bgetenforce\b/,
  /\bsetenforce\s+1\b/, // Enable SELinux
  /\bsetenforce\s+Enforcing\b/i,
  /\baa-status\b/,
  /\bapparmor_status\b/,
  /\bauditctl\s+-l\b/,
  /\bauditctl\s+--list\b/,
  /\bGet-MpPreference\b/i,
  /\bGet-MpComputerStatus\b/i,
  /\bsystemctl\s+start\s+\w+\b/, // Starting services is safe
  /\bsystemctl\s+enable\s+\w+\b/, // Enabling services is safe
  /\bufw\s+enable\b/,
  /\bufw\s+--force\s+enable\b/,
];

export function detectSecurityToolDisabling(
  toolUseData: ToolUseData,
  config?: SecurityToolDisablingConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  // First check if this is a safe operation
  for (const safePattern of SAFE_PATTERNS) {
    if (safePattern.test(toolInput)) {
      return Promise.resolve(null);
    }
  }

  // Check for security disabling patterns
  for (const pattern of SECURITY_DISABLING_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity,
        message:
          'Attempt to disable security protection detected - this could leave the system vulnerable',
        detector: 'security-tool-disabling',
      });
    }
  }

  return Promise.resolve(null);
}
