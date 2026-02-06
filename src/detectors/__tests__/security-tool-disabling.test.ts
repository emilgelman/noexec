import { describe, it, expect } from 'vitest';
import { detectSecurityToolDisabling } from '../security-tool-disabling';
import type { ToolUseData } from '../../types';

describe('detectSecurityToolDisabling', () => {
  // Helper to create tool use data
  const createToolUse = (command: string): ToolUseData => ({
    command,
  });

  describe('Firewall disabling', () => {
    it('should detect ufw disable', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw disable'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('security-tool-disabling');
    });

    it('should detect ufw --force disable', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw --force disable'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect iptables -F', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('iptables -F'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect iptables --flush', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('iptables --flush'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect iptables -X', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('iptables -X'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect firewall-cmd --remove-all', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('firewall-cmd --remove-all'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Windows firewall disabling', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('netsh advfirewall set allprofiles state off')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect PowerShell firewall disabling', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('Set-NetFirewallProfile -Profile Domain -Enabled False')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect ufw status check', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw status'));
      expect(result).toBeNull();
    });

    it('should NOT detect ufw enable', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw enable'));
      expect(result).toBeNull();
    });
  });

  describe('SELinux disabling', () => {
    it('should detect setenforce 0', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('setenforce 0'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect setenforce Permissive', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('setenforce Permissive'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect SELINUX=disabled in config', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('echo "SELINUX=disabled" > /etc/selinux/config')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect SELINUX=permissive in config', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sed -i "s/SELINUX=enforcing/SELINUX=permissive/" /etc/selinux/config')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect setenforce 1 (enabling)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('setenforce 1'));
      expect(result).toBeNull();
    });

    it('should NOT detect getenforce (status check)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('getenforce'));
      expect(result).toBeNull();
    });
  });

  describe('AppArmor disabling', () => {
    it('should detect systemctl stop apparmor', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl stop apparmor'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl disable apparmor', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl disable apparmor'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect aa-disable', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('aa-disable /etc/apparmor.d/usr.bin.firefox')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect apparmor_parser -R', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('apparmor_parser -R /etc/apparmor.d/usr.sbin.nginx')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect aa-status (status check)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('aa-status'));
      expect(result).toBeNull();
    });

    it('should NOT detect systemctl status apparmor', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl status apparmor'));
      expect(result).toBeNull();
    });
  });

  describe('Antivirus disabling', () => {
    it('should detect Windows Defender real-time monitoring disable', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('Set-MpPreference -DisableRealtimeMonitoring $true')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Windows Defender behavior monitoring disable', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('Set-MpPreference -DisableBehaviorMonitoring true')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Windows Defender exclusion for C drive', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('Add-MpPreference -ExclusionPath "C:\\"')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect ClamAV stop', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('systemctl stop clamav-daemon')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect ClamAV disable', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl disable clamav'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect killing ClamAV daemon', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('pkill -9 clamd'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect Windows Defender status check', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('Get-MpComputerStatus'));
      expect(result).toBeNull();
    });
  });

  describe('Audit logging disabling', () => {
    it('should detect auditctl -D (delete all rules)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('auditctl -D'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect auditctl --delete-all', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('auditctl --delete-all'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect auditctl -e 0 (disable auditing)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('auditctl -e 0'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl stop auditd', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl stop auditd'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl disable auditd', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl disable auditd'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect auditctl -l (list rules)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('auditctl -l'));
      expect(result).toBeNull();
    });
  });

  describe('System logging disabling', () => {
    it('should detect systemctl stop rsyslog', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl stop rsyslog'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl disable rsyslog', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl disable rsyslog'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl stop journald', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl stop journald'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl mask systemd-journald', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('systemctl mask systemd-journald')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect removing /var/log', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('rm -rf /var/log/'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect systemctl status rsyslog', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl status rsyslog'));
      expect(result).toBeNull();
    });
  });

  describe('Security updates disabling', () => {
    it('should detect apt-mark hold', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('apt-mark hold unattended-upgrades')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl stop unattended-upgrades', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('systemctl stop unattended-upgrades')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl disable unattended-upgrades', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('systemctl disable unattended-upgrades')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect systemctl mask apt-daily', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('systemctl mask apt-daily.timer')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect yum-config-manager --disable', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('yum-config-manager --disable updates')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect dnf config-manager --set-disabled', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('dnf config-manager --set-disabled updates')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling apt periodic updates', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse(
          'echo \'APT::Periodic::Update-Package-Lists "0";\' > /etc/apt/apt.conf.d/20auto-upgrades'
        )
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Kernel security disabling', () => {
    it('should detect disabling ASLR via proc', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('echo 0 > /proc/sys/kernel/randomize_va_space')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling ASLR via sysctl', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sysctl -w kernel.randomize_va_space=0')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling exec-shield', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sysctl -w kernel.exec-shield=0')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling kptr_restrict', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sysctl -w kernel.kptr_restrict=0')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling ptrace scope', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sysctl -w kernel.yama.ptrace_scope=0')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('macOS security disabling', () => {
    it('should detect disabling SIP (System Integrity Protection)', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('csrutil disable'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling Gatekeeper', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('spctl --master-disable'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Windows security service disabling', () => {
    it('should detect stopping Windows Defender service', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('sc stop WinDefend'));
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect stopping Security Health Service', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sc stop SecurityHealthService')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect disabling Windows Defender via sc config', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('sc config WinDefend start=disabled')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('Configuration options', () => {
    it('should respect disabled config', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw disable'), {
        enabled: false,
        severity: 'high',
      });
      expect(result).toBeNull();
    });

    it('should respect custom severity', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('ufw disable'), {
        enabled: true,
        severity: 'medium',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });
  });

  describe('Edge cases and complex commands', () => {
    it('should detect security disabling in chained commands', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('apt-get update && ufw disable && apt-get upgrade')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect security disabling in scripts', async () => {
      const result = await detectSecurityToolDisabling(
        createToolUse('bash -c "systemctl stop auditd"')
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect starting security services', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl start auditd'));
      expect(result).toBeNull();
    });

    it('should NOT detect enabling security services', async () => {
      const result = await detectSecurityToolDisabling(createToolUse('systemctl enable apparmor'));
      expect(result).toBeNull();
    });
  });
});
