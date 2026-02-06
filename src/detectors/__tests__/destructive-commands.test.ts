import { describe, it, expect } from 'vitest';
import { detectDestructiveCommand } from '../destructive-commands';

describe('detectDestructiveCommand', () => {
  describe('rm commands', () => {
    it('should detect rm -rf /', async () => {
      const result = await detectDestructiveCommand({ command: 'rm -rf /' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.detector).toBe('destructive-command');
    });

    it('should detect rm -rf ~', async () => {
      const result = await detectDestructiveCommand({ command: 'rm -rf ~' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect rm -rf with wildcards', async () => {
      const result = await detectDestructiveCommand({ command: 'rm -rf /*' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect rm with -r and -f in different order', async () => {
      const result = await detectDestructiveCommand({ command: 'rm -fr /' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow safe rm commands', async () => {
      const result = await detectDestructiveCommand({ command: 'rm old_file.txt' });
      expect(result).toBeNull();
    });

    it('should allow rm in current directory', async () => {
      const result = await detectDestructiveCommand({ command: 'rm -rf build' });
      expect(result).toBeNull();
    });
  });

  describe('dd commands', () => {
    it('should detect dd to device files', async () => {
      const result = await detectDestructiveCommand({
        command: 'dd if=/dev/zero of=/dev/sda',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect dd writing to root', async () => {
      const result = await detectDestructiveCommand({
        command: 'dd if=/dev/urandom of=/boot/vmlinuz',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should allow safe dd commands', async () => {
      const result = await detectDestructiveCommand({
        command: 'dd if=input.iso of=output.img',
      });
      expect(result).toBeNull();
    });
  });

  describe('filesystem commands', () => {
    it('should detect mkfs', async () => {
      const result = await detectDestructiveCommand({ command: 'mkfs.ext4 /dev/sdb1' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect fdisk', async () => {
      const result = await detectDestructiveCommand({ command: 'fdisk /dev/sda' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect parted', async () => {
      const result = await detectDestructiveCommand({ command: 'parted /dev/sdb' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect wipefs', async () => {
      const result = await detectDestructiveCommand({ command: 'wipefs -a /dev/sdc' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect shred', async () => {
      const result = await detectDestructiveCommand({ command: 'shred -vfz /dev/sda' });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('fork bombs', () => {
    it('should detect classic fork bomb', async () => {
      const result = await detectDestructiveCommand({
        command: ':(){ :|:& };:',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('system file operations', () => {
    it('should detect writing to /etc/passwd', async () => {
      const result = await detectDestructiveCommand({
        command: 'echo "hacker::0:0:::/bin/bash" > /etc/passwd',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chmod on critical paths', async () => {
      const result = await detectDestructiveCommand({
        command: 'chmod 777 /etc/shadow',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });

    it('should detect chown on system directories', async () => {
      const result = await detectDestructiveCommand({
        command: 'chown nobody:nobody /usr/bin/sudo',
      });
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });

  describe('safe commands', () => {
    it('should allow normal file operations', async () => {
      const testCases = [
        'rm old_file.txt',
        'dd if=input.bin of=output.bin bs=4M',
        'chmod +x script.sh',
        'chown user:group myfile.txt',
      ];

      for (const command of testCases) {
        const result = await detectDestructiveCommand({ command });
        expect(result).toBeNull();
      }
    });
  });
});
