import { describe, it, expect } from 'vitest';
import { detectProcessManipulation } from '../process-manipulation';

describe('detectProcessManipulation', () => {
  describe('Debugger attachment', () => {
    it('should detect gdb attachment', async () => {
      const testCases = [
        'gdb -p 1234',
        'gdb --pid 1234',
        'gdb --attach 1234',
        'gdb /usr/bin/program 5678',
        'gdb -p $(pgrep ssh)',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.detector).toBe('process-manipulation');
        expect(result?.message).toContain('debugger attachment');
      }
    });

    it('should detect strace attachment', async () => {
      const testCases = [
        'strace -p 1234',
        'strace --attach 1234',
        'strace -p 5678 -o output.txt',
        'strace --attach=$(pgrep nginx)',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('debugger attachment');
      }
    });

    it('should detect lldb attachment', async () => {
      const testCases = [
        'lldb -p 1234',
        'lldb --pid 1234',
        'lldb --attach-pid 1234',
        'lldb --attach-name nginx',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('debugger attachment');
      }
    });

    it('should NOT detect safe debugging of own code', async () => {
      const testCases = [
        'gdb ./myprogram',
        'gdb --args ./myapp --debug',
        'lldb ./myapp',
        'lldb -- ./myprogram',
        'gdb myprogram core',
        'lldb --core core',
        'strace ./myprogram',
        'strace -f ./test',
        'gdb --batch -ex "bt" ./program',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('Memory dumping', () => {
    it('should detect gcore usage', async () => {
      const testCases = ['gcore 1234', 'gcore -o dumpfile 5678', 'gcore $(pgrep sshd)'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('memory dumping');
      }
    });

    it('should detect /proc/[pid]/mem access', async () => {
      const testCases = [
        'cat /proc/1234/mem',
        'cat /proc/$PID/mem',
        'dd if=/proc/1234/mem of=dump.bin',
        'head /proc/5678/mem',
        'tail /proc/9999/mem',
        'less /proc/1234/mem',
        'more /proc/5678/mem',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('memory dumping');
      }
    });

    it('should detect /proc/[pid]/maps reading', async () => {
      const testCases = [
        'cat /proc/1234/maps',
        'cat /proc/$PID/maps',
        'grep heap /proc/1234/maps',
        'grep stack /proc/5678/maps',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('memory dumping');
      }
    });

    it('should detect bulk memory scraping', async () => {
      const testCases = [
        'for pid in /proc/[0-9]*; do cat $pid/mem; done',
        'find /proc -name mem',
        'find /proc -name maps',
        'strings /proc/1234/mem',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should NOT detect reading own process info', async () => {
      const testCases = [
        'cat /proc/self/maps',
        'cat /proc/self/status',
        'cat /proc/$$/maps',
        'cat /proc/$$/status',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('ptrace usage', () => {
    it('should detect direct ptrace commands', async () => {
      const testCases = [
        'ptrace PTRACE_ATTACH',
        'ptrace PTRACE_PEEKDATA',
        'ptrace(PTRACE_ATTACH, pid, 0, 0)',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('ptrace');
      }
    });

    it('should detect Python ptrace usage', async () => {
      const testCases = [
        'import ptrace',
        'from ptrace import PtraceDebugger',
        'python -c "import ptrace; ptrace.attach(1234)"',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect LD_PRELOAD with ptrace libraries', async () => {
      const testCases = ['LD_PRELOAD=/tmp/ptrace.so ls', 'export LD_PRELOAD=/lib/ptrace_hook.so'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Process injection', () => {
    it('should detect writing to /proc/[pid]/mem', async () => {
      const testCases = [
        'echo "code" > /proc/1234/mem',
        'printf "\\x90\\x90" > /proc/5678/mem',
        'dd if=shellcode.bin of=/proc/1234/mem',
        'cat payload.bin > /proc/5678/mem',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('injection');
      }
    });

    it('should detect LD_PRELOAD injection', async () => {
      const testCases = [
        'LD_PRELOAD=/tmp/evil.so /proc/1234',
        'export LD_PRELOAD=/tmp/hook.so && sudo ls',
        'export LD_PRELOAD=/tmp/inject.so && exec bash',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect injection via /proc/[pid]/fd', async () => {
      const testCases = ['echo "malicious" > /proc/1234/fd/1', 'cat payload > /proc/5678/fd/0'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect injection scripts', async () => {
      const testCases = [
        'python inject_shellcode.py 1234',
        'perl ptrace_inject.pl 5678',
        'ruby process_inject.rb 9999',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Process hiding', () => {
    it('should detect /proc manipulation', async () => {
      const testCases = [
        'mount --bind /tmp/fake /proc',
        'umount /proc',
        'mount -t tmpfs none /proc',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('hiding');
      }
    });

    it('should detect rootkit module loading', async () => {
      const testCases = [
        'insmod rootkit.ko',
        'modprobe hide_process',
        'insmod procfs_hide.ko',
        'modprobe stealth_proc',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect LD_PRELOAD hooking', async () => {
      const testCases = [
        'LD_PRELOAD=/tmp/hook.so ps',
        'export LD_PRELOAD=/lib/hide.so',
        'LD_PRELOAD=/tmp/stealth.so top',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should NOT detect safe LD_PRELOAD for testing', async () => {
      const testCases = [
        'LD_PRELOAD=./mylib.so ./test',
        'export LD_PRELOAD=./debug.so && ./test_runner',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('Signal abuse', () => {
    it('should detect killing security processes', async () => {
      const testCases = [
        'kill -9 $(pgrep osqueryd)',
        'pkill -9 falco',
        'killall -9 auditd',
        'kill -KILL $(pgrep aide)',
        'pkill --signal=KILL tripwire',
        'killall -9 rkhunter',
        'kill -9 $(pgrep chkrootkit)',
        'pkill -9 samhain',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('killing security');
      }
    });

    it('should detect killing logging processes', async () => {
      const testCases = [
        'kill -9 $(pgrep rsyslog)',
        'pkill -9 syslog-ng',
        'killall -9 systemd-journald',
        'kill -KILL $(pgrep journald)',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect killing EDR agents', async () => {
      const testCases = [
        'kill -9 $(pgrep crowdstrike)',
        'pkill -9 falcon-sensor',
        'killall -9 cb-sensor',
        'kill -9 $(pgrep wazuh-agent)',
        'pkill -KILL ossec',
        'killall -9 clamd',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect suspending critical processes', async () => {
      const testCases = [
        'kill -19 $(pgrep osqueryd)',
        'kill -STOP $(pgrep falco)',
        'kill --signal=STOP $(pgrep auditd)',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Core dump enabling', () => {
    it('should detect ulimit -c unlimited', async () => {
      const testCases = ['ulimit -c unlimited', 'ulimit -c 999999999', 'ulimit -c 10000000'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('core dump');
      }
    });

    it('should detect core pattern manipulation', async () => {
      const testCases = [
        'echo "core.%p" > /proc/sys/kernel/core_pattern',
        'sysctl -w kernel.core_pattern=/tmp/core',
        'echo "1" > /proc/sys/kernel/core_uses_pid',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect disabling core dump restrictions', async () => {
      const testCases = ['sysctl -w fs.suid_dumpable=1', 'echo 1 > /proc/sys/fs/suid_dumpable'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Priority manipulation', () => {
    it('should detect very high nice priority', async () => {
      const testCases = [
        'nice -n -20 myprocess',
        'nice -n -19 ./script',
        'nice -n -15 command',
        'nice --adjustment=-20 program',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('priority manipulation');
      }
    });

    it('should detect renice to high priority', async () => {
      const testCases = ['renice -20 1234', 'renice --priority=-19 5678', 'renice -n -20 9999'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect real-time priority', async () => {
      const testCases = [
        'chrt -f 99 myprocess',
        'chrt --fifo 99 ./program',
        'chrt -r 99 command',
        'chrt --rr 99 process',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect real-time I/O priority', async () => {
      const testCases = [
        'ionice -c 1 myprocess',
        'ionice --class 1 program',
        'ionice -c 1 -n 0 command',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Namespace manipulation', () => {
    it('should detect unshare creating namespaces', async () => {
      const testCases = [
        'unshare -p bash',
        'unshare --pid bash',
        'unshare -n bash',
        'unshare --net bash',
        'unshare -m bash',
        'unshare --mount bash',
        'unshare -u bash',
        'unshare --uts bash',
        'unshare -i bash',
        'unshare --ipc bash',
        'unshare -U bash',
        'unshare --user bash',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('namespace manipulation');
      }
    });

    it('should detect nsenter entering namespaces', async () => {
      const testCases = [
        'nsenter -t 1234 bash',
        'nsenter --target 1234 sh',
        'nsenter -p bash',
        'nsenter --pid bash',
        'nsenter -m bash',
        'nsenter --mount bash',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect ip netns manipulation', async () => {
      const testCases = [
        'ip netns add newns',
        'ip netns del oldns',
        'ip netns exec myns bash',
        'ip netns attach myns 1234',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect namespace file manipulation', async () => {
      const testCases = [
        'mount --bind /tmp/ns /proc/1234/ns/pid',
        'cat /proc/1234/ns/net',
        'echo "data" > /proc/1234/ns/mnt',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should NOT detect safe namespace listing', async () => {
      const testCases = ['ip netns list', 'ip netns identify 1234'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('LD_PRELOAD injection', () => {
    it('should detect LD_PRELOAD from suspicious locations', async () => {
      const testCases = [
        'LD_PRELOAD=/tmp/evil.so ls',
        'LD_PRELOAD=/dev/shm/malicious.so ps',
        'LD_PRELOAD=/var/tmp/hook.so top',
        'export LD_PRELOAD=/tmp/inject.so',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
        expect(result?.message).toContain('LD_PRELOAD');
      }
    });

    it('should detect LD_PRELOAD with system binaries', async () => {
      const testCases = [
        'LD_PRELOAD=/lib/hook.so sudo ls',
        'LD_PRELOAD=/tmp/evil.so su',
        'LD_PRELOAD=/tmp/hook.so ssh user@host',
        'LD_PRELOAD=/tmp/inject.so ps',
        'export LD_PRELOAD=/tmp/hook.so; sudo bash',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });

    it('should detect LD_LIBRARY_PATH manipulation', async () => {
      const testCases = [
        'LD_LIBRARY_PATH=/tmp sudo',
        'LD_LIBRARY_PATH=/dev/shm bash',
        'export LD_LIBRARY_PATH=/tmp',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).not.toBeNull();
        expect(result?.severity).toBe('high');
      }
    });
  });

  describe('Legitimate monitoring tools', () => {
    it('should NOT detect system monitoring tools', async () => {
      const testCases = ['top', 'htop', 'ps aux', 'ps -ef', 'ps --forest', 'pstree', 'pgrep nginx'];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });

    it('should NOT detect performance monitoring', async () => {
      const testCases = [
        'perf top',
        'perf stat ls',
        'perf record ./program',
        'vmstat',
        'iostat',
        'sar',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });

    it('should NOT detect read-only process inspection', async () => {
      const testCases = [
        'lsof',
        'fuser /file',
        'pmap 1234',
        'strace -e trace=open ls',
        'strace -c ./myprogram',
      ];

      for (const command of testCases) {
        const result = await detectProcessManipulation({ command });
        expect(result).toBeNull();
      }
    });
  });

  describe('Configuration', () => {
    it('should respect enabled flag', async () => {
      const result = await detectProcessManipulation(
        { command: 'gdb -p 1234' },
        { enabled: false, severity: 'high' }
      );

      expect(result).toBeNull();
    });

    it('should use custom severity', async () => {
      const result = await detectProcessManipulation(
        { command: 'gdb -p 1234' },
        { enabled: true, severity: 'medium' }
      );

      expect(result).not.toBeNull();
      expect(result?.severity).toBe('medium');
    });
  });
});
