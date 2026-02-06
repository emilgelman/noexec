import { describe, it, expect } from 'vitest';
import { detectContainerEscape } from '../container-escape';
import type { ToolUseData } from '../../types';
import type { ContainerEscapeConfig } from '../../config/types';

describe('container-escape detector', () => {
  const defaultConfig: ContainerEscapeConfig = {
    enabled: true,
    severity: 'high',
    allowPrivilegedForCI: false,
  };

  describe('privileged containers', () => {
    it('should detect docker run --privileged', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --privileged ubuntu /bin/bash',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
      expect(result?.message).toContain('Privileged container');
      expect(result?.message).toContain('container escape');
    });

    it('should detect podman run --privileged', async () => {
      const toolUseData: ToolUseData = {
        command: 'podman run --privileged -it alpine sh',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Privileged container');
    });

    it('should detect privileged in docker-compose', async () => {
      const toolUseData: ToolUseData = {
        command: `services:
  app:
    image: nginx
    privileged: true`,
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Privileged container');
    });

    it('should detect privileged in Kubernetes', async () => {
      const toolUseData: ToolUseData = {
        command: `securityContext:
  privileged: true`,
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('docker socket mounting', () => {
    it('should detect docker socket mount with -v', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /var/run/docker.sock:/var/run/docker.sock alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Docker socket mount');
      expect(result?.message).toContain('full control over host Docker daemon');
    });

    it('should detect docker socket mount with --volume', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --volume=/var/run/docker.sock:/var/run/docker.sock ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Docker socket mount');
    });

    it('should detect docker socket mount in docker-compose', async () => {
      const toolUseData: ToolUseData = {
        command: `volumes:
  - /var/run/docker.sock:/var/run/docker.sock`,
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Docker socket mount');
    });

    it('should detect containerd socket mount', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /run/containerd/containerd.sock:/run/containerd/containerd.sock alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('host namespace sharing', () => {
    it('should detect --network=host', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --network=host nginx',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Host namespace');
      expect(result?.message).toContain('breaks container isolation');
    });

    it('should detect --net=host', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --net=host ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Host namespace');
    });

    it('should detect --pid=host', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --pid=host alpine ps aux',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Host namespace');
    });

    it('should detect --ipc=host', async () => {
      const toolUseData: ToolUseData = {
        command: 'podman run --ipc=host centos',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect hostNetwork in Kubernetes', async () => {
      const toolUseData: ToolUseData = {
        command: 'hostNetwork: true',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect hostPID in Kubernetes', async () => {
      const toolUseData: ToolUseData = {
        command: 'hostPID: true',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('dangerous capabilities', () => {
    it('should detect --cap-add=SYS_ADMIN', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --cap-add=SYS_ADMIN ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Dangerous Linux capability');
      expect(result?.message).toContain('SYS_ADMIN');
    });

    it('should detect --cap-add=SYS_PTRACE', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --cap-add=SYS_PTRACE alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('SYS_PTRACE');
    });

    it('should detect --cap-add=SYS_MODULE', async () => {
      const toolUseData: ToolUseData = {
        command: 'podman run --cap-add=SYS_MODULE fedora',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('SYS_MODULE');
    });

    it('should detect --cap-add=DAC_READ_SEARCH', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --cap-add=DAC_READ_SEARCH ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect --cap-add=ALL', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --cap-add=ALL centos',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Dangerous Linux capability');
    });

    it('should detect capabilities in Kubernetes', async () => {
      const toolUseData: ToolUseData = {
        command: `capabilities:
  add:
    - SYS_ADMIN`,
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('cgroups manipulation', () => {
    it('should detect writing to cgroup release_agent', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo /tmp/escape.sh > /sys/fs/cgroup/rdma/release_agent',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('cgroups manipulation');
      expect(result?.message).toContain('release_agent');
    });

    it('should detect cgroup file modification', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo 1 > /sys/fs/cgroup/notify_on_release',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('cgroups manipulation');
    });

    it('should detect mounting cgroups', async () => {
      const toolUseData: ToolUseData = {
        command: 'mount -t cgroup -o memory memory /mnt/cgroup',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect cgroup volume mount in docker', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /sys/fs/cgroup:/sys/fs/cgroup:ro ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('kernel module loading', () => {
    it('should detect modprobe', async () => {
      const toolUseData: ToolUseData = {
        command: 'modprobe nf_conntrack',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Kernel module loading');
      expect(result?.message).toContain('full system compromise');
    });

    it('should detect insmod', async () => {
      const toolUseData: ToolUseData = {
        command: 'insmod /lib/modules/kernel.ko',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Kernel module loading');
    });

    it('should detect rmmod', async () => {
      const toolUseData: ToolUseData = {
        command: 'rmmod bad_module',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect lsmod', async () => {
      const toolUseData: ToolUseData = {
        command: 'lsmod | grep netfilter',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('chroot escape', () => {
    it('should detect chroot directory traversal', async () => {
      const toolUseData: ToolUseData = {
        command: 'mkdir ./..; chroot ./..',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Chroot escape');
    });

    it('should detect pivot_root', async () => {
      const toolUseData: ToolUseData = {
        command: 'pivot_root . old_root',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Chroot escape');
    });

    it('should detect /proc/self/root access', async () => {
      const toolUseData: ToolUseData = {
        command: 'ls /proc/self/root',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect /proc/1/root access', async () => {
      const toolUseData: ToolUseData = {
        command: 'cat /proc/1/root/etc/shadow',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('nsenter abuse', () => {
    it('should detect nsenter -t 1', async () => {
      const toolUseData: ToolUseData = {
        command: 'nsenter -t 1 -m -u -n -i sh',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('nsenter to host namespaces');
      expect(result?.message).toContain('breaks isolation');
    });

    it('should detect nsenter --target=1', async () => {
      const toolUseData: ToolUseData = {
        command: 'nsenter --target=1 --mount --uts --net bash',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('nsenter');
    });

    it('should detect nsenter with all namespaces', async () => {
      const toolUseData: ToolUseData = {
        command: 'nsenter -a -t 1',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect nsenter --all', async () => {
      const toolUseData: ToolUseData = {
        command: 'nsenter --all --target 1 /bin/bash',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('core_pattern exploitation', () => {
    it('should detect writing to core_pattern', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo "|/tmp/exploit.sh" > /proc/sys/kernel/core_pattern',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('core_pattern exploitation');
      expect(result?.message).toContain('container escape');
    });

    it('should detect pipe in core_pattern', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo "|/exploit" > /proc/sys/kernel/core_pattern',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect reading core_pattern', async () => {
      const toolUseData: ToolUseData = {
        command: 'cat /proc/sys/kernel/core_pattern',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('host filesystem mounts', () => {
    it('should detect mounting host root', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /:/host ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Host filesystem mount');
      expect(result?.message).toContain('sensitive host files');
    });

    it('should detect mounting /etc', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /etc:/hostconfig alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Host filesystem mount');
    });

    it('should detect mounting /root', async () => {
      const toolUseData: ToolUseData = {
        command: 'podman run -v /root:/root centos',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect mounting /proc', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /proc:/proc ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect mounting /sys', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /sys:/sys ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect mounting /dev', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v /dev:/dev alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });

    it('should detect hostPath in Kubernetes', async () => {
      const toolUseData: ToolUseData = {
        command: `hostPath:
  path: /etc`,
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('proc/sys manipulation', () => {
    it('should detect writing to /proc/sys/', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo 1 > /proc/sys/net/ipv4/ip_forward',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('procfs/sysfs manipulation');
    });

    it('should detect accessing host processes via /proc/1/', async () => {
      const toolUseData: ToolUseData = {
        command: 'cat /proc/1/environ',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('host processes');
    });

    it('should detect writing to /sys/', async () => {
      const toolUseData: ToolUseData = {
        command: 'echo disabled > /sys/class/net/eth0/device/sriov_numvfs',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('security bypass', () => {
    it('should detect AppArmor unconfined', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --security-opt apparmor=unconfined ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('Security feature bypass');
      expect(result?.message).toContain('AppArmor');
    });

    it('should detect SELinux disable', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --security-opt label=disable centos',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('SELinux');
    });

    it('should detect seccomp unconfined', async () => {
      const toolUseData: ToolUseData = {
        command: 'podman run --security-opt seccomp=unconfined alpine',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
      expect(result?.message).toContain('seccomp');
    });

    it('should detect no-new-privileges=false', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --security-opt no-new-privileges=false ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('safe patterns', () => {
    it('should allow normal docker run', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -d -p 8080:80 nginx',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).toBeNull();
    });

    it('should allow safe volume mounts', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run -v ./data:/app/data ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).toBeNull();
    });

    it('should allow normal capabilities', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --cap-add=NET_ADMIN ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).toBeNull();
    });

    it('should allow docker ps and other read commands', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker ps -a',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).toBeNull();
    });

    it('should allow docker-compose up', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker-compose up -d',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).toBeNull();
    });
  });

  describe('CI/CD exceptions', () => {
    it('should allow privileged for docker:dind when configured', async () => {
      const ciConfig: ContainerEscapeConfig = {
        enabled: true,
        severity: 'high',
        allowPrivilegedForCI: true,
      };

      const toolUseData: ToolUseData = {
        command: 'docker run --privileged docker:dind',
      };
      const result = await detectContainerEscape(toolUseData, ciConfig);
      expect(result).toBeNull();
    });

    it('should allow Docker socket for GitLab Runner when configured', async () => {
      const ciConfig: ContainerEscapeConfig = {
        enabled: true,
        severity: 'high',
        allowPrivilegedForCI: true,
      };

      const toolUseData: ToolUseData = {
        command: 'docker run -v /var/run/docker.sock:/var/run/docker.sock gitlab/gitlab-runner',
      };
      const result = await detectContainerEscape(toolUseData, ciConfig);
      expect(result).toBeNull();
    });

    it('should still detect privileged without CI flag', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --privileged docker:dind',
      };
      const result = await detectContainerEscape(toolUseData, defaultConfig);
      expect(result).not.toBeNull();
    });
  });

  describe('detector config', () => {
    it('should respect enabled flag', async () => {
      const disabledConfig: ContainerEscapeConfig = {
        enabled: false,
        severity: 'high',
        allowPrivilegedForCI: false,
      };

      const toolUseData: ToolUseData = {
        command: 'docker run --privileged ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, disabledConfig);
      expect(result).toBeNull();
    });

    it('should use custom severity', async () => {
      const mediumConfig: ContainerEscapeConfig = {
        enabled: true,
        severity: 'medium',
        allowPrivilegedForCI: false,
      };

      const toolUseData: ToolUseData = {
        command: 'docker run --privileged ubuntu',
      };
      const result = await detectContainerEscape(toolUseData, mediumConfig);
      expect(result?.severity).toBe('medium');
    });

    it('should use default config when not provided', async () => {
      const toolUseData: ToolUseData = {
        command: 'docker run --privileged ubuntu',
      };
      const result = await detectContainerEscape(toolUseData);
      expect(result).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});
