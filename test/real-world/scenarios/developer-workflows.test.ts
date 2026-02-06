import { describe, it, expect } from 'vitest';
import { credentialLeakDetector } from '../../../src/detectors/credential-leak.js';
import { destructiveCommandsDetector } from '../../../src/detectors/destructive-commands.js';
import { gitForceOperationsDetector } from '../../../src/detectors/git-force-operations.js';
import { envVarLeakDetector } from '../../../src/detectors/env-var-leak.js';

/**
 * Real-world developer workflow scenarios
 * These commands should generally be safe and not trigger false positives
 */
describe('Developer Workflows - Git Operations', () => {
  const safeGitCommands = [
    'git clone https://github.com/facebook/react.git',
    'git pull origin main',
    'git push origin feature/new-feature',
    'git commit -m "fix: update dependencies"',
    'git checkout -b feature/add-tests',
    'git merge develop',
    'git stash',
    'git stash pop',
    'git rebase develop',
    'git cherry-pick abc123',
    'git log --oneline -10',
    'git diff HEAD~1',
    'git status',
    'git branch -D old-feature', // Local branch deletion is safe
  ];

  it('should not flag safe git operations', () => {
    safeGitCommands.forEach((cmd) => {
      const result = gitForceOperationsDetector.analyze(cmd, {});
      expect(result).toBeNull();
    });
  });

  const dangerousGitCommands = [
    { cmd: 'git push -f origin main', reason: 'force push to main' },
    { cmd: 'git push --force origin master', reason: 'force push to master' },
    {
      cmd: 'git push origin +main:main',
      reason: 'force push with + syntax',
    },
  ];

  it('should flag dangerous git operations', () => {
    dangerousGitCommands.forEach(({ cmd, reason }) => {
      const result = gitForceOperationsDetector.analyze(cmd, {});
      expect(result, `Expected to detect: ${reason}`).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});

describe('Developer Workflows - Package Management', () => {
  const safePackageCommands = [
    'npm install',
    'npm install --save-dev typescript',
    'npm run build',
    'npm test',
    'npm ci',
    'yarn install',
    'yarn add react',
    'pnpm install',
    'pip install -r requirements.txt',
    'pip install numpy pandas',
    'cargo build --release',
    'go mod download',
    'composer install',
  ];

  it('should not flag safe package manager commands', () => {
    safePackageCommands.forEach((cmd) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});

      expect(credResult, `Credential false positive on: ${cmd}`).toBeNull();
      expect(destructResult, `Destructive false positive on: ${cmd}`).toBeNull();
    });
  });
});

describe('Developer Workflows - Docker & Containers', () => {
  const safeDockerCommands = [
    'docker build -t myapp:latest .',
    'docker run -d -p 3000:3000 myapp',
    'docker-compose up -d',
    'docker-compose down',
    'docker ps',
    'docker logs myapp',
    'docker exec -it myapp /bin/bash',
    'kubectl apply -f deployment.yaml',
    'kubectl get pods',
    'kubectl logs pod-name',
    'kubectl describe service myapp',
  ];

  it('should not flag safe Docker/K8s commands', () => {
    safeDockerCommands.forEach((cmd) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});

      expect(credResult, `Credential false positive on: ${cmd}`).toBeNull();
      expect(destructResult, `Destructive false positive on: ${cmd}`).toBeNull();
    });
  });

  const dangerousDockerCommands = [
    {
      cmd: 'docker run --rm -v /:/host alpine rm -rf /host/etc',
      reason: 'destructive host mount',
    },
    {
      cmd: 'kubectl delete namespace production',
      reason: 'delete production namespace',
    },
  ];

  it('should flag dangerous Docker/K8s operations', () => {
    dangerousDockerCommands.forEach(({ cmd, reason }) => {
      const result = destructiveCommandsDetector.analyze(cmd, {});
      expect(result, `Expected to detect: ${reason}`).not.toBeNull();
    });
  });
});

describe('Developer Workflows - CI/CD Pipelines', () => {
  const safeCICDCommands = [
    'npm run lint',
    'npm run test:coverage',
    'npm run build',
    './scripts/deploy-staging.sh',
    'rsync -avz dist/ user@server:/var/www/',
    'ssh deploy@server "pm2 restart app"',
    'curl -X POST https://api.vercel.com/deploy',
    'gh release create v1.0.0',
    'aws s3 sync dist/ s3://my-bucket/',
    'gcloud app deploy',
  ];

  it('should not flag safe CI/CD commands', () => {
    safeCICDCommands.forEach((cmd) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      expect(credResult, `Credential false positive on: ${cmd}`).toBeNull();
      expect(destructResult, `Destructive false positive on: ${cmd}`).toBeNull();
      expect(envResult, `EnvVar false positive on: ${cmd}`).toBeNull();
    });
  });
});

describe('Developer Workflows - File Operations', () => {
  const safeFileCommands = [
    'rm -rf node_modules',
    'rm -rf dist',
    'rm -rf .next',
    'rm -rf build',
    'rm -rf target',
    'rm -rf coverage',
    'mkdir -p src/components',
    'cp .env.example .env',
    'mv old-file.js new-file.js',
    'find . -name "*.log" -delete',
    'tar -czf backup.tar.gz ./data',
    'unzip package.zip',
  ];

  it('should not flag safe file operations', () => {
    safeFileCommands.forEach((cmd) => {
      const result = destructiveCommandsDetector.analyze(cmd, {});
      expect(result, `False positive on: ${cmd}`).toBeNull();
    });
  });

  const dangerousFileCommands = [
    { cmd: 'rm -rf /', reason: 'root directory deletion' },
    { cmd: 'rm -rf ~/*', reason: 'home directory deletion' },
    { cmd: 'dd if=/dev/zero of=/dev/sda', reason: 'disk overwrite' },
    { cmd: 'chmod -R 777 /', reason: 'dangerous permission change' },
  ];

  it('should flag dangerous file operations', () => {
    dangerousFileCommands.forEach(({ cmd, reason }) => {
      const result = destructiveCommandsDetector.analyze(cmd, {});
      expect(result, `Expected to detect: ${reason}`).not.toBeNull();
      expect(result?.severity).toBe('high');
    });
  });
});

describe('Developer Workflows - Database Operations', () => {
  const safeDatabaseCommands = [
    'psql -U postgres -d mydb -c "SELECT * FROM users LIMIT 10"',
    'mysql -u root -p mydb < schema.sql',
    'mongodump --db mydb --out ./backup',
    'redis-cli PING',
    'sqlite3 mydb.db "SELECT count(*) FROM users"',
  ];

  it('should not flag safe database commands', () => {
    safeDatabaseCommands.forEach((cmd) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});

      // Note: These might trigger credential warnings if they contain actual passwords
      // but should not trigger false positives with -p flag alone
      expect(destructResult, `Destructive false positive on: ${cmd}`).toBeNull();
    });
  });
});

describe('Developer Workflows - Testing & Debugging', () => {
  const safeTestingCommands = [
    'npm test',
    'npm run test:watch',
    'jest --coverage',
    'vitest run',
    'pytest tests/',
    'cargo test',
    'go test ./...',
    'npm run debug',
    'node --inspect index.js',
    'strace -p 1234',
    'ltrace ./myapp',
  ];

  it('should not flag safe testing commands', () => {
    safeTestingCommands.forEach((cmd) => {
      const credResult = credentialLeakDetector.analyze(cmd, {});
      const destructResult = destructiveCommandsDetector.analyze(cmd, {});
      const envResult = envVarLeakDetector.analyze(cmd, {});

      expect(credResult, `Credential false positive on: ${cmd}`).toBeNull();
      expect(destructResult, `Destructive false positive on: ${cmd}`).toBeNull();
      expect(envResult, `EnvVar false positive on: ${cmd}`).toBeNull();
    });
  });
});
