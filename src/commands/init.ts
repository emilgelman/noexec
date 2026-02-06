import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';

interface InitOptions {
  platform: string;
}

interface ClaudeHook {
  type: string;
  command: string;
}

interface ClaudePreToolUse {
  matcher: string;
  hooks: ClaudeHook[];
}

interface ClaudeConfig {
  hooks?: {
    PreToolUse?: ClaudePreToolUse[];
  };
}

export async function initCommand(options: InitOptions): Promise<void> {
  console.log(`Initializing noexec for platform: ${options.platform}`);

  if (options.platform === 'claude') {
    await initClaude();
  } else {
    console.error(`Unknown platform: ${options.platform}`);
    process.exit(1);
  }
}

function initClaude(): Promise<void> {
  const homeDir = os.homedir();
  const claudeDir = path.join(homeDir, '.claude');
  const claudeSettingsPath = path.join(claudeDir, 'settings.json');

  console.log(`Looking for Claude settings at: ${claudeSettingsPath}`);

  // Ensure .claude directory exists
  if (!fs.existsSync(claudeDir)) {
    console.log('Creating .claude directory');
    fs.mkdirSync(claudeDir, { recursive: true });
  }

  let config: ClaudeConfig = {};

  if (fs.existsSync(claudeSettingsPath)) {
    console.log('Found existing Claude settings');
    const content = fs.readFileSync(claudeSettingsPath, 'utf-8');
    // eslint-disable-next-line @typescript-eslint/no-unsafe-assignment
    config = JSON.parse(content);
  } else {
    console.log('No existing Claude settings found, creating new file');
  }

  config.hooks ??= {};
  config.hooks.PreToolUse ??= [];

  const noexecHook: ClaudePreToolUse = {
    matcher: 'Bash',
    hooks: [
      {
        type: 'command',
        command: 'noexec analyze --hook PreToolUse',
      },
    ],
  };

  const existingHookIndex = config.hooks.PreToolUse.findIndex((h) =>
    h.hooks?.some((hook) => hook.command?.includes('noexec analyze'))
  );

  if (existingHookIndex >= 0) {
    console.log('Updating existing noexec hook configuration');
    config.hooks.PreToolUse[existingHookIndex] = noexecHook;
  } else {
    console.log('Adding noexec hook configuration');
    config.hooks.PreToolUse.push(noexecHook);
  }

  fs.writeFileSync(claudeSettingsPath, JSON.stringify(config, null, 2), 'utf-8');
  console.log(`\nSuccessfully configured noexec in ${claudeSettingsPath}`);
  console.log('\nnoexec will now analyze Bash commands before execution.');
  console.log(
    '\nNote: You may need to restart your Claude Code session for the hook to take effect.'
  );

  return Promise.resolve();
}
