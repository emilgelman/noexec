import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as readline from 'readline';
import chalk from 'chalk';
import { login } from '../api-client';
import { savePlatformConfig, getPlatformConfigPath } from '../config/platform';

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

interface NoExecConfigFile {
  mode?: 'free' | 'team';
  platform?: {
    enabled: boolean;
    apiUrl: string;
    apiKey: string;
    teamId: string;
  };
}

/**
 * Prompt for input
 */
function promptInput(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    rl.question(prompt, (answer) => {
      rl.close();
      resolve(answer);
    });
  });
}

/**
 * Prompt for password securely (hide input)
 */
function promptPassword(prompt: string): Promise<string> {
  return new Promise((resolve) => {
    const rl = readline.createInterface({
      input: process.stdin,
      output: process.stdout,
    });

    // Mute output to hide password
    const stdin = process.stdin as NodeJS.ReadStream & {
      _handle?: { setRawMode?: (mode: boolean) => void };
    };
    if (stdin._handle?.setRawMode) {
      stdin._handle.setRawMode(false);
    }

    rl.question(prompt, (answer) => {
      rl.close();
      console.log(''); // New line after password input
      resolve(answer);
    });
  });
}

/**
 * Check if noexec is already initialized
 */
function checkExistingConfig(): NoExecConfigFile | null {
  const configPath = getPlatformConfigPath();

  if (!fs.existsSync(configPath)) {
    return null;
  }

  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    return JSON.parse(content) as NoExecConfigFile;
  } catch {
    return null;
  }
}

/**
 * Save mode configuration
 */
function saveModeConfig(mode: 'free' | 'team'): void {
  const homeDir = os.homedir();
  const configDir = path.join(homeDir, '.noexec');
  const configPath = getPlatformConfigPath();

  // Ensure directory exists
  if (!fs.existsSync(configDir)) {
    fs.mkdirSync(configDir, { recursive: true });
  }

  let existingConfig: NoExecConfigFile = {};

  // Try to preserve existing config
  if (fs.existsSync(configPath)) {
    try {
      const content = fs.readFileSync(configPath, 'utf-8');
      existingConfig = JSON.parse(content) as NoExecConfigFile;
    } catch {
      existingConfig = {};
    }
  }

  // Set mode
  existingConfig.mode = mode;

  // Write back
  fs.writeFileSync(configPath, JSON.stringify(existingConfig, null, 2), 'utf-8');
}

/**
 * Handle team authentication flow
 */
async function handleTeamAuth(): Promise<boolean> {
  try {
    console.log(chalk.blue.bold('\n🔐 Login to noexec Team\n'));

    // Get email
    const email = await promptInput('Email: ');

    if (!email?.trim()) {
      console.error(chalk.red('❌ Email is required\n'));
      return false;
    }

    // Get password
    const password = await promptPassword('Password: ');

    if (!password?.trim()) {
      console.error(chalk.red('❌ Password is required\n'));
      return false;
    }

    console.log(chalk.gray('\n⏳ Authenticating...\n'));

    // Authenticate with platform
    const response = await login(email.trim(), password.trim());

    // Save credentials to config
    savePlatformConfig({
      enabled: true,
      apiUrl: 'https://platform.noexec.io/api',
      apiKey: response.apiKey,
      teamId: response.teamId,
    });

    // Also save mode
    saveModeConfig('team');

    console.log(
      chalk.green.bold(`✅ Logged in as ${email.trim()}. Team config will auto-apply.\n`)
    );

    return true;
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Login failed: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ An unexpected error occurred\n'));
    }
    return false;
  }
}

/**
 * Interactive authentication prompt
 */
async function promptAuthentication(): Promise<void> {
  console.log(chalk.cyan('\nHow would you like to use noexec?\n'));
  console.log(chalk.white('  1. Free (unauthenticated)'));
  console.log(chalk.gray('     → Works locally, no team features\n'));
  console.log(chalk.white('  2. Team (authenticated)'));
  console.log(chalk.gray('     → Team dashboard, centralized policies, audit logs\n'));

  const choice = await promptInput('Choose [1-2]: ');

  if (choice === '2') {
    // Team mode
    let success = false;
    while (!success) {
      success = await handleTeamAuth();

      if (!success) {
        const retry = await promptInput(
          '\nWould you like to retry or fall back to free mode? [retry/free]: '
        );

        if (retry.toLowerCase() === 'free' || retry.toLowerCase() === 'f') {
          // Fall back to free mode
          saveModeConfig('free');
          console.log(chalk.green("✓ Configured for local use. You're all set!\n"));
          break;
        }
        // Otherwise, loop will retry
      }
    }
  } else {
    // Default to free mode for choice 1 or anything else (including cancel/exit)
    saveModeConfig('free');
    console.log(chalk.green("✓ Configured for local use. You're all set!\n"));
  }
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
  return (async () => {
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
    console.log(chalk.green(`\n✓ noexec hook configured in Claude settings\n`));

    // Check if already initialized
    const existingConfig = checkExistingConfig();

    if (existingConfig?.mode) {
      console.log(chalk.yellow('⚠️  noexec is already initialized.'));
      console.log(chalk.gray(`Current mode: ${existingConfig.mode}\n`));
      console.log(chalk.cyan("Run 'noexec login' to switch to team mode"));
      console.log(chalk.cyan("or 'noexec logout' to switch to free mode\n"));
    } else {
      // Show authentication prompt
      await promptAuthentication();
    }

    console.log(
      chalk.gray(
        '\nNote: You may need to restart your Claude Code session for the hook to take effect.'
      )
    );
  })();
}
