import chalk from 'chalk';
import * as readline from 'readline';
import { login } from '../api-client';
import { savePlatformConfig } from '../config/platform';

interface LoginOptions {
  email?: string;
  password?: string;
  apiUrl?: string;
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

export async function loginCommand(options: LoginOptions): Promise<void> {
  try {
    console.log(chalk.blue.bold('\n🔐 Login to noexec Platform\n'));

    // Get email
    options.email ??= await promptInput('Email: ');

    if (!options.email?.trim()) {
      console.error(chalk.red('❌ Email is required\n'));
      process.exit(1);
    }

    // Get password
    options.password ??= await promptPassword('Password: ');

    if (!options.password?.trim()) {
      console.error(chalk.red('❌ Password is required\n'));
      process.exit(1);
    }

    console.log(chalk.gray('\n⏳ Authenticating...\n'));

    // Authenticate with platform
    const response = await login(options.email.trim(), options.password.trim(), options.apiUrl);

    // Save credentials to config
    savePlatformConfig({
      enabled: true,
      apiUrl: options.apiUrl ?? 'https://platform.noexec.io/api',
      apiKey: response.apiKey,
      teamId: response.teamId,
    });

    console.log(chalk.green.bold('✅ Successfully logged in!\n'));
    console.log(chalk.gray(`   Team: ${response.teamName}`));
    console.log(chalk.gray(`   Team ID: ${response.teamId}\n`));
    console.log(
      chalk.cyan('💡 Security detections will now be reported to your team dashboard.\n')
    );

    process.exit(0);
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Login failed: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ An unexpected error occurred\n'));
    }
    process.exit(1);
  }
}
