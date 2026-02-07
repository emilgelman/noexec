import chalk from 'chalk';
import * as fs from 'fs';
import { getPlatformConfigPath } from '../config/platform';

interface NoExecConfigFile {
  mode?: 'free' | 'team';
  platform?: {
    enabled: boolean;
    apiUrl: string;
    apiKey: string;
    teamId: string;
  };
}

export function logoutCommand(): void {
  const configPath = getPlatformConfigPath();

  if (!fs.existsSync(configPath)) {
    console.log(chalk.yellow("⚠️  No configuration found. Run 'noexec init' to get started.\n"));
    process.exit(0);
  }

  // Read existing config
  let config: NoExecConfigFile = {};
  try {
    const content = fs.readFileSync(configPath, 'utf-8');
    config = JSON.parse(content) as NoExecConfigFile;
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Could not read configuration file: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ Could not read configuration file\n'));
    }
    process.exit(1);
  }

  // Check if already in free mode
  if (config.mode === 'free' && !config.platform?.apiKey) {
    console.log(chalk.blue('ℹ️  Already in free mode.\n'));
    process.exit(0);
  }

  // Switch to free mode
  config.mode = 'free';

  // Clear platform credentials
  if (config.platform) {
    config.platform.enabled = false;
    config.platform.apiKey = '';
    config.platform.teamId = '';
  }

  // Save updated config
  try {
    fs.writeFileSync(configPath, JSON.stringify(config, null, 2), 'utf-8');
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Failed to save configuration: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ Failed to save configuration\n'));
    }
    process.exit(1);
  }

  console.log(chalk.green.bold('✅ Successfully logged out!\n'));
  console.log(chalk.gray('   Switched to free (local) mode\n'));
  console.log(chalk.cyan("💡 Run 'noexec login' to reconnect to your team\n"));

  process.exit(0);
}
