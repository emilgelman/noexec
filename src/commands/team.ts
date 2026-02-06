import chalk from 'chalk';
import { fetchTeamConfig } from '../api-client';
import { loadPlatformConfig } from '../config/platform';

export async function teamSyncCommand(): Promise<void> {
  try {
    const platformConfig = loadPlatformConfig();

    if (!platformConfig?.apiKey || !platformConfig.teamId) {
      console.error(chalk.red('\n❌ Not logged in. Run `noexec login` first.\n'));
      process.exit(1);
    }

    console.log(chalk.blue.bold('\n🔄 Syncing team configuration...\n'));

    const teamConfig = await fetchTeamConfig(platformConfig);

    console.log(chalk.green.bold('✅ Successfully synced team configuration!\n'));
    console.log(chalk.gray(`   Team: ${teamConfig.teamName}`));
    console.log(chalk.gray(`   Team ID: ${teamConfig.teamId}\n`));

    if (teamConfig.config) {
      console.log(chalk.cyan('📋 Team Configuration:'));
      console.log(chalk.gray(JSON.stringify(teamConfig.config, null, 2)));
      console.log('');
    }

    // Optionally merge team config into local config
    // For now, just display it. In a real implementation, you might want to:
    // - Save team-specific detector settings
    // - Update trusted domains
    // - Apply team policies

    console.log(
      chalk.cyan('💡 Team settings have been synced. Some settings may require manual review.\n')
    );

    process.exit(0);
  } catch (error) {
    if (error instanceof Error) {
      console.error(chalk.red(`\n❌ Sync failed: ${error.message}\n`));
    } else {
      console.error(chalk.red('\n❌ An unexpected error occurred\n'));
    }
    process.exit(1);
  }
}
