#!/usr/bin/env node

import { Command } from 'commander';
import { initCommand } from './commands/init';
import { analyzeCommand } from './commands/analyze';
import { loginCommand } from './commands/login';
import { teamSyncCommand } from './commands/team';

const program = new Command();

program
  .name('noexec')
  .description(
    'Security scanner for agentic CLIs - prevents dangerous commands and credential leaks'
  )
  .version('1.0.0');

program
  .command('init')
  .description('Initialize noexec by configuring hooks in detected CLI tools')
  .option('--platform <platform>', 'Specific platform to configure (claude)', 'claude')
  .action(initCommand);

program
  .command('analyze')
  .description('Analyze tool use for security issues')
  .option('--hook <hook>', 'Hook type being executed', 'PreToolUse')
  .action(analyzeCommand);

program
  .command('login')
  .description('Authenticate with the noexec platform')
  .option('--email <email>', 'Email address')
  .option('--password <password>', 'Password')
  .option('--api-url <url>', 'Custom API URL')
  .action(loginCommand);

program
  .command('team')
  .description('Sync team configuration from platform')
  .action(teamSyncCommand);

program.parse();
