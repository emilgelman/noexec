#!/usr/bin/env node

import { Command } from 'commander';
import { initCommand } from './commands/init';
import { analyzeCommand } from './commands/analyze';
import { loginCommand } from './commands/login';
import { logoutCommand } from './commands/logout';

const program = new Command();

program
  .name('noexec')
  .description(
    'Security scanner for agentic CLIs - prevents dangerous commands and credential leaks'
  )
  .version('1.0.0');

program
  .command('init')
  .description('Initialize noexec and choose authentication mode (free or team)')
  .option('--platform <platform>', 'Specific platform to configure (claude)', 'claude')
  .action(initCommand);

program
  .command('analyze')
  .description('Analyze tool use for security issues')
  .option('--hook <hook>', 'Hook type being executed', 'PreToolUse')
  .action(analyzeCommand);

program
  .command('login')
  .description('Authenticate with the noexec team platform')
  .option('--email <email>', 'Email address')
  .option('--password <password>', 'Password')
  .option('--api-url <url>', 'Custom API URL')
  .action(loginCommand);

program
  .command('logout')
  .description('Switch to free (local) mode and clear team credentials')
  .action(logoutCommand);

program.parse();
