#!/usr/bin/env node

import { Command } from 'commander';
import { initCommand } from './commands/init';
import { analyzeCommand } from './commands/analyze';

const program = new Command();

program
  .name('noexec')
  .description(
    'Security scanner for agentic CLIs - prevents dangerous commands and credential leaks'
  )
  .version('0.1.0');

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

program.parse();
