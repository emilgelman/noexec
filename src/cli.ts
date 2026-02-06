#!/usr/bin/env node

import { Command } from 'commander';
import { initCommand } from './commands/init';
import { analyzeCommand } from './commands/analyze';
import { generateConfigFile, validateConfigFile } from './config';
import chalk from 'chalk';

const program = new Command();

program
  .name('noexec')
  .description(
    'Security scanner for agentic CLIs - prevents dangerous commands and credential leaks',
  )
  .version('1.0.0');

program
  .command('init')
  .description('Initialize noexec by configuring hooks in detected CLI tools')
  .option('--platform <platform>', 'Specific platform to configure (claude)', 'claude')
  .option('--config', 'Generate a default config file (noexec.config.json)')
  .action((options) => {
    if (options.config) {
      try {
        const configPath = generateConfigFile();
        console.log(chalk.green(`✅ Generated config file: ${configPath}`));
        console.log(
          chalk.cyan('\n💡 Edit this file to customize detector behavior and thresholds.\n'),
        );
      } catch (error) {
        if (error instanceof Error) {
          console.error(chalk.red(`❌ Error: ${error.message}`));
        }
        process.exit(1);
      }
    } else {
      initCommand(options);
    }
  });

program
  .command('analyze')
  .description('Analyze tool use for security issues')
  .option('--hook <hook>', 'Hook type being executed', 'PreToolUse')
  .option('--config <path>', 'Path to custom config file')
  .action(analyzeCommand);

program
  .command('validate-config')
  .description('Validate a noexec config file')
  .argument('[path]', 'Path to config file (default: ./noexec.config.json)', './noexec.config.json')
  .action((path: string) => {
    try {
      validateConfigFile(path);
      console.log(chalk.green(`✅ Config file is valid: ${path}`));
    } catch (error) {
      if (error instanceof Error) {
        console.error(chalk.red(`❌ Invalid config: ${error.message}`));
      }
      process.exit(1);
    }
  });

program.parse();
