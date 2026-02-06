import type { Detection, ToolUseData } from '../types';

// Top 100 legitimate package names for typosquatting detection
const LEGITIMATE_NPM_PACKAGES = [
  'react',
  'express',
  'lodash',
  'axios',
  'next',
  'typescript',
  'webpack',
  'eslint',
  'prettier',
  'jest',
  'babel',
  'mocha',
  'chai',
  'request',
  'commander',
  'moment',
  'async',
  'colors',
  'debug',
  'chalk',
  'dotenv',
  'uuid',
  'cors',
  'body-parser',
  'mongoose',
  'mysql',
  'sequelize',
  'redis',
  'passport',
  'jsonwebtoken',
  'bcrypt',
  'socket.io',
  'vue',
  'angular',
  'jquery',
  'bootstrap',
  'tailwindcss',
  'sass',
  'less',
  'postcss',
  'vite',
  'rollup',
  'parcel',
  'gulp',
  'grunt',
  'nodemon',
  'pm2',
  'forever',
  'yargs',
  'inquirer',
  'ora',
  'boxen',
  'node-fetch',
  'form-data',
  'multer',
  'helmet',
  'morgan',
  'winston',
  'pino',
  'bunyan',
  'cheerio',
  'puppeteer',
  'playwright',
  'selenium-webdriver',
  'supertest',
  'sinon',
  'ava',
  'tap',
  'vitest',
  'jsdom',
  'happy-dom',
  'graphql',
  'apollo-server',
  'prisma',
  'typeorm',
  'knex',
  'pg',
  'sqlite3',
  'mongodb',
  'faker',
  'chance',
  'validator',
  'joi',
  'yup',
  'zod',
  'class-validator',
  'express-validator',
  'dayjs',
  'date-fns',
  'luxon',
  'ramda',
  'underscore',
  'immutable',
  'rxjs',
  'bluebird',
  'q',
  'co',
  'through',
  'through2',
  'concat-stream',
  'stream-browserify',
];

const LEGITIMATE_PIP_PACKAGES = [
  'requests',
  'numpy',
  'pandas',
  'django',
  'flask',
  'pytest',
  'pillow',
  'matplotlib',
  'scipy',
  'scikit-learn',
  'tensorflow',
  'torch',
  'keras',
  'opencv-python',
  'beautifulsoup4',
  'selenium',
  'sqlalchemy',
  'alembic',
  'celery',
  'redis',
  'pyyaml',
  'click',
  'colorama',
  'tqdm',
  'joblib',
  'cloudpickle',
  'dill',
  'boto3',
  'botocore',
  'google-cloud-storage',
  'azure-storage-blob',
  'pydantic',
  'fastapi',
  'uvicorn',
  'aiohttp',
  'httpx',
  'urllib3',
  'certifi',
  'chardet',
  'idna',
  'cryptography',
  'paramiko',
  'fabric',
  'ansible',
  'saltstack',
  'docker',
  'kubernetes',
  'pytest-cov',
  'coverage',
  'black',
  'flake8',
  'pylint',
  'mypy',
  'isort',
  'autopep8',
  'bandit',
  'safety',
  'pipenv',
  'poetry',
  'virtualenv',
  'wheel',
  'setuptools',
  'twine',
  'sphinx',
  'mkdocs',
  'jinja2',
  'mako',
  'werkzeug',
  'gunicorn',
  'uwsgi',
  'gevent',
  'eventlet',
  'twisted',
  'tornado',
  'sanic',
  'starlette',
  'psycopg2',
  'pymongo',
  'mysql-connector-python',
  'cx-oracle',
  'pyodbc',
  'peewee',
  'pony',
  'jupyter',
  'ipython',
  'notebook',
  'jupyterlab',
  'spyder',
  'statsmodels',
  'seaborn',
  'plotly',
  'bokeh',
  'altair',
  'networkx',
  'sympy',
  'nltk',
  'spacy',
  'gensim',
  'transformers',
];

const LEGITIMATE_CARGO_PACKAGES = [
  'serde',
  'tokio',
  'clap',
  'async-trait',
  'anyhow',
  'thiserror',
  'log',
  'env_logger',
  'reqwest',
  'hyper',
  'axum',
  'actix-web',
  'rocket',
  'sqlx',
  'diesel',
  'sea-orm',
  'rayon',
  'crossbeam',
  'parking_lot',
  'dashmap',
  'bytes',
  'futures',
  'pin-project',
  'once_cell',
  'lazy_static',
  'regex',
  'chrono',
  'time',
  'uuid',
  'rand',
  'serde_json',
  'toml',
  'yaml-rust',
  'config',
];

const LEGITIMATE_GEM_PACKAGES = [
  'rails',
  'rake',
  'bundler',
  'rspec',
  'pry',
  'devise',
  'pundit',
  'cancancan',
  'sidekiq',
  'redis',
  'pg',
  'mysql2',
  'sqlite3',
  'activerecord',
  'sequel',
  'nokogiri',
  'httparty',
  'faraday',
  'rest-client',
  'dotenv',
  'puma',
  'unicorn',
  'passenger',
  'capistrano',
  'rubocop',
  'simplecov',
  'factory_bot',
  'faker',
  'webmock',
  'vcr',
  'minitest',
  'cucumber',
];

// Package manager commands and patterns
const PACKAGE_MANAGER_PATTERNS = {
  npm: {
    install:
      /\bnpm\s+(?:install|i|add)\s+(?:--[\w-]+\s+)*(@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9/_-]+)(?:@[\w.-]+)?/gi,
    registry: /\bnpm\s+config\s+set\s+registry\s+/,
    source: /\bnpm\s+(?:install|i|add)\s+(?:https?|git\+https?|git\+ssh|file):\/\//,
    ignoreScripts: /\bnpm\s+(?:install|i|add)\s+[^\n]*--ignore-scripts/,
  },
  yarn: {
    install:
      /\byarn\s+(?:workspace\s+[\w-]+\s+)?(?:add|install)\s+(?:--[\w-]+\s+)*(@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9/_-]+)(?:@[\w.-]+)?/gi,
    registry: /\byarn\s+config\s+set\s+registry\s+/,
    source: /\byarn\s+(?:add|install)\s+(?:https?|git\+https?|git\+ssh|file):\/\//,
  },
  pnpm: {
    install:
      /\bpnpm\s+(?:install|add|i)\s+(?:--[\w-]+\s+)*(@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9/@/_-]+)(?:@[\w.-]+)?/gi,
    registry: /\bpnpm\s+config\s+set\s+registry\s+/,
    source: /\bpnpm\s+(?:install|add|i)\s+(?:https?|git\+https?|git\+ssh|file):\/\//,
  },
  pip: {
    install: /\bpip(?:3)?\s+install\s+(?:--[\w-]+\s+)*([a-z0-9_-]+)(?:==[\w.-]+)?/gi,
    registry: /\bpip(?:3)?\s+config\s+set\s+/,
    source: /\bpip(?:3)?\s+install\s+(?:git\+https?|https?|file):\/\//,
    noVerify: /\bpip(?:3)?\s+install\s+[^\n]*(?:--no-verify|--trusted-host)/,
  },
  cargo: {
    install: /\bcargo\s+(?:install|add)\s+(?:--[\w-]+\s+)*([a-z0-9_-]+)/gi,
    registry: /\bcargo\s+config\s+set\s+/,
    git: /\bcargo\s+(?:install|add)\s+--git\s+/,
  },
  gem: {
    install: /\bgem\s+install\s+(?:--[\w-]+\s+)*([a-z0-9_-]+)/gi,
    source: /\bgem\s+install\s+[^\n]*(?:--source|--clear-sources)/,
  },
  go: {
    install: /\bgo\s+(?:get|install)\s+([a-z0-9./_-]+)/gi,
    insecure: /\bgo\s+(?:get|install)\s+[^\n]*-insecure/,
  },
};

// Dangerous installation contexts
const DANGEROUS_CONTEXTS = [
  // Root/sudo installs (unnecessary privilege escalation)
  /\bsudo\s+(?:npm|yarn|pnpm|pip|pip3|gem|cargo)\s+(?:install|add|i)\s+(?:-g|--global)/,

  // Installing from /tmp or /temp (suspicious location)
  /\b(?:npm|yarn|pnpm|pip|pip3|cargo|gem)\s+(?:install|add|i)\s+[^\n]*(?:\/tmp|\/temp|\\temp)\//,

  // Unknown/untrusted git repositories
  /\bgit\+ssh:\/\/(?!github\.com|gitlab\.com|bitbucket\.org)/,

  // Direct HTTP (not HTTPS) sources
  /\b(?:npm|yarn|pnpm|pip|pip3)\s+(?:install|add|i)\s+http:\/\/(?!localhost|127\.0\.0\.1)/,
];

/**
 * Calculate Levenshtein distance between two strings
 * Returns the minimum number of single-character edits (insertions, deletions, substitutions)
 */
function levenshteinDistance(str1: string, str2: string): number {
  const len1 = str1.length;
  const len2 = str2.length;

  // Create a 2D array for dynamic programming
  const dp: number[][] = Array.from({ length: len1 + 1 }, () =>
    Array.from({ length: len2 + 1 }, () => 0)
  );

  // Initialize base cases
  for (let i = 0; i <= len1; i++) {
    dp[i][0] = i;
  }
  for (let j = 0; j <= len2; j++) {
    dp[0][j] = j;
  }

  // Fill the dp table
  for (let i = 1; i <= len1; i++) {
    for (let j = 1; j <= len2; j++) {
      if (str1[i - 1] === str2[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1]!;
      } else {
        dp[i][j] =
          1 +
          Math.min(
            dp[i - 1][j], // deletion
            dp[i][j - 1], // insertion
            dp[i - 1][j - 1] // substitution
          );
      }
    }
  }

  return dp[len1][len2];
}

/**
 * Check if a package name is a potential typosquat of a legitimate package
 * Returns the legitimate package name if it's a typosquat, null otherwise
 */
function findTyposquat(
  packageName: string,
  legitimatePackages: string[],
  maxDistance = 2
): string | null {
  // Skip scoped packages (@scope/package) - they're official/organization packages
  if (packageName.startsWith('@')) {
    return null;
  }

  // Remove scope from package name (@scope/package -> package)
  const cleanName = packageName.replace(/^@[a-z0-9-]+\//, '');

  // Ignore very short package names (< 3 chars) to reduce false positives
  if (cleanName.length < 3) {
    return null;
  }

  const cleanLower = cleanName.toLowerCase();

  for (const legit of legitimatePackages) {
    const legitLower = legit.toLowerCase();

    // Exact match - not a typosquat
    if (cleanLower === legitLower) {
      return null;
    }

    const distance = levenshteinDistance(cleanLower, legitLower);

    // Check if it's close enough to be a typo but not exact match
    if (distance > 0 && distance <= maxDistance) {
      // Additional check: similar length (within 2 characters)
      const lengthDiff = Math.abs(cleanName.length - legit.length);
      if (lengthDiff <= 2) {
        // Prevent false positives for packages that are both legitimate
        // e.g., numpy and sympy are both real packages, just similar
        // Check if the package name itself is in the legitimate list
        const isLegitimate = legitimatePackages.some((pkg) => pkg.toLowerCase() === cleanLower);

        if (!isLegitimate) {
          return legit;
        }
      }
    }
  }

  return null;
}

/**
 * Extract package names from a package manager command
 */
function extractPackageNames(
  command: string,
  packageManager: 'npm' | 'yarn' | 'pnpm' | 'pip' | 'cargo' | 'gem' | 'go'
): string[] {
  const packages: string[] = [];

  // Common keywords to filter out
  const keywords = [
    'install',
    'add',
    'i',
    'npm',
    'yarn',
    'pnpm',
    'pip',
    'pip3',
    'cargo',
    'gem',
    'go',
    'get',
    'workspace',
  ];

  // For npm/yarn/pnpm/pip - split by whitespace and filter
  if (packageManager === 'npm' || packageManager === 'yarn' || packageManager === 'pnpm') {
    // Check if this is actually an npm/yarn/pnpm command
    if (!/\b(npm|yarn|pnpm)\s+/.test(command)) {
      return [];
    }

    const tokens = command.split(/\s+/);
    for (const token of tokens) {
      // Skip flags
      if (token.startsWith('--') || token === '-g' || token === '-D' || token === '--save-dev')
        continue;
      // Skip keywords
      if (keywords.includes(token.toLowerCase())) continue;
      // Skip URLs and paths
      if (
        token.startsWith('http://') ||
        token.startsWith('https://') ||
        token.startsWith('git+') ||
        token.startsWith('file:') ||
        token.startsWith('/')
      )
        continue;

      // Extract package name (strip version)
      const pkgMatch = /^(@[a-z0-9-]+\/[a-z0-9-]+|[a-z0-9][a-z0-9._/-]*)(?:@[\d][\d\w.-]*)?$/i.exec(
        token
      );
      if (pkgMatch?.[1]) {
        const pkg = pkgMatch[1];
        // Must have at least one letter/digit after stripping
        if (/[a-z0-9]/i.test(pkg)) {
          packages.push(pkg);
        }
      }
    }
  } else if (packageManager === 'pip') {
    // Check if this is actually a pip command
    if (!/\bpip(?:3)?\s+/.test(command)) {
      return [];
    }

    const tokens = command.split(/\s+/);
    for (const token of tokens) {
      if (token.startsWith('--') || token.startsWith('-')) continue;
      if (keywords.includes(token.toLowerCase())) continue;
      if (
        token.startsWith('http://') ||
        token.startsWith('https://') ||
        token.startsWith('git+') ||
        token.startsWith('/')
      )
        continue;

      const pkgMatch = /^([a-z0-9][a-z0-9_-]*)(?:==[\w.-]+)?$/i.exec(token);
      if (pkgMatch?.[1]) {
        packages.push(pkgMatch[1]);
      }
    }
  } else {
    // For cargo, gem, go - use the original regex approach
    const pattern = PACKAGE_MANAGER_PATTERNS[packageManager].install;
    let match;
    pattern.lastIndex = 0;

    while ((match = pattern.exec(command)) !== null) {
      if (match[1]) {
        packages.push(match[1]);
      }
    }
  }

  return packages;
}

/**
 * Detect package manager poisoning attempts
 */
export function detectPackagePoisoning(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);
  const command = toolUseData.command ?? '';

  // Check for dangerous contexts first (high severity)
  for (const pattern of DANGEROUS_CONTEXTS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message: 'Dangerous package installation context detected (untrusted source or location)',
        detector: 'package-poisoning',
      });
    }
  }

  // Check for registry manipulation
  if (
    PACKAGE_MANAGER_PATTERNS.npm.registry.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.yarn.registry.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.pnpm.registry.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.pip.registry.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.cargo.registry.test(toolInput)
  ) {
    return Promise.resolve({
      severity: 'high',
      message: 'Package registry manipulation detected - changing to untrusted source',
      detector: 'package-poisoning',
    });
  }

  // Check for untrusted sources (HTTP, unknown git, etc.)
  if (
    PACKAGE_MANAGER_PATTERNS.npm.source.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.yarn.source.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.pnpm.source.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.pip.source.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.cargo.git.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.gem.source.test(toolInput)
  ) {
    return Promise.resolve({
      severity: 'high',
      message: 'Installing package from untrusted or non-standard source',
      detector: 'package-poisoning',
    });
  }

  // Check for ignoring verification
  if (
    PACKAGE_MANAGER_PATTERNS.npm.ignoreScripts.test(toolInput) ||
    PACKAGE_MANAGER_PATTERNS.pip.noVerify.test(toolInput)
  ) {
    return Promise.resolve({
      severity: 'medium',
      message: 'Package installation with verification/scripts disabled',
      detector: 'package-poisoning',
    });
  }

  // Check for root/sudo installs without -g/--global
  if (
    /\bsudo\s+(?:npm|yarn|pnpm|pip|pip3|gem)\s+(?:install|add|i)\s+(?!.*-g|.*--global)/.test(
      toolInput
    )
  ) {
    return Promise.resolve({
      severity: 'medium',
      message: 'Using sudo/root for package installation (unnecessary privilege escalation)',
      detector: 'package-poisoning',
    });
  }

  // Check for insecure go get
  if (PACKAGE_MANAGER_PATTERNS.go.insecure.test(toolInput)) {
    return Promise.resolve({
      severity: 'high',
      message: 'Go package installation with -insecure flag (skips TLS verification)',
      detector: 'package-poisoning',
    });
  }

  // Check for typosquatting in npm/yarn/pnpm packages
  const npmPackages = [
    ...extractPackageNames(command, 'npm'),
    ...extractPackageNames(command, 'yarn'),
    ...extractPackageNames(command, 'pnpm'),
  ];

  for (const pkg of npmPackages) {
    const legitimatePackage = findTyposquat(pkg, LEGITIMATE_NPM_PACKAGES);
    if (legitimatePackage) {
      return Promise.resolve({
        severity: 'high',
        message: `Potential typosquatting detected: "${pkg}" is similar to legitimate package "${legitimatePackage}"`,
        detector: 'package-poisoning',
      });
    }
  }

  // Check for typosquatting in pip packages
  const pipPackages = extractPackageNames(command, 'pip');
  for (const pkg of pipPackages) {
    const legitimatePackage = findTyposquat(pkg, LEGITIMATE_PIP_PACKAGES);
    if (legitimatePackage) {
      return Promise.resolve({
        severity: 'high',
        message: `Potential typosquatting detected: "${pkg}" is similar to legitimate package "${legitimatePackage}"`,
        detector: 'package-poisoning',
      });
    }
  }

  // Check for typosquatting in cargo packages
  const cargoPackages = extractPackageNames(command, 'cargo');
  for (const pkg of cargoPackages) {
    const legitimatePackage = findTyposquat(pkg, LEGITIMATE_CARGO_PACKAGES);
    if (legitimatePackage) {
      return Promise.resolve({
        severity: 'high',
        message: `Potential typosquatting detected: "${pkg}" is similar to legitimate package "${legitimatePackage}"`,
        detector: 'package-poisoning',
      });
    }
  }

  // Check for typosquatting in gem packages
  const gemPackages = extractPackageNames(command, 'gem');
  for (const pkg of gemPackages) {
    const legitimatePackage = findTyposquat(pkg, LEGITIMATE_GEM_PACKAGES);
    if (legitimatePackage) {
      return Promise.resolve({
        severity: 'high',
        message: `Potential typosquatting detected: "${pkg}" is similar to legitimate package "${legitimatePackage}"`,
        detector: 'package-poisoning',
      });
    }
  }

  return Promise.resolve(null);
}
