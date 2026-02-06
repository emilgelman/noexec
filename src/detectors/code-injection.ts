import type { Detection, ToolUseData } from '../types';

/**
 * Detects code injection and dynamic code execution patterns
 *
 * Severity: CRITICAL
 * Reason: Arbitrary code execution vulnerabilities
 */

/**
 * Patterns for eval/exec in various languages
 */
const EVAL_EXEC_PATTERNS = [
  // Python eval/exec
  /\beval\s*\(/,
  /\bexec\s*\(/,
  /\b__import__\s*\(/,
  /\bcompile\s*\([^)]*['"]exec['"][^)]*\)/,

  // JavaScript eval
  /\bFunction\s*\(/,
  /new\s+Function\s*\(/,

  // Ruby eval
  /\beval\s*[([]/,
  /\binstance_eval\b/,
  /\bclass_eval\b/,
  /\bmodule_eval\b/,

  // PHP exec-family
  /\bshell_exec\s*\(/,
  /\bpassthru\s*\(/,
  /\bproc_open\s*\(/,
  /\bpopen\s*\(/,

  // PHP eval
  /\bassert\s*\([^)]*\$/, // PHP assert with variables (can be used as eval)

  // Perl eval
  /\beval\s*[{"']/,

  // Lua loadstring/load
  /\bloadstring\s*\(/,
  /\bload\s*\(/,
];

/**
 * Patterns for dynamic imports with variables
 */
const DYNAMIC_IMPORT_PATTERNS = [
  // JavaScript/Node.js dynamic imports with variables
  /\bimport\s*\(\s*[a-zA-Z_$]/,
  /\bimport\s*\([^)]*\+[^)]*\)/,
  /\bimport\s*\([^)]*\$\{/,
  /\bimport\s*\(`[^`]*\$\{/,

  // require with concatenation/variables
  /\brequire\s*\([^)]*\+[^)]*\)/,
  /\brequire\s*\([^)]*\$\{/,
  /\brequire\s*\(`[^`]*\$\{/,

  // Python __import__ with variables
  /\b__import__\s*\([a-zA-Z_]/,
  /\b__import__\s*\([^)]*\+[^)]*\)/,
  /\b__import__\s*\([^)]*%[^)]*\)/,
  /\b__import__\s*\([^)]*f['"]/,

  // Python importlib with variables
  /\bimportlib\.import_module\s*\([a-zA-Z_]/,
  /\bimportlib\.import_module\s*\([^)]*\+[^)]*\)/,
];

/**
 * Template injection patterns
 */
const TEMPLATE_INJECTION_PATTERNS = [
  // Jinja2/Flask/Django template injection
  /{{[^}]*(?:config|request|session|g\.|self\.|_|\.(?:__class__|__bases__|__subclasses__|__globals__))/,
  /{{[^}]*\[\s*['"]__.*?__['"]\s*]/,

  // Handlebars/Mustache with variables
  /\{\{[^}]*(?:process\.env|require\(|import\()/,

  // ERB (Ruby) injection
  /<%[^%]*=\s*[a-zA-Z_$]/,

  // String formatting with user input (Python)
  /\.format\s*\([^)]*(?:request|input|user|param)/i,
  /%\s*(?:request|input|user|param)/i,

  // JavaScript template literals with suspicious patterns
  /`[^`]*\$\{[^}]*(?:eval|Function|require|import|exec)\(/,
  /`[^`]*\$\{[^}]*\[[^}]*\]/,

  // Server-Side Template Injection markers
  /\$\{[^}]*(?:7\*7|#this|@java|\.getClass\(\)|\.class|\.forName)/,
  /\$\{[^}]*(?:Runtime|ProcessBuilder|getRuntime)/,

  // Thymeleaf injection
  /__\$\{[^}]*T\(java/,
  /__\$\{[^}]*new java/,

  // FreeMarker injection
  /<#[^>]*(?:assign|import|include)[^>]*[a-zA-Z_$]/,
];

/**
 * SQL injection patterns
 */
const SQL_INJECTION_PATTERNS = [
  // Python f-strings in execute (JSON.stringify escapes quotes to \")
  /(?:execute|cursor\.execute)\s*\(\s*f\\?["']/,

  // Python string concatenation in SQL
  /(?:execute|cursor\.execute)\s*\([^)]*\+[^)]*\)/,
  /(?:execute|cursor\.execute)\s*\([^)]*%[^)]*\)/,

  // JavaScript string concatenation with SQL keywords
  /(?:query|execute)\s*\([^)]*\\?["'][^"']*\+[^)]*\)/,

  // JavaScript template literals with SQL  
  /(?:query|execute)\s*\(`[^`]*\$\{[^}]*\}[^`]*(?:SELECT|INSERT|UPDATE|DELETE)/i,

  // PHP mysqli/mysql with concatenation
  /(?:mysqli_query|mysql_query|pg_query)\s*\([^)]*\\?["'][^"']*\.[^)]*\)/,

  // Ruby string interpolation in SQL
  /(?:execute|query|find_by_sql)\s*\([^)]*#{/,

  // Generic: SQL keywords with concatenation operators
  /(?:SELECT|INSERT|UPDATE|DELETE)[^;]*(?:\+|\.|\|\||&)[^;]*(?:WHERE|VALUES|SET|FROM)/i,
];

/**
 * Command substitution and injection patterns
 */
const COMMAND_INJECTION_PATTERNS = [
  // Backticks (command substitution)
  /`[^`]*\$[a-zA-Z_]/,
  /`[^`]*\{/,

  // $() command substitution with variables
  /\$\([^)]*\$[a-zA-Z_]/,
  /\$\([^)]*\{/,

  // Shell command building with concatenation
  /(?:system|exec|popen|subprocess\.call|subprocess\.run|os\.system)\s*\([^)]*(?:\+|%|f['"])[^)]*\)/,
  /(?:system|exec|popen)\s*\([^)]*\$\{/,

  // Python subprocess with shell=True and string concatenation
  /subprocess\.[a-zA-Z_]+\s*\([^)]*shell\s*=\s*True[^)]*(?:\+|%|f['"])/,

  // JavaScript child_process with concatenation
  /(?:exec|spawn|execSync|spawnSync)\s*\([^)]*\+[^)]*\)/,
  /(?:exec|spawn|execSync|spawnSync)\s*\(`[^`]*\$\{/,

  // Ruby backticks and system with interpolation
  /`[^`]*#{/,
  /system\s*\([^)]*#{/,
  /%x{[^}]*#{/,

  // PHP shell commands with concatenation
  /(?:shell_exec|exec|system|passthru)\s*\([^)]*\.[^)]*\$/,
  /`[^`]*\.[^`]*\$/,
];

/**
 * Deserialization patterns
 */
const DESERIALIZATION_PATTERNS = [
  // Python pickle
  /\bpickle\.loads?\s*\(/,
  /\bcPickle\.loads?\s*\(/,
  /\bdill\.loads?\s*\(/,

  // Python YAML unsafe load
  /\byaml\.load\s*\(/,
  /\byaml\.unsafe_load\s*\(/,
  /\byaml\.full_load\s*\([^)]*(?!Loader\s*=\s*yaml\.SafeLoader)/,

  // JavaScript JSON.parse on untrusted data
  /JSON\.parse\s*\([^)]*(?:request|req\.|input|user|param)/i,

  // Java deserialization
  /ObjectInputStream\s*\(/,
  /readObject\s*\(\s*\)/,
  /XMLDecoder\s*\(/,

  // PHP unserialize
  /\bunserialize\s*\([^)]*\$[a-zA-Z_]/,

  // Ruby Marshal.load
  /Marshal\.load\s*\(/,
  /Marshal\.restore\s*\(/,

  // Python shelve with untrusted data
  /shelve\.open\s*\([^)]*(?:request|input|user)/i,
];

/**
 * Dynamic function call patterns
 */
const DYNAMIC_FUNCTION_PATTERNS = [
  // Python getattr with variables (not string literals which are safer)
  /\bgetattr\s*\([^)]*,\s*[a-zA-Z_$][a-zA-Z0-9_$]*\s*\)/,

  // PHP call_user_func family
  /\bcall_user_func\s*\(\s*\$[a-zA-Z_]/,
  /\bcall_user_func_array\s*\(\s*\$[a-zA-Z_]/,
  /\$[a-zA-Z_]+\s*\(/,

  // JavaScript dynamic property access for functions
  /\[[^[\]]*\]\s*\(/,

  // Python __getattribute__
  /\.__getattribute__\s*\(/,

  // Reflection-based calls
  /\breflect\.[a-zA-Z_]+\s*\(/,
  /\.invoke\s*\(/,
  /\.getMethod\s*\([^)]*\)\s*\.invoke/,
];

/**
 * Safe patterns that should not trigger detection
 */
const SAFE_PATTERNS = [
  // Python ast.literal_eval (safe evaluation)
  /\bast\.literal_eval\s*\(/,

  // YAML safe load
  /\byaml\.safe_load\s*\(/,
  /\byaml\.load\s*\([^)]*Loader\s*=\s*yaml\.SafeLoader/,

  // Parameterized SQL queries (safe)
  /\.execute\s*\([^)]*,\s*[[(]/, // Python parameterized
  /query\s*\([^)]*,\s*[[{]/, // JS parameterized
  /prepare\s*\(/,

  // Comments and documentation
  /^\s*(?:#|\/\/|\/\*).*(?:eval|exec|import)/,

  // String literals without actual execution (in quotes or after print)
  /(?:print|console\.log|echo)\s*\([^)]*["'](?:eval|exec|import)["']/,
  /["'](?:eval|exec|import)["']\s*(?:is|are|was|were|be|been)/,

  // subprocess without shell=True (safer)
  /subprocess\.[a-zA-Z_]+\s*\(\s*\[[^\]]*\](?!.*shell\s*=\s*True)/,

  // system/exec in comments explaining not to use them
  /[#\/]\s*[Dd]o\s+not\s+use\s+(?:eval|exec)/,
  /[#\/]\s*[Aa]void\s+(?:eval|exec)/,
  /[#\/]\s*[Nn]ever\s+use\s+(?:eval|exec)/,
];

/**
 * Check if command contains safe patterns
 */
function isSafePattern(command: string): boolean {
  return SAFE_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check if this is a comment or documentation
 */
function isCommentOrDocstring(command: string): boolean {
  const lines = command.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    // Skip comments
    if (trimmed.startsWith('#') || trimmed.startsWith('//') || trimmed.startsWith('*')) {
      continue;
    }
    // Skip docstrings
    if (trimmed.startsWith('"""') || trimmed.startsWith("'''")) {
      continue;
    }
    // If we find actual code, it's not just a comment
    if (trimmed.length > 0) {
      return false;
    }
  }
  return true;
}

/**
 * Detect code injection patterns
 */
export function detectCodeInjection(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  // Check for safe patterns first
  if (isSafePattern(toolInput)) {
    return Promise.resolve(null);
  }

  // Check if it's just comments/documentation
  if (isCommentOrDocstring(toolInput)) {
    return Promise.resolve(null);
  }

  // Check for eval/exec patterns
  for (const pattern of EVAL_EXEC_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Code injection risk: eval()/exec() detected - can execute arbitrary code from user input',
        detector: 'code-injection',
      });
    }
  }

  // Check for dynamic imports with variables
  for (const pattern of DYNAMIC_IMPORT_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Code injection risk: dynamic import with variables - attacker may control module path',
        detector: 'code-injection',
      });
    }
  }

  // Check for template injection
  for (const pattern of TEMPLATE_INJECTION_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Code injection risk: template injection detected - untrusted input in template may execute code',
        detector: 'code-injection',
      });
    }
  }

  // Check for SQL injection
  for (const pattern of SQL_INJECTION_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'SQL injection risk: raw SQL with string concatenation - use parameterized queries instead',
        detector: 'code-injection',
      });
    }
  }

  // Check for command injection
  for (const pattern of COMMAND_INJECTION_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Command injection risk: shell command built with untrusted input - may execute arbitrary commands',
        detector: 'code-injection',
      });
    }
  }

  // Check for unsafe deserialization
  for (const pattern of DESERIALIZATION_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Code injection risk: unsafe deserialization - pickle/yaml.load/unserialize can execute code',
        detector: 'code-injection',
      });
    }
  }

  // Check for dynamic function calls
  for (const pattern of DYNAMIC_FUNCTION_PATTERNS) {
    if (pattern.test(toolInput)) {
      return Promise.resolve({
        severity: 'high',
        message:
          'Code injection risk: dynamic function call with untrusted input - attacker may control execution flow',
        detector: 'code-injection',
      });
    }
  }

  return Promise.resolve(null);
}
