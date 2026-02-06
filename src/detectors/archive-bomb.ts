import type { Detection, ToolUseData } from '../types';
import type { ArchiveBombConfig } from '../config/types';

/**
 * Detects archive-based attacks including bombs, path traversal, and unsafe extraction
 */

/**
 * Pattern for extracting archives without validation
 */
const UNSAFE_EXTRACTION_PATTERNS = [
  // tar extract from untrusted sources
  /\btar\s+[^|&;]*(?:xf|xvf|xzf|xjf|extract)\b[^|&;]*(?:https?:\/\/|ftp:\/\/|curl|wget)/,
  
  // unzip from URL or untrusted source
  /\bunzip\b[^|&;]*(?:https?:\/\/|ftp:\/\/|curl|wget)/,
  
  // 7z extract from URL
  /\b7z\s+[^|&;]*x\b[^|&;]*(?:https?:\/\/|ftp:\/\/|curl|wget)/,
  
  // Piped extraction (curl | tar, wget | tar)
  /(?:curl|wget)\b[^\n|]*\|\s*tar\s+[^|&;]*(?:x|extract)/,
  /(?:curl|wget)\b[^\n|]*\|\s*unzip\b/,
  /(?:curl|wget)\b[^\n|]*\|\s*7z\s+x\b/,
  
  // tar from stdin without validation
  /\btar\s+[^|&;]*(?:xf|xvf|xzf|xjf)\s+-\b/,
];

/**
 * Path traversal patterns in archive operations
 */
const PATH_TRAVERSAL_PATTERNS = [
  // Multiple directory traversal sequences
  /(?:\.\.\/){2,}/,
  /\.\.[\\\/]\.\.[\\\/]/,
  
  // Path traversal to specific sensitive directories
  /\.\.[\\\/]+etc[\\\/]passwd/,
  /\.\.[\\\/]+etc[\\\/]shadow/,
  /\.\.[\\\/]+root[\\\/]/,
  /\.\.[\\\/]+home[\\\/]/,
  
  // Archive commands with path traversal
  /\b(?:tar|unzip|7z)\b[^&;|]*\.\.[\\\/]/,
  
  // Absolute paths in archive context (suspicious)
  /\b(?:tar|unzip|7z)\b[^&;|]*(?:\/etc|\/usr\/bin|\/usr\/local\/bin|\/root|\/bin|\/sbin)/,
];

/**
 * Extracting to sensitive/dangerous locations
 */
const DANGEROUS_EXTRACTION_LOCATIONS = [
  // Extract to system directories
  /\b(?:tar|unzip|7z)\b[^&;|]*(?:-C|--directory|cd)[^&;|]*(?:\/etc|\/usr\/bin|\/usr\/local\/bin|\/bin|\/sbin|\/root)/,
  
  // Extract directly to system paths
  /\b(?:tar|unzip|7z)\b[^&;|]*xf[^&;|]*(?:\/etc|\/usr\/bin|\/usr\/local\/bin|\/bin|\/sbin)/,
  
  // cd to system dir then extract
  /cd\s+(?:\/etc|\/usr\/bin|\/usr\/local\/bin|\/bin|\/sbin|\/root)[^&;]*&&[^&;]*(?:tar|unzip|7z)/,
  
  // Extract with absolute path output
  /\bunzip\b[^&;|]*-d\s*(?:\/etc|\/usr\/bin|\/usr\/local\/bin|\/bin|\/sbin)/,
];

/**
 * Missing safety flags in tar operations
 */
const MISSING_SAFETY_FLAGS = [
  // tar without --no-same-owner (symbolic link attack vector)
  {
    pattern: /\btar\s+(?!.*--no-same-owner)[^&;|]*(?:xf|xvf|xzf|xjf)\b/,
    message: 'tar extraction without --no-same-owner flag (vulnerable to symbolic link attacks)',
  },
  
  // tar without --no-same-permissions
  {
    pattern: /\btar\s+(?!.*--no-same-permissions)[^&;|]*(?:xf|xvf|xzf|xjf)\b/,
    message: 'tar extraction without --no-same-permissions flag (may preserve dangerous permissions)',
  },
];

/**
 * Recursive or nested extraction patterns (archive bomb indicators)
 */
const RECURSIVE_EXTRACTION_PATTERNS = [
  // Find and extract pattern (extracting many archives)
  /find\b[^&;|]*\.(zip|tar|gz|tgz|bz2|xz|7z)[^&;|]*\|\s*xargs\s+(?:tar|unzip|7z)/,
  
  // Loop through archives and extract
  /for\b[^;]*in\b[^;]*\.(zip|tar|gz|tgz)[^;]*;\s*do[^;]*(?:tar|unzip|7z)[^;]*;/,
  
  // Extracting archives recursively with wildcards
  /\b(?:tar|unzip|7z)\b[^&;|]*\*\.(?:zip|tar|gz|tgz|bz2|xz|7z)/,
  
  // Extract and extract again (nested)
  /\b(?:tar|unzip|7z)\b[^&;]*&&[^&;]*\b(?:tar|unzip|7z)\b/,
];

/**
 * Large file extraction without checks
 */
const LARGE_FILE_EXTRACTION_PATTERNS = [
  // Piped extraction without any size limits or validation
  /(?:curl|wget)\b[^|]*\|\s*(?:tar|unzip|7z)\b(?!.*--max-size|--limit)/,
  
  // Extract archives without space checks
  /\b(?:tar|unzip|7z)\b[^&;]*(?:xf|extract|x)\b(?!.*df|.*du|.*disk|.*space)/,
];

/**
 * Zip slip vulnerabilities (extraction with programming languages)
 */
const ZIP_SLIP_PATTERNS = [
  // Python zipfile without path validation
  /\bZipFile\b[^;]*\.extractall\(/,
  /\bzipfile\.extract\b(?!.*validatepath|.*sanitize|.*check)/,
  
  // Python tarfile without validation
  /\btarfile\.extractall\b(?!.*filter|.*safe)/,
  /\bTarFile\b[^;]*\.extractall\(/,
  
  // Java zip extraction without validation
  /\bZipInputStream\b[^;]*\.getNextEntry\b(?!.*canonicalPath|.*validate)/,
  /\bnew\s+ZipFile\b[^;]*\.extract\b(?!.*validate|.*sanitize)/,
  
  // Node.js extraction without validation
  /\bunzipper\.Extract\b(?!.*validate|.*filter)/,
  /\bextract-zip\b[^;]*(?!.*validate|.*filter)/,
  /\btar\.x\b(?!.*filter|.*strip)/,
  
  // Ruby zip extraction
  /\bZip::File\.open\b[^;]*\.extract\b(?!.*validate|.*sanitize)/,
  
  // .NET extraction
  /\bZipFile\.ExtractToDirectory\b(?!.*validate|.*sanitize)/,
];

/**
 * Known safe archive operations
 */
const SAFE_ARCHIVE_PATTERNS = [
  // Listing archive contents (read-only)
  /\btar\s+(?:tf|tvf|tzf|tjf|--list)\b/,
  /\bunzip\s+-l\b/,
  /\b7z\s+l\b/,
  
  // Extracting to current directory from local files
  /\btar\s+[^&;|]*(?:xf|xvf)\s+(?!.*https?:\/\/)(?!.*curl|wget)[a-zA-Z0-9_\-./]+\.tar/,
  
  // Extracting with explicit safety flags
  /\btar\s+[^&;|]*--no-same-owner[^&;|]*--no-same-permissions/,
  
  // Creating archives (not extracting)
  /\btar\s+(?:cf|cvf|czf|cjf|--create)\b/,
  /\bzip\s+-r\b/,
  /\b7z\s+a\b/,
  
  // Validation before extraction
  /\b(?:tar|unzip|7z)\b[^;]*&&\s*grep\b/,
  /\b(?:tar|unzip)\b[^;]*\|\s*grep\s+-v\s+\.\./,
  
  // Package managers (safe)
  /\b(?:apt|yum|dnf|pacman|brew|npm|pip|cargo)\b[^&;|]*install/,
];

/**
 * Sensitive file patterns that shouldn't be in archives
 */
const SENSITIVE_FILE_IN_ARCHIVE = [
  /\b(?:tar|unzip|7z)\b[^&;|]*(?:passwd|shadow|id_rsa|id_dsa|\.pem|\.key|\.env|credentials|secret)/,
];

/**
 * Check if the command is a safe archive operation
 */
function isSafeArchiveOperation(command: string): boolean {
  return SAFE_ARCHIVE_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check if command contains path traversal patterns
 */
function hasPathTraversal(command: string): boolean {
  return PATH_TRAVERSAL_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check if extracting to dangerous locations
 */
function extractsToDangerousLocation(command: string): boolean {
  return DANGEROUS_EXTRACTION_LOCATIONS.some((pattern) => pattern.test(command));
}

/**
 * Check if extraction is from untrusted source
 */
function isUntrustedExtraction(command: string): boolean {
  return UNSAFE_EXTRACTION_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check for missing critical safety flags
 */
function hasMissingSafetyFlags(command: string): { missing: boolean; message: string } {
  // Only check for tar extraction commands
  if (!/\btar\s+[^&;|]*(?:xf|xvf|xzf|xjf|extract)\b/.test(command)) {
    return { missing: false, message: '' };
  }
  
  // Check if it's a safe operation (local file, trusted source)
  if (isSafeArchiveOperation(command)) {
    return { missing: false, message: '' };
  }
  
  // Check for missing --no-same-owner (most critical)
  if (!/--no-same-owner/.test(command)) {
    return {
      missing: true,
      message: 'tar extraction without --no-same-owner flag (vulnerable to symbolic link attacks)',
    };
  }
  
  return { missing: false, message: '' };
}

/**
 * Check for recursive extraction patterns
 */
function hasRecursiveExtraction(command: string): boolean {
  return RECURSIVE_EXTRACTION_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check for large file extraction without validation
 */
function hasLargeFileExtraction(command: string): boolean {
  return LARGE_FILE_EXTRACTION_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check for zip slip vulnerability patterns
 */
function hasZipSlipVulnerability(command: string): boolean {
  return ZIP_SLIP_PATTERNS.some((pattern) => pattern.test(command));
}

/**
 * Check for sensitive files in archive context
 */
function hasSensitiveFileInArchive(command: string): boolean {
  return SENSITIVE_FILE_IN_ARCHIVE.some((pattern) => pattern.test(command));
}

/**
 * Detect archive bomb and path traversal attacks
 */
export function detectArchiveBomb(
  toolUseData: ToolUseData,
  config?: ArchiveBombConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  // Skip if this is a safe archive operation
  if (isSafeArchiveOperation(toolInput)) {
    return Promise.resolve(null);
  }

  // Check for path traversal (HIGH PRIORITY)
  if (hasPathTraversal(toolInput)) {
    return Promise.resolve({
      severity: 'high',
      message:
        'Dangerous pattern: path traversal detected in archive operation - could overwrite system files or access sensitive directories',
      detector: 'archive-bomb',
    });
  }

  // Check for extraction to dangerous/system locations
  if (extractsToDangerousLocation(toolInput)) {
    return Promise.resolve({
      severity: 'high',
      message:
        'Dangerous pattern: extracting archive to sensitive system directory (/etc, /usr/bin, /bin) - could compromise system integrity',
      detector: 'archive-bomb',
    });
  }

  // Check for untrusted archive extraction (piped from curl/wget)
  if (isUntrustedExtraction(toolInput)) {
    return Promise.resolve({
      severity,
      message:
        'Dangerous pattern: extracting archive from untrusted source without validation - could be archive bomb or contain malicious files',
      detector: 'archive-bomb',
    });
  }

  // Check for recursive extraction patterns (archive bomb indicator)
  if (hasRecursiveExtraction(toolInput)) {
    return Promise.resolve({
      severity,
      message:
        'Dangerous pattern: recursive archive extraction detected - possible archive bomb that could fill disk space',
      detector: 'archive-bomb',
    });
  }

  // Check for zip slip vulnerability in code
  if (hasZipSlipVulnerability(toolInput)) {
    return Promise.resolve({
      severity: 'high',
      message:
        'Dangerous pattern: zip slip vulnerability - extracting archives without path validation could allow arbitrary file writes',
      detector: 'archive-bomb',
    });
  }

  // Check for missing safety flags (medium severity)
  const safetyCheck = hasMissingSafetyFlags(toolInput);
  if (safetyCheck.missing) {
    return Promise.resolve({
      severity: 'medium',
      message: `Warning: ${safetyCheck.message}`,
      detector: 'archive-bomb',
    });
  }

  // Check for large file extraction without checks
  if (hasLargeFileExtraction(toolInput)) {
    return Promise.resolve({
      severity: 'medium',
      message:
        'Warning: extracting large archive without size checks - could fill disk space if malicious',
      detector: 'archive-bomb',
    });
  }

  // Check for sensitive files in archive context
  if (hasSensitiveFileInArchive(toolInput)) {
    return Promise.resolve({
      severity: 'medium',
      message:
        'Warning: archive operation involving sensitive files (credentials, keys) - ensure proper handling',
      detector: 'archive-bomb',
    });
  }

  return Promise.resolve(null);
}
