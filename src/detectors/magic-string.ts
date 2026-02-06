import type { Detection, ToolUseData } from '../types';
import type { MagicStringConfig } from '../config/types';

export function detectMagicString(
  toolUseData: ToolUseData,
  config?: MagicStringConfig
): Promise<Detection | null> {
  if (config && !config.enabled) {
    return Promise.resolve(null);
  }

  const severity = config?.severity ?? 'high';
  const toolInput = JSON.stringify(toolUseData);

  if (toolInput.includes('test_me')) {
    return Promise.resolve({
      severity,
      message: 'Magic string "test_me" detected in tool input',
      detector: 'magic-string',
    });
  }

  return Promise.resolve(null);
}
