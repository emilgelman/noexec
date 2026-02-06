import type { Detection, ToolUseData } from '../types';

export function detectMagicString(toolUseData: ToolUseData): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  if (toolInput.includes('test_me')) {
    return Promise.resolve({
      severity: 'high',
      message: 'Magic string "test_me" detected in tool input',
      detector: 'magic-string',
    });
  }

  return Promise.resolve(null);
}
