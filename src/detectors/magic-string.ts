import { Detection } from './index';

export async function detectMagicString(toolUseData: any): Promise<Detection | null> {
  const toolInput = JSON.stringify(toolUseData);

  if (toolInput.includes('test_me')) {
    return {
      severity: 'high',
      message: 'Magic string "test_me" detected in tool input',
      detector: 'magic-string'
    };
  }

  return null;
}
