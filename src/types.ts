// Tool use data structure from Claude Code
export interface ToolUseData {
  command?: string;
  [key: string]: unknown;
}

export interface Detection {
  severity: 'high' | 'medium' | 'low';
  message: string;
  detector: string;
}

export type Detector = (toolUseData: ToolUseData) => Promise<Detection | null>;
