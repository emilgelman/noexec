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

export interface DetectorConfig {
  enabled: boolean;
  severity: 'high' | 'medium' | 'low';
  [key: string]: unknown;
}

export type Detector<TConfig extends DetectorConfig = DetectorConfig> = (
  toolUseData: ToolUseData,
  config?: TConfig
) => Promise<Detection | null>;
