export interface Detection {
  severity: 'high' | 'medium' | 'low';
  message: string;
  detector: string;
}

export type Detector = (toolUseData: any) => Promise<Detection | null>;
