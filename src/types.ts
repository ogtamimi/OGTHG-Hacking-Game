
export enum ChallengeCategory {
  WEB = 'Web Security',
  SQL = 'SQL Injection',
  XSS = 'Cross-Site Scripting',
  AUTH = 'Authentication',
  INJECTION = 'Injection',
  LOGIC = 'Business Logic'
}

export enum Difficulty {
  EASY = 'Easy',
  MEDIUM = 'Medium',
  HARD = 'Hard'
}

export interface Challenge {
  id: string;
  title: string;
  category: ChallengeCategory;
  difficulty: Difficulty;
  points: number;
  description: string;
  hint: string;
  solutionSteps: string[];
  simulatorType: 'terminal' | 'browser';
  targetUrl?: string;
  correctPayload?: string | string[];
  flag: string;
}

export interface UserProfile {
  username: string;
  nickname: string;
  email: string;
  age: number;
  profilePic: string;
  score: number;
  level: number;
  completedChallenges: string[];
  joinDate: string;
  bio?: string;
}

export interface Settings {
  darkMode: boolean;
  notifications: boolean;
  privacyMode: boolean;
}
