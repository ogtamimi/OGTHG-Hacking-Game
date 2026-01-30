
import { UserProfile, Settings } from './types';

const STORAGE_KEY = 'ogthg_user_data';
const SETTINGS_KEY = 'ogthg_settings';

const DEFAULT_USER: UserProfile = {
  username: '',
  nickname: '',
  email: '',
  age: 0,
  profilePic: 'https://api.dicebear.com/7.x/avataaars/svg?seed=Ghost',
  score: 0,
  level: 1,
  completedChallenges: [],
  joinDate: new Date().toISOString(),
  bio: 'Learning the ways of the OGTHG.'
};

const DEFAULT_SETTINGS: Settings = {
  darkMode: true,
  notifications: true,
  privacyMode: false
};

export const getUser = (): UserProfile => {
  const data = localStorage.getItem(STORAGE_KEY);
  return data ? JSON.parse(data) : DEFAULT_USER;
};

export const isUserInitialized = (): boolean => {
  const user = getUser();
  return !!user.nickname;
};

export const saveUser = (user: UserProfile) => {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(user));
};

export const initializeUser = (name: string, age: number) => {
  const newUser = { 
    ...DEFAULT_USER, 
    nickname: name, 
    username: name.toLowerCase().replace(/\s+/g, '_'),
    age: age,
    joinDate: new Date().toISOString()
  };
  saveUser(newUser);
  return newUser;
};

export const getSettings = (): Settings => {
  const data = localStorage.getItem(SETTINGS_KEY);
  return data ? JSON.parse(data) : DEFAULT_SETTINGS;
};

export const saveSettings = (settings: Settings) => {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify(settings));
};

export const completeChallenge = (challengeId: string, points: number) => {
  const user = getUser();
  if (!user.completedChallenges.includes(challengeId)) {
    user.completedChallenges.push(challengeId);
    user.score += points;
    user.level = Math.floor(user.score / 500) + 1;
    saveUser(user);
    return true;
  }
  return false;
};
