
import React, { useState } from 'react';
import { Settings as SettingsIcon, Bell, Eye, EyeOff, Monitor, Shield, Smartphone, Globe, Trash2 } from 'lucide-react';
import { getSettings, saveSettings } from '../store';
import { Settings as SettingsType } from '../types';

const Settings: React.FC = () => {
  const [settings, setSettings] = useState<SettingsType>(getSettings());

  const toggle = (key: keyof SettingsType) => {
    const updated = { ...settings, [key]: !settings[key] };
    setSettings(updated);
    saveSettings(updated);
  };

  return (
    <div className="p-8 max-w-3xl mx-auto space-y-8">
      <h1 className="text-3xl font-bold text-white flex items-center">
        <SettingsIcon className="mr-3 text-violet-400" size={32} /> System Configuration
      </h1>

      <div className="space-y-6">
        <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
          <h3 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-6">User Interface</h3>
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="p-2 bg-slate-800 rounded-lg"><Monitor size={20} className="text-slate-400" /></div>
                <div>
                  <div className="font-bold text-white">Shadow Mode</div>
                  <div className="text-xs text-slate-500">Always active for OGTHG operatives.</div>
                </div>
              </div>
              <div className="w-12 h-6 bg-violet-600 rounded-full flex items-center justify-end px-1 cursor-not-allowed opacity-50">
                 <div className="w-4 h-4 bg-white rounded-full shadow-lg" />
              </div>
            </div>

            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="p-2 bg-slate-800 rounded-lg"><Bell size={20} className="text-slate-400" /></div>
                <div>
                  <div className="font-bold text-white">Mission Alerts</div>
                  <div className="text-xs text-slate-500">Push notifications for new target releases.</div>
                </div>
              </div>
              <button 
                onClick={() => toggle('notifications')}
                className={`w-12 h-6 rounded-full flex items-center transition-all ${settings.notifications ? 'bg-violet-600 justify-end px-1' : 'bg-slate-700 justify-start px-1'}`}
              >
                 <div className="w-4 h-4 bg-white rounded-full shadow-lg" />
              </button>
            </div>
          </div>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-2xl">
          <h3 className="text-sm font-bold text-slate-500 uppercase tracking-widest mb-6">Security & Privacy</h3>
          <div className="space-y-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div className="p-2 bg-slate-800 rounded-lg"><Shield size={20} className="text-slate-400" /></div>
                <div>
                  <div className="font-bold text-white">Anonymize Profile</div>
                  <div className="text-xs text-slate-500">Hide your rank and solves from the leaderboard.</div>
                </div>
              </div>
              <button 
                onClick={() => toggle('privacyMode')}
                className={`w-12 h-6 rounded-full flex items-center transition-all ${settings.privacyMode ? 'bg-violet-600 justify-end px-1' : 'bg-slate-700 justify-start px-1'}`}
              >
                 <div className="w-4 h-4 bg-white rounded-full shadow-lg" />
              </button>
            </div>
          </div>
        </div>

        <div className="bg-red-500/5 border border-red-500/20 rounded-3xl p-8 shadow-2xl">
          <h3 className="text-sm font-bold text-red-400 uppercase tracking-widest mb-6">Destructive Actions</h3>
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <div className="p-2 bg-red-500/10 rounded-lg"><Trash2 size={20} className="text-red-400" /></div>
              <div>
                <div className="font-bold text-white">Wipe All Progress</div>
                <div className="text-xs text-slate-500">Permanently delete mission logs and OGT points.</div>
              </div>
            </div>
            <button className="px-4 py-2 bg-red-600/10 text-red-500 border border-red-500/20 rounded-xl hover:bg-red-600 hover:text-white transition-all font-bold text-sm">
              Factory Reset
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Settings;
