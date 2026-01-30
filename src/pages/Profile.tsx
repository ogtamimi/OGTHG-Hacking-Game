
import React, { useState } from 'react';
import { User, Shield, Edit3, Save, Camera, Mail, CheckCircle, Hash } from 'lucide-react';
import { getUser, saveUser } from '../store';
import { UserProfile } from '../types';
import { INITIAL_CHALLENGES } from '../constants';
import { motion } from 'framer-motion';

const Profile: React.FC = () => {
  const [user, setUser] = useState<UserProfile>(getUser());
  const [isEditing, setIsEditing] = useState(false);
  const [editedUser, setEditedUser] = useState<UserProfile>(user);

  const handleSave = () => {
    saveUser(editedUser);
    setUser(editedUser);
    setIsEditing(false);
  };

  return (
    <div className="p-8 max-w-4xl mx-auto space-y-8 animate-in slide-in-from-bottom-4 duration-500">
      <div className="flex justify-between items-center">
        <h1 className="text-3xl font-black text-white italic uppercase tracking-tighter">Operative Profile</h1>
        <button
          onClick={() => isEditing ? handleSave() : setIsEditing(true)}
          className={`flex items-center space-x-2 px-6 py-2 rounded-xl font-black uppercase italic tracking-widest transition-all ${
            isEditing ? 'bg-violet-600 text-white hover:bg-violet-500' : 'bg-slate-800 text-slate-300 hover:bg-slate-700'
          }`}
        >
          {isEditing ? <><Save size={18} /> <span>Save Profile</span></> : <><Edit3 size={18} /> <span>Edit Entry</span></>}
        </button>
      </div>

      <div className="grid md:grid-cols-3 gap-8">
        <div className="space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 flex flex-col items-center text-center shadow-2xl">
            <div className="relative mb-6">
              <img src={user.profilePic} alt="Avatar" className="w-32 h-32 rounded-3xl border-4 border-violet-500/20 shadow-xl" />
              {isEditing && (
                <button className="absolute bottom-0 right-0 p-2 bg-violet-600 rounded-lg text-white shadow-lg hover:scale-110 transition-transform">
                  <Camera size={16} />
                </button>
              )}
            </div>
            <h2 className="text-2xl font-black text-white mb-1 italic uppercase tracking-tighter">{user.nickname}</h2>
            <p className="text-slate-500 font-mono text-sm">@{user.username}</p>
            <div className="mt-6 flex flex-col w-full space-y-3">
              <div className="flex items-center justify-between text-[10px] p-3 bg-slate-950 rounded-xl border border-slate-800 font-bold uppercase tracking-widest">
                <span className="text-slate-500">Member Since</span>
                <span className="text-slate-300 font-mono">{new Date(user.joinDate).toLocaleDateString()}</span>
              </div>
              <div className="flex items-center justify-between text-[10px] p-3 bg-slate-950 rounded-xl border border-slate-800 font-bold uppercase tracking-widest">
                <span className="text-slate-500">Tier Status</span>
                <span className="text-violet-400 font-black">ELITE OPERATIVE</span>
              </div>
            </div>
          </div>
          
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-6 space-y-4 shadow-xl">
             <h3 className="text-xs font-black text-slate-500 uppercase tracking-widest flex items-center">
               <Shield size={16} className="mr-2" /> Clearance Level
             </h3>
             <div className="space-y-4">
                <div className="flex justify-between items-center text-sm">
                   <span className="text-slate-500 font-medium">Network Rank</span>
                   <span className="text-white font-black italic">#42</span>
                </div>
                <div className="flex justify-between items-center text-sm">
                   <span className="text-slate-500 font-medium">Missions Cleared</span>
                   <span className="text-white font-black italic">{user.completedChallenges.length}</span>
                </div>
             </div>
          </div>
        </div>

        <div className="md:col-span-2 space-y-6">
          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-xl">
            <h3 className="text-lg font-black mb-6 italic uppercase tracking-tighter">Operative Details</h3>
            <div className="space-y-6">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Nickname</label>
                  {isEditing ? (
                    <input 
                      className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 text-white focus:border-violet-600 outline-none font-medium transition-all"
                      value={editedUser.nickname}
                      onChange={e => setEditedUser({...editedUser, nickname: e.target.value})}
                    />
                  ) : (
                    <p className="p-3 bg-slate-950/50 rounded-xl text-slate-200 border border-slate-800/50 font-medium">{user.nickname}</p>
                  )}
                </div>
                <div className="space-y-2">
                  <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Operative Age</label>
                  {isEditing ? (
                    <div className="relative">
                      <Hash className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-600" size={14} />
                      <input 
                        type="number"
                        className="w-full bg-slate-950 border border-slate-800 rounded-xl p-3 pl-8 text-white focus:border-violet-600 outline-none font-medium transition-all"
                        value={editedUser.age}
                        onChange={e => setEditedUser({...editedUser, age: parseInt(e.target.value) || 0})}
                      />
                    </div>
                  ) : (
                    <p className="p-3 bg-slate-950/50 rounded-xl text-slate-200 border border-slate-800/50 font-medium flex items-center">
                      <Hash size={14} className="mr-2 text-slate-500" /> {user.age} Years Old
                    </p>
                  )}
                </div>
              </div>

              <div className="space-y-2">
                <label className="text-[10px] font-black text-slate-500 uppercase tracking-widest px-2">Encryption Bio</label>
                {isEditing ? (
                  <textarea 
                    className="w-full bg-slate-950 border border-slate-800 rounded-xl p-4 text-white focus:border-violet-600 outline-none min-h-[120px] font-medium transition-all"
                    value={editedUser.bio}
                    onChange={e => setEditedUser({...editedUser, bio: e.target.value})}
                  />
                ) : (
                  <p className="p-4 bg-slate-950/50 rounded-xl text-slate-400 text-sm leading-relaxed border border-slate-800/50 font-medium">
                    {user.bio || "No data encrypted in bio section."}
                  </p>
                )}
              </div>
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-3xl p-8 shadow-xl">
             <h3 className="text-lg font-black mb-6 italic uppercase tracking-tighter">Mission Sequence Log</h3>
             <div className="space-y-4">
                {user.completedChallenges.length === 0 ? (
                  <div className="text-slate-500 text-center py-10 border-2 border-dashed border-slate-800 rounded-3xl">
                    <Shield size={32} className="mx-auto mb-3 opacity-20" />
                    <p className="text-xs font-bold uppercase tracking-widest">No clearance recorded yet.</p>
                  </div>
                ) : (
                  user.completedChallenges.map(id => {
                    const c = INITIAL_CHALLENGES.find(ch => ch.id === id);
                    return (
                      <div key={id} className="flex items-center justify-between p-4 bg-slate-950 rounded-xl border border-slate-800 hover:border-violet-600/20 transition-all group">
                        <div className="flex items-center space-x-4">
                          <div className="p-2 bg-emerald-500/10 rounded-lg group-hover:scale-110 transition-transform"><CheckCircle className="text-emerald-500" size={16} /></div>
                          <div>
                            <div className="font-bold text-sm text-white">{c?.title}</div>
                            <div className="text-[10px] text-slate-500 uppercase font-bold tracking-widest">{c?.category}</div>
                          </div>
                        </div>
                        <span className="text-violet-400 font-mono text-sm font-bold">+{c?.points} XP</span>
                      </div>
                    );
                  })
                )}
             </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Profile;
