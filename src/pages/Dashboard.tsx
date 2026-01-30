
import React, { useEffect, useState } from 'react';
import { User as UserIcon, Trophy, Star, ChevronRight, CheckCircle2, Zap } from 'lucide-react';
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer } from 'recharts';
import { Link } from 'react-router-dom';
import { INITIAL_CHALLENGES } from '../constants';
import { getUser } from '../store';
import { UserProfile } from '../types';
import { motion } from 'framer-motion';

const Dashboard: React.FC = () => {
  const [user, setUser] = useState<UserProfile>(getUser());

  const progressPercentage = (user.completedChallenges.length / INITIAL_CHALLENGES.length) * 100;

  // Generate real activity based on completed challenges (simplified simulation)
  const activityData = [
    { name: 'Mon', solved: 0 },
    { name: 'Tue', solved: 0 },
    { name: 'Wed', solved: 0 },
    { name: 'Thu', solved: 0 },
    { name: 'Fri', solved: 0 },
    { name: 'Sat', solved: 0 },
    { name: 'Sun', solved: user.completedChallenges.length },
  ];

  return (
    <div className="p-8 space-y-8 animate-in fade-in duration-500">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Welcome, Operative {user.nickname}</h1>
          <p className="text-slate-400">System status: <span className="text-violet-400 font-mono">ENCRYPTED</span> | Total Progress: <span className="text-violet-400 font-bold">{user.completedChallenges.length} Solves</span></p>
        </div>
        <div className="flex space-x-4">
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center space-x-4 shadow-xl">
            <div className="p-2 bg-violet-500/10 rounded-lg">
              <Trophy className="text-violet-400" size={20} />
            </div>
            <div>
              <div className="text-xs text-slate-500 uppercase font-bold tracking-widest">Mastery Level</div>
              <div className="text-xl font-bold text-white">{user.level}</div>
            </div>
          </div>
          <div className="bg-slate-900 border border-slate-800 p-4 rounded-xl flex items-center space-x-4 shadow-xl">
            <div className="p-2 bg-blue-500/10 rounded-lg">
              <Star className="text-blue-400" size={20} />
            </div>
            <div>
              <div className="text-xs text-slate-500 uppercase font-bold tracking-widest">OGT Points</div>
              <div className="text-xl font-bold text-white">{user.score}</div>
            </div>
          </div>
        </div>
      </div>

      <div className="grid lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 space-y-8">
          <motion.div initial={{ opacity: 0, y: 10 }} animate={{ opacity: 1, y: 0 }} className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <h3 className="text-lg font-bold mb-6 flex items-center">
              <Zap className="mr-2 text-violet-400" size={18} /> Operative Activity
            </h3>
            <div className="h-64 w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={activityData}>
                  <CartesianGrid strokeDasharray="3 3" vertical={false} stroke="#1e293b" />
                  <XAxis dataKey="name" axisLine={false} tickLine={false} tick={{fill: '#64748b', fontSize: 12}} />
                  <YAxis axisLine={false} tickLine={false} tick={{fill: '#64748b', fontSize: 12}} />
                  <Tooltip
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#8b5cf6' }}
                  />
                  <Bar dataKey="solved" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </motion.div>

          <div className="space-y-4">
            <div className="flex justify-between items-center">
              <h3 className="text-xl font-bold">Unsolved Missions</h3>
              <Link to="/challenges" className="text-violet-400 text-sm hover:underline flex items-center">
                Explore Vault <ChevronRight size={16} />
              </Link>
            </div>
            <div className="grid sm:grid-cols-2 gap-4">
              {INITIAL_CHALLENGES.filter(c => !user.completedChallenges.includes(c.id)).slice(0, 4).map(challenge => (
                <Link
                  key={challenge.id}
                  to={`/challenge/${challenge.id}`}
                  className="bg-slate-900 border border-slate-800 p-5 rounded-xl hover:border-violet-500/50 transition-all group shadow-sm hover:shadow-violet-500/5"
                >
                  <div className="flex justify-between items-start mb-3">
                    <span className="px-2 py-1 bg-slate-800 rounded text-[10px] font-bold text-slate-400 uppercase tracking-widest">{challenge.category}</span>
                    <span className="text-violet-400 font-mono text-sm">{challenge.points} PTS</span>
                  </div>
                  <h4 className="font-bold text-white mb-2 group-hover:text-violet-400 transition-colors">{challenge.title}</h4>
                  <p className="text-slate-500 text-sm line-clamp-2 mb-4">{challenge.description}</p>
                </Link>
              ))}
            </div>
          </div>
        </div>

        <div className="space-y-8">
          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6 shadow-xl">
            <h3 className="font-bold mb-4">Progression Status</h3>
            <div className="relative pt-1">
              <div className="flex mb-2 items-center justify-between">
                <div>
                  <span className="text-xs font-semibold inline-block py-1 px-2 uppercase rounded-full text-violet-400 bg-violet-500/10 border border-violet-500/20">
                    Tier {user.level}
                  </span>
                </div>
                <div className="text-right">
                  <span className="text-xs font-semibold inline-block text-violet-400">
                    {Math.round(progressPercentage)}%
                  </span>
                </div>
              </div>
              <div className="overflow-hidden h-2 mb-4 text-xs flex rounded bg-slate-800">
                <div style={{ width: `${progressPercentage}%` }} className="shadow-none flex flex-col text-center whitespace-nowrap text-white justify-center bg-violet-500"></div>
              </div>
            </div>
            <div className="space-y-3 mt-6">
               <div className="text-xs text-slate-500 uppercase font-bold tracking-widest">Skills Analysis</div>
               {[
                 { label: 'Web Exploitation', progress: Math.min(100, (user.completedChallenges.length * 15)) },
                 { label: 'Logical Injection', progress: Math.min(100, (user.completedChallenges.length * 10)) },
               ].map(cat => (
                 <div key={cat.label} className="space-y-1">
                   <div className="flex justify-between text-xs">
                     <span className="text-slate-400">{cat.label}</span>
                     <span className="text-slate-500">{cat.progress}%</span>
                   </div>
                   <div className="h-1 bg-slate-800 rounded">
                     <div className="h-full bg-violet-500/50 rounded transition-all duration-1000" style={{ width: `${cat.progress}%` }} />
                   </div>
                 </div>
               ))}
            </div>
          </div>

          <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
            <h3 className="font-bold mb-4">Achievements</h3>
            <div className="grid grid-cols-3 gap-3">
              {[1, 2, 3, 4, 5, 6].map(i => {
                const isUnlocked = user.completedChallenges.length >= i;
                return (
                  <div key={i} className={`aspect-square rounded-xl flex items-center justify-center transition-all ${isUnlocked ? 'bg-violet-500/10 border-violet-500/30 border shadow-[0_0_10px_rgba(139,92,246,0.1)]' : 'bg-slate-800/50 opacity-30 grayscale'}`}>
                    {isUnlocked ? <CheckCircle2 className="text-violet-400" size={24} /> : <UserIcon className="text-slate-700" size={20} />}
                  </div>
                );
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default Dashboard;
