
import React, { useState, useEffect } from 'react';
import { Link } from 'react-router-dom';
import { Search, Shield, Lock, Unlock, ArrowUpRight, CheckCircle } from 'lucide-react';
import { INITIAL_CHALLENGES } from '../constants';
import { getUser } from '../store';

const ChallengesList: React.FC = () => {
  const [filter, setFilter] = useState('All');
  const [search, setSearch] = useState('');
  const [user, setUser] = useState(getUser());

  const categories = ['All', 'Web Security', 'SQL Injection', 'Cross-Site Scripting', 'Authentication', 'Injection', 'Business Logic'];

  const filtered = INITIAL_CHALLENGES.filter(c => {
    const matchesFilter = filter === 'All' || c.category === filter;
    const matchesSearch = c.title.toLowerCase().includes(search.toLowerCase()) ||
                          c.description.toLowerCase().includes(search.toLowerCase());
    return matchesFilter && matchesSearch;
  });

  return (
    <div className="p-8 space-y-8">
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Missions Hub</h1>
          <p className="text-slate-400">Select a target to begin exploitation.</p>
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 text-slate-500" size={18} />
          <input
            className="bg-slate-900 border border-slate-800 rounded-xl py-2 pl-10 pr-4 text-white outline-none focus:border-violet-500 transition-all w-full sm:w-64"
            placeholder="Search database..."
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
      </div>

      <div className="flex flex-wrap gap-2">
        {categories.map(cat => (
          <button
            key={cat}
            onClick={() => setFilter(cat)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-all ${
              filter === cat
                ? 'bg-violet-500 text-white font-bold shadow-[0_0_15px_rgba(139,92,246,0.3)]'
                : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white'
            }`}
          >
            {cat}
          </button>
        ))}
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-6">
        {filtered.map((challenge) => {
          const isCompleted = user.completedChallenges.includes(challenge.id);
          return (
            <Link
              key={challenge.id}
              to={`/challenge/${challenge.id}`}
              className={`group p-6 rounded-2xl bg-slate-900 border transition-all hover:-translate-y-1 relative overflow-hidden ${
                isCompleted ? 'border-emerald-500/40 bg-emerald-500/[0.02]' : 'border-slate-800 hover:border-violet-500/50'
              }`}
            >
              {isCompleted && (
                <div className="absolute top-0 right-0 p-3 bg-emerald-500/10 rounded-bl-xl border-l border-b border-emerald-500/20">
                  <CheckCircle className="text-emerald-400 animate-pulse" size={16} />
                </div>
              )}

              <div className="flex justify-between items-start mb-4">
                <span className="text-[10px] font-bold text-slate-500 uppercase tracking-widest">{challenge.category}</span>
                <span className="text-violet-400 font-mono font-bold">{challenge.points} PTS</span>
              </div>

              <h3 className={`text-xl font-bold mb-3 flex items-center transition-colors ${isCompleted ? 'text-emerald-400' : 'text-white group-hover:text-violet-400'}`}>
                {challenge.title}
                <ArrowUpRight size={16} className="ml-2 opacity-0 group-hover:opacity-100 transition-opacity" />
              </h3>

              <p className="text-slate-500 text-sm line-clamp-2 mb-6">{challenge.description}</p>

              <div className="flex items-center justify-between mt-auto pt-4 border-t border-slate-800/50">
                <div className="flex items-center space-x-2">
                   <div className={`w-2 h-2 rounded-full ${
                    challenge.difficulty === 'Easy' ? 'bg-green-500 shadow-[0_0_8px_rgba(34,197,94,0.5)]' :
                    challenge.difficulty === 'Medium' ? 'bg-yellow-500 shadow-[0_0_8px_rgba(234,179,8,0.5)]' : 'bg-red-500 shadow-[0_0_8px_rgba(239,68,68,0.5)]'
                  }`} />
                  <span className="text-xs text-slate-400 font-bold uppercase tracking-wider">{challenge.difficulty}</span>
                </div>
                {isCompleted ? (
                   <span className="text-xs text-emerald-400 font-bold flex items-center">
                     <Unlock size={12} className="mr-1" /> RESOLVED
                   </span>
                ) : (
                  <span className="text-xs text-slate-500 font-bold flex items-center">
                    <Lock size={12} className="mr-1" /> SECURED
                  </span>
                )}
              </div>
            </Link>
          );
        })}
      </div>
    </div>
  );
};

export default ChallengesList;
