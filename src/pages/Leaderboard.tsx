
import React, { useMemo } from 'react';
import { Trophy, Medal, Star, ChevronUp, User as UserIcon } from 'lucide-react';
import { getUser } from '../store';

const STATIC_COMPETITORS = [
  { name: 'RootHunter', score: 4500, solves: 18, avatar: 'RH' },
  { name: 'Sudo_Cry', score: 3250, solves: 14, avatar: 'SC' },
  { name: 'CyberWiz', score: 2800, solves: 12, avatar: 'CW' },
  { name: 'ZeroDay', score: 2200, solves: 9, avatar: 'ZD' },
  { name: 'BinaryBane', score: 1500, solves: 7, avatar: 'BB' },
  { name: 'HackSmith', score: 800, solves: 4, avatar: 'HS' },
];

const Leaderboard: React.FC = () => {
  const user = getUser();
  
  const leaderboard = useMemo(() => {
    const list = [
      ...STATIC_COMPETITORS,
      { 
        name: user.nickname, 
        score: user.score, 
        solves: user.completedChallenges.length, 
        avatar: user.nickname.substring(0, 2).toUpperCase(),
        isMe: true 
      }
    ];
    return list.sort((a, b) => b.score - a.score).map((p, i) => ({ ...p, rank: i + 1 }));
  }, [user]);

  return (
    <div className="p-8 max-w-5xl mx-auto space-y-8 animate-in fade-in zoom-in duration-300">
      <div className="flex justify-between items-end">
        <div>
          <h1 className="text-3xl font-bold text-white mb-2">Hall of Fame</h1>
          <p className="text-slate-400">Current operative standings in the OGTHG network.</p>
        </div>
        <div className="text-right">
          <div className="text-xs text-slate-500 font-bold uppercase tracking-widest">Your Ranking</div>
          <div className="text-2xl font-bold text-violet-400">#{leaderboard.find(p => (p as any).isMe)?.rank || 'N/A'}</div>
        </div>
      </div>

      <div className="grid md:grid-cols-3 gap-6">
        {leaderboard.slice(0, 3).map((player, i) => (
          <div
            key={player.name}
            className={`p-8 rounded-2xl relative overflow-hidden border shadow-2xl transition-all duration-500 hover:scale-105 ${
              i === 0 ? 'bg-violet-500/10 border-violet-500/30' : 'bg-slate-900 border-slate-800'
            }`}
          >
            <div className="absolute -top-4 -right-4 opacity-5">
              <Trophy size={140} className={i === 0 ? 'text-violet-400' : 'text-slate-400'} />
            </div>
            <div className="relative z-10 flex flex-col items-center">
              <div className={`w-20 h-20 rounded-2xl flex items-center justify-center text-2xl font-bold mb-4 border-2 transition-transform duration-700 hover:rotate-6 ${
                i === 0 ? 'border-violet-500 bg-violet-500/20 text-violet-400 shadow-[0_0_20px_rgba(139,92,246,0.3)]' :
                i === 1 ? 'border-blue-500 bg-blue-500/20 text-blue-400' :
                'border-slate-600 bg-slate-800 text-slate-400'
              }`}>
                {player.avatar}
              </div>
              <div className="text-center">
                <div className="flex items-center justify-center space-x-2 mb-1">
                  <Medal size={16} className={i === 0 ? 'text-yellow-500' : i === 1 ? 'text-slate-300' : 'text-amber-600'} />
                  <h3 className="font-bold text-xl">{(player as any).isMe ? player.name + ' (You)' : player.name}</h3>
                </div>
                <div className="text-sm text-slate-500 uppercase font-bold tracking-widest mb-4">Rank #{player.rank}</div>
                <div className="text-3xl font-mono font-bold text-white mb-1">{player.score.toLocaleString()}</div>
                <div className="text-[10px] text-slate-600 font-bold uppercase">System Points</div>
              </div>
            </div>
          </div>
        ))}
      </div>

      <div className="bg-slate-900 border border-slate-800 rounded-2xl overflow-hidden shadow-2xl">
        <div className="grid grid-cols-6 p-4 bg-slate-800/50 text-[10px] font-bold uppercase tracking-widest text-slate-500 border-b border-slate-800">
          <div className="col-span-1">Rank</div>
          <div className="col-span-3">Operative</div>
          <div className="col-span-1 text-right">Solved</div>
          <div className="col-span-1 text-right">Points</div>
        </div>
        <div className="divide-y divide-slate-800">
          {leaderboard.map((player) => (
            <div key={player.name} className={`grid grid-cols-6 p-5 items-center hover:bg-slate-800/30 transition-all ${(player as any).isMe ? 'bg-violet-500/5 border-l-4 border-violet-500' : ''}`}>
              <div className="col-span-1 font-mono text-slate-500">#{player.rank}</div>
              <div className="col-span-3 flex items-center space-x-3">
                <div className="w-8 h-8 rounded bg-slate-800 flex items-center justify-center text-xs font-bold text-slate-400">{player.avatar}</div>
                <span className={`font-bold ${(player as any).isMe ? 'text-violet-400' : 'text-white'}`}>{player.name}</span>
                {player.rank < 4 && <Star size={12} className="text-yellow-500 fill-yellow-500" />}
              </div>
              <div className="col-span-1 text-right text-slate-400 font-mono">{player.solves}</div>
              <div className="col-span-1 text-right font-mono font-bold text-white flex items-center justify-end">
                {player.score.toLocaleString()}
                <ChevronUp size={12} className="ml-1 text-violet-500" />
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
};

export default Leaderboard;
