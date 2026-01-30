
import React from 'react';
import { LayoutDashboard, Trophy, Terminal, User, Settings, LogOut, ShieldCheck, GraduationCap } from 'lucide-react';
import { Link, useLocation } from 'react-router-dom';

interface SidebarProps {
  onLogout: () => void;
}

const Sidebar: React.FC<SidebarProps> = ({ onLogout }) => {
  const location = useLocation();

  const menuItems = [
    { name: 'Dashboard', icon: LayoutDashboard, path: '/dashboard' },
    { name: 'Academy', icon: GraduationCap, path: '/academy' },
    { name: 'Challenges', icon: Terminal, path: '/challenges' },
    { name: 'Leaderboard', icon: Trophy, path: '/leaderboard' },
    { name: 'Profile', icon: User, path: '/profile' },
    { name: 'Settings', icon: Settings, path: '/settings' },
  ];

  return (
    <div className="w-64 h-screen bg-slate-900 border-r border-slate-800 flex flex-col sticky top-0 z-50">
      <div className="p-8 flex items-center space-x-3">
        <div className="w-10 h-10 bg-violet-600 rounded-xl flex items-center justify-center shadow-lg shadow-violet-600/20 transform rotate-3">
          <ShieldCheck className="text-white w-6 h-6" />
        </div>
        <span className="text-2xl font-black tracking-tighter text-white uppercase italic">OGTHG</span>
      </div>

      <nav className="flex-1 px-4 py-8 space-y-2">
        {menuItems.map((item) => {
          const Icon = item.icon;
          const isActive = location.pathname === item.path;
          return (
            <Link
              key={item.name}
              to={item.path}
              className={`flex items-center space-x-4 px-5 py-4 rounded-2xl transition-all duration-300 group ${
                isActive
                  ? 'bg-violet-600 text-white shadow-xl shadow-violet-600/20 italic font-black uppercase text-xs tracking-widest'
                  : 'text-slate-500 hover:bg-slate-800 hover:text-white font-bold uppercase text-[10px] tracking-widest'
              }`}
            >
              <Icon size={18} className={`${isActive ? 'scale-110' : 'group-hover:text-violet-400'} transition-all`} />
              <span>{item.name}</span>
            </Link>
          );
        })}
      </nav>

      <div className="p-6 border-t border-slate-800">
        <button
          onClick={onLogout}
          className="flex items-center space-x-4 px-5 py-4 w-full rounded-2xl text-slate-500 hover:bg-red-500/10 hover:text-red-400 transition-all font-black uppercase text-[10px] tracking-widest italic"
        >
          <LogOut size={18} />
          <span>Terminate</span>
        </button>
      </div>
    </div>
  );
};

export default Sidebar;
