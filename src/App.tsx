
import React, { useState, useEffect } from 'react';
import { HashRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { User, Calendar, LogIn, AlertCircle, Loader2, Sparkles, ChevronRight } from 'lucide-react';
import LandingPage from './pages/LandingPage';
import Dashboard from './pages/Dashboard';
import Academy from './pages/Academy';
import ChallengePage from './pages/ChallengePage';
import ChallengesList from './pages/ChallengesList';
import Leaderboard from './pages/Leaderboard';
import Profile from './pages/Profile';
import Settings from './pages/Settings';
import Sidebar from './components/Sidebar';
import { isUserInitialized, initializeUser } from './store';
import { motion, AnimatePresence } from 'framer-motion';

const App: React.FC = () => {
  const [isAuthenticated, setIsAuthenticated] = useState(isUserInitialized());
  const [isLoading, setIsLoading] = useState(false);
  const [error, setError] = useState('');
  const [name, setName] = useState('');
  const [age, setAge] = useState<string>('');

  const handleInitialize = async (e: React.FormEvent) => {
    e.preventDefault();
    setIsLoading(true);
    setError('');
    
    // Aesthetic delay for initialization
    await new Promise(resolve => setTimeout(resolve, 1200));
    
    if (!name.trim() || name.length < 3) {
      setError('Please provide a valid operative name (min 3 chars).');
      setIsLoading(false);
      return;
    }

    const ageNum = parseInt(age);
    if (isNaN(ageNum) || ageNum < 5 || ageNum > 100) {
      setError('Please provide a valid age (5-100).');
      setIsLoading(false);
      return;
    }
    
    initializeUser(name, ageNum);
    setIsAuthenticated(true);
    setIsLoading(false);
  };

  const logout = () => {
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return (
      <Router>
        <Routes>
          <Route path="/" element={<LandingPage />} />
          <Route path="/initialize" element={
            <div className="min-h-screen bg-slate-950 flex items-center justify-center p-4 selection:bg-violet-500 selection:text-white relative overflow-hidden">
              <div className="absolute top-0 left-0 w-full h-full pointer-events-none opacity-20">
                <div className="absolute top-[-10%] left-[-10%] w-[50%] h-[50%] bg-violet-600 rounded-full blur-[150px]" />
                <div className="absolute bottom-[-10%] right-[-10%] w-[50%] h-[50%] bg-blue-600 rounded-full blur-[150px]" />
              </div>

              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }}
                animate={{ opacity: 1, scale: 1 }}
                className="w-full max-w-md space-y-8 bg-slate-900 p-10 rounded-[3rem] border border-slate-800 shadow-[0_30px_60px_rgba(0,0,0,0.6)] relative z-10"
              >
                <div className="text-center">
                  <div className="w-20 h-20 bg-violet-600 rounded-3xl mx-auto flex items-center justify-center shadow-2xl shadow-violet-600/30 mb-8 transform -rotate-6">
                    <Sparkles className="text-white w-10 h-10" />
                  </div>
                  <h2 className="text-4xl font-black text-white tracking-tighter uppercase italic">Operative Entry</h2>
                  <p className="mt-2 text-sm text-slate-500 font-bold uppercase tracking-widest">Register your signal with OGTHG</p>
                </div>

                <form className="space-y-6" onSubmit={handleInitialize}>
                  <div className="space-y-4">
                    <div className="relative group">
                      <User className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-violet-500 transition-colors" size={18} />
                      <input 
                        type="text"
                        required
                        value={name}
                        onChange={(e) => setName(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-2xl p-4 pl-12 text-white focus:border-violet-500 outline-none transition-all placeholder:text-slate-800 font-medium" 
                        placeholder="Operative Name (e.g. Shadow)" 
                      />
                    </div>
                    <div className="relative group">
                      <Calendar className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-600 group-focus-within:text-violet-500 transition-colors" size={18} />
                      <input 
                        type="number"
                        required
                        value={age}
                        onChange={(e) => setAge(e.target.value)}
                        className="w-full bg-slate-950 border border-slate-800 rounded-2xl p-4 pl-12 text-white focus:border-violet-500 outline-none transition-all placeholder:text-slate-800 font-medium" 
                        placeholder="Age" 
                      />
                    </div>
                  </div>

                  <AnimatePresence>
                    {error && (
                      <motion.div 
                        initial={{ opacity: 0, height: 0 }}
                        animate={{ opacity: 1, height: 'auto' }}
                        className="flex items-center space-x-2 text-red-500 text-xs font-bold bg-red-500/10 p-3 rounded-xl border border-red-500/20"
                      >
                        <AlertCircle size={14} />
                        <span>{error}</span>
                      </motion.div>
                    )}
                  </AnimatePresence>

                  <button 
                    type="submit" 
                    disabled={isLoading}
                    className="w-full bg-violet-600 text-white font-black py-5 rounded-2xl hover:bg-violet-500 hover:-translate-y-1 active:translate-y-0 transition-all shadow-2xl shadow-violet-600/30 uppercase tracking-[0.2em] italic flex items-center justify-center space-x-2 disabled:opacity-50"
                  >
                    {isLoading ? <Loader2 className="animate-spin" size={20} /> : (
                      <span className="flex items-center">Initialize Signal <ChevronRight size={18} className="ml-2" /></span>
                    )}
                  </button>
                </form>
              </motion.div>
            </div>
          } />
          <Route path="*" element={<Navigate to="/" />} />
        </Routes>
      </Router>
    );
  }

  return (
    <Router>
      <div className="flex min-h-screen bg-slate-950 selection:bg-violet-500 selection:text-white">
        <Sidebar onLogout={logout} />
        <main className="flex-1 overflow-y-auto bg-slate-950">
          <Routes>
            <Route path="/dashboard" element={<Dashboard />} />
            <Route path="/academy" element={<Academy />} />
            <Route path="/challenges" element={<ChallengesList />} />
            <Route path="/challenge/:id" element={<ChallengePage />} />
            <Route path="/leaderboard" element={<Leaderboard />} />
            <Route path="/profile" element={<Profile />} />
            <Route path="/settings" element={<Settings />} />
            <Route path="*" element={<Navigate to="/dashboard" />} />
          </Routes>
        </main>
      </div>
    </Router>
  );
};

export default App;
