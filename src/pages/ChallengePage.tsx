
import React, { useState, useEffect, useMemo } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { 
  Lightbulb, Info, ArrowLeft, Send, CheckCircle, Globe, Sparkles, Shield, 
  Search, Lock, ShoppingCart, User as UserIcon, Code, Eye, Terminal as TerminalIcon,
  AlertTriangle, Settings as SettingsIcon, Database, RefreshCw, Cpu
} from 'lucide-react';
import { INITIAL_CHALLENGES } from '../constants';
import TerminalSimulator from '../components/TerminalSimulator';
import BrowserSimulator from '../components/BrowserSimulator';
import { getAIHint } from '../services/geminiService';
import { completeChallenge, getUser } from '../store';
import { motion, AnimatePresence } from 'framer-motion';

const Loader2 = ({ className, size }: { className?: string, size?: number }) => (
  <RefreshCw className={`${className} animate-spin`} size={size} />
);

const ChallengePage: React.FC = () => {
  const { id } = useParams();
  const navigate = useNavigate();
  const challenge = INITIAL_CHALLENGES.find(c => c.id === id);
  
  const [currentUrl, setCurrentUrl] = useState(challenge?.targetUrl || 'http://target.ogt');
  const [flagInput, setFlagInput] = useState('');
  const [isSolved, setIsSolved] = useState(false);
  const [showHint, setShowHint] = useState(false);
  const [aiHint, setAiHint] = useState('');
  const [loadingHint, setLoadingHint] = useState(false);
  const [error, setError] = useState(false);
  const [viewSource, setViewSource] = useState(false);
  
  // Specific states for interactive components
  const [sqliUser, setSqliUser] = useState('');
  const [sqliPass, setSqliPass] = useState('');
  const [sqliResult, setSqliResult] = useState('');
  const [xssInput, setXssInput] = useState('');
  const [xssAlert, setXssAlert] = useState(false);
  const [cookies, setCookies] = useState({ user_type: 'guest' });
  const [sstiInput, setSstiInput] = useState('');
  const [sstiResult, setSstiResult] = useState('');

  useEffect(() => {
    const user = getUser();
    if (user.completedChallenges.includes(id || '')) {
      setIsSolved(true);
    }
    setCurrentUrl(challenge?.targetUrl || 'http://target.ogt');
    setViewSource(false);
    setXssAlert(false);
    setSstiResult('');
  }, [id, challenge]);

  if (!challenge) return <div className="p-8 text-white">Challenge not found.</div>;

  const handleFlagSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (flagInput.trim() === challenge.flag) {
      completeChallenge(challenge.id, challenge.points);
      setIsSolved(true);
      setError(false);
    } else {
      setError(true);
      setTimeout(() => setError(false), 2000);
    }
  };

  const handleTerminalCommand = (cmd: string) => {
    const payloads = Array.isArray(challenge.correctPayload) ? challenge.correctPayload : [challenge.correctPayload];
    if (payloads.some(p => cmd.includes(p as string))) {
      return `[SYSTEM ALERT] ENCRYPTION BROKEN\nExploit successful. Payload acknowledged.\nFLAG: ${challenge.flag}`;
    }
    if (cmd === 'ls') return 'index.html  assets/  config.php  secret_data.db  .bash_history';
    if (cmd.startsWith('cat ')) return `ACCESS_DENIED: Kernel isolation prevents reading ${cmd.split(' ')[1]}`;
    return `ogt_bash: command not found: ${cmd}`;
  };

  const requestAiHint = async () => {
    setLoadingHint(true);
    setShowHint(true);
    const hint = await getAIHint(challenge.title, "Hey Omar, I'm stuck. Can you explain the logic behind this mission in simple terms?");
    setAiHint(hint || "Omar is in a deep meditation... Try again!");
    setLoadingHint(false);
  };

  const renderBrowserContent = () => {
    if (viewSource) {
      return (
        <div className="bg-slate-950 text-emerald-500/80 p-6 font-mono text-[10px] h-full overflow-auto rounded border border-slate-800 shadow-inner">
          <div className="mb-4 text-slate-700 italic border-b border-slate-800 pb-2 flex justify-between">
            <span>FILE: INDEX.HTML</span>
            <span>OGT SOURCE VIEW</span>
          </div>
          <pre>{`<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Target Node: ${challenge.title}</title>
</head>
<body>
    <header>
        <h1>Secure Communications Node</h1>
        <p>Target ID: ${challenge.id}</p>
    </header>
    
    <main>
        <!-- SYSTEM NOTE: Ensure security patches are applied before public release -->
        ${challenge.id === '1' ? '<!-- SECURITY_DEBUG: OGT{h1dd3n_1n_pl41n_s1ght} -->' : '<!-- Check internal systems for vulnerabilities -->'}
        
        <div id="app">
            <!-- Dynamic content loaded via JS -->
        </div>
    </main>

    <footer>
        &copy; 2024 OGTHG Security Protocols
    </footer>
    
    <script src="/js/encryption.js"></script>
</body>
</html>`}</pre>
        </div>
      );
    }

    switch (challenge.id) {
      case '21': // SSTI
        return (
          <div className="p-10 bg-white text-slate-900 h-full flex flex-col items-center justify-center">
             <div className="w-full max-w-sm bg-slate-50 p-8 rounded-[2.5rem] border border-slate-200 shadow-xl">
                <h2 className="text-xl font-black italic uppercase tracking-tighter mb-4 text-center">Nexus Greeter</h2>
                <div className="space-y-4">
                   <input 
                      className="w-full p-4 border border-slate-200 rounded-2xl outline-none focus:border-violet-500 transition-all font-mono text-sm"
                      placeholder="Enter your name..."
                      value={sstiInput}
                      onChange={(e) => setSstiInput(e.target.value)}
                   />
                   <button 
                      onClick={() => {
                        if (sstiInput.includes('{{') && sstiInput.includes('7*7')) setSstiResult('Hello, 49!');
                        else if (sstiInput.includes('{{config')) setSstiResult('FLAG: OGT{sst1_jinja2_exp0sed}');
                        else setSstiResult(`Hello, ${sstiInput}!`);
                      }}
                      className="w-full bg-slate-900 text-white p-4 rounded-2xl font-black uppercase italic"
                   >
                      Greet Me
                   </button>
                </div>
                {sstiResult && <div className="mt-6 p-4 bg-violet-600/10 border border-violet-500/20 rounded-xl text-center text-sm font-bold text-violet-600">{sstiResult}</div>}
             </div>
          </div>
        );

      case '3': // SQL Injection Login
        return (
          <div className="max-w-xs mx-auto mt-20 p-8 bg-slate-50 rounded-[2rem] border border-slate-200 shadow-xl text-slate-900">
            <h2 className="text-2xl font-black mb-6 text-center italic tracking-tighter uppercase">Admin Portal</h2>
            <div className="space-y-4">
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest px-2">Username</label>
                <input 
                  className="w-full p-4 bg-white border border-slate-200 rounded-2xl text-sm focus:border-violet-500 outline-none transition-all shadow-inner" 
                  placeholder="admin"
                  value={sqliUser}
                  onChange={(e) => setSqliUser(e.target.value)}
                />
              </div>
              <div className="space-y-1">
                <label className="text-[10px] font-bold text-slate-400 uppercase tracking-widest px-2">Password</label>
                <input 
                  className="w-full p-4 bg-white border border-slate-200 rounded-2xl text-sm focus:border-violet-500 outline-none transition-all shadow-inner" 
                  type="password" 
                  placeholder="••••••••"
                  value={sqliPass}
                  onChange={(e) => setSqliPass(e.target.value)}
                />
              </div>
              <button 
                onClick={() => {
                  if (sqliPass.includes("' OR 1=1 --") || sqliPass.includes("' OR '1'='1")) {
                    setSqliResult(`[SQL SUCCESS] Query: SELECT * FROM users WHERE user='${sqliUser}' AND pass='${sqliPass}' -> Row Found! FLAG: OGT{sql1_byp4ss_m4st3r}`);
                  } else {
                    setSqliResult("[SQL ERROR] Invalid credentials. Access Logged.");
                  }
                }}
                className="w-full bg-slate-900 text-white p-4 rounded-2xl font-black hover:bg-violet-600 transition-all uppercase italic tracking-widest"
              >
                Log In
              </button>
            </div>
            {sqliResult && <p className={`mt-4 text-[10px] font-bold text-center ${sqliResult.includes('SUCCESS') ? 'text-emerald-600' : 'text-red-500'}`}>{sqliResult}</p>}
          </div>
        );

      case '4': // XSS Search
        return (
          <div className="p-10 bg-white text-slate-900 h-full">
            <div className="flex items-center space-x-3 mb-10">
              <div className="relative flex-1">
                <Search className="absolute left-4 top-1/2 -translate-y-1/2 text-slate-300" size={18} />
                <input 
                  className="w-full p-4 pl-12 bg-slate-50 border border-slate-200 rounded-2xl text-sm outline-none focus:border-violet-500 transition-all shadow-inner" 
                  placeholder="Search the nexus database..." 
                  value={xssInput}
                  onChange={(e) => setXssInput(e.target.value)}
                />
              </div>
              <button 
                onClick={() => {
                  if (xssInput.toLowerCase().includes('<script>alert(')) setXssAlert(true);
                }}
                className="p-4 bg-violet-600 text-white rounded-2xl hover:bg-violet-500 transition-all shadow-lg shadow-violet-600/20"
              >
                <Search size={20} />
              </button>
            </div>
            <div className="border-t border-slate-100 pt-8">
               <h3 className="font-bold text-slate-400 uppercase text-xs tracking-widest mb-4">Results for: <span className="text-slate-900" dangerouslySetInnerHTML={{ __html: xssInput || '...' }} /></h3>
               <div className="bg-slate-50 p-10 rounded-[2rem] border-2 border-dashed border-slate-100 flex flex-col items-center justify-center">
                  <Database size={48} className="text-slate-100 mb-4" />
                  <p className="text-slate-300 italic text-sm">No data nodes found for this query.</p>
               </div>
            </div>
            {xssAlert && (
              <div className="absolute inset-0 z-50 flex items-center justify-center bg-slate-950/20 backdrop-blur-sm p-4">
                 <div className="bg-white border-4 border-violet-600 p-8 rounded-[2rem] shadow-2xl max-w-sm text-center">
                    <AlertTriangle className="text-violet-600 mx-auto mb-4" size={48} />
                    <h2 className="text-2xl font-black italic uppercase tracking-tighter mb-2">XSS TRIGGERED</h2>
                    <p className="text-slate-500 text-sm font-medium mb-6">JavaScript payload executed successfully in context. Vulnerability confirmed.</p>
                    <div className="bg-slate-950 text-emerald-400 p-4 rounded-xl font-mono text-xs break-all mb-6 italic">FLAG: {"OGT{xss_f1rst_st3p}"}</div>
                    <button onClick={() => setXssAlert(false)} className="w-full bg-slate-900 text-white p-4 rounded-2xl font-black uppercase italic">Close Alert</button>
                 </div>
              </div>
            )}
          </div>
        );

      default:
        return (
          <div className="h-full flex flex-col items-center justify-center bg-white text-slate-900 rounded-[3rem] p-10 text-center relative overflow-hidden">
            <Globe size={80} className="text-slate-100 mb-6 animate-pulse" />
            <h2 className="text-3xl font-black text-slate-800 italic uppercase tracking-tighter mb-4">Target Sector Online</h2>
            <p className="text-sm text-slate-400 font-medium max-w-sm">This target is currently under active monitoring. Use the URL bar or console tools to initiate the exploit sequence.</p>
            <div className="mt-10 flex space-x-4">
               <div className="flex items-center space-x-2">
                 <div className="w-2 h-2 rounded-full bg-violet-600" />
                 <span className="text-[10px] font-bold text-slate-400 uppercase tracking-widest">Live Node</span>
               </div>
            </div>
          </div>
        );
    }
  };

  return (
    <div className="flex h-screen bg-slate-950 text-slate-50 selection:bg-violet-500 selection:text-white">
      <div className="w-[420px] border-r border-slate-800 p-8 flex flex-col h-full overflow-y-auto bg-slate-900/50">
        <button onClick={() => navigate('/challenges')} className="flex items-center text-slate-500 hover:text-white mb-10 transition-colors text-[10px] font-black uppercase tracking-[0.2em]">
          <ArrowLeft size={16} className="mr-2" /> Abort Mission
        </button>

        <div className="mb-8">
          <span className="px-3 py-1 bg-violet-600/10 text-violet-400 text-[10px] font-black uppercase tracking-[0.2em] rounded-lg border border-violet-500/20 mb-4 inline-block">
            {challenge.category}
          </span>
          <h1 className="text-4xl font-black mb-3 italic tracking-tighter uppercase leading-tight">{challenge.title}</h1>
          <div className="flex items-center space-x-4">
            <div className="flex items-center bg-slate-800/80 px-3 py-1.5 rounded-xl border border-slate-700">
               <Shield size={12} className="mr-2 text-violet-400" />
               <span className="text-[10px] text-slate-300 font-black uppercase tracking-widest">{challenge.difficulty}</span>
            </div>
            <div className="flex items-center bg-violet-600/10 px-3 py-1.5 rounded-xl border border-violet-500/20">
               <span className="text-violet-400 font-black text-[10px] uppercase tracking-widest">{challenge.points} XP</span>
            </div>
          </div>
        </div>

        <div className="space-y-6 flex-1">
          <div className="bg-slate-800/50 p-6 rounded-[2rem] border border-slate-700 shadow-inner relative overflow-hidden group">
            <div className="absolute top-0 right-0 p-3 opacity-20 group-hover:opacity-40 transition-opacity"><Info size={40} /></div>
            <h3 className="font-black flex items-center mb-4 text-[10px] uppercase tracking-[0.2em] text-slate-500">
               Briefing Log
            </h3>
            <p className="text-slate-300 leading-relaxed text-sm font-medium">{challenge.description}</p>
          </div>

          <div className="space-y-4">
            <div className="flex items-center justify-between px-2">
              <h3 className="font-black uppercase tracking-[0.2em] text-[10px] text-slate-500">Mentorship System</h3>
              <div className="flex items-center space-x-2">
                <span className="text-[10px] text-violet-400 font-black uppercase italic">Operative Omar</span>
                <div className="w-8 h-8 rounded-xl bg-violet-600 flex items-center justify-center text-xs font-black italic shadow-lg shadow-violet-600/20">O</div>
              </div>
            </div>
            
            <button
              onClick={requestAiHint}
              disabled={loadingHint}
              className="w-full flex items-center justify-center p-5 bg-violet-600 text-white rounded-[2rem] hover:bg-violet-500 transition-all text-sm font-black shadow-2xl shadow-violet-600/30 group uppercase italic tracking-widest disabled:opacity-50"
            >
              {loadingHint ? <Loader2 className="animate-spin mr-2" size={20} /> : <Sparkles className="mr-2 group-hover:rotate-12 transition-transform" size={20} />} 
              {loadingHint ? 'Deciphering...' : 'Consult Omar'}
            </button>

            <AnimatePresence>
              {showHint && (
                <motion.div
                  initial={{ opacity: 0, y: 10, scale: 0.95 }}
                  animate={{ opacity: 1, y: 0, scale: 1 }}
                  className="bg-slate-900 border-2 border-violet-600/20 p-6 rounded-[2.5rem] text-xs leading-relaxed shadow-2xl relative"
                >
                  <div className="prose prose-invert prose-sm text-slate-400 mt-2 font-medium">
                    {loadingHint ? "Connecting to the mainframe..." : aiHint}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>
        </div>

        <div className="mt-10 pt-8 border-t border-slate-800/50">
          <form onSubmit={handleFlagSubmit} className="space-y-4">
            <div className="relative">
              <input
                className={`w-full bg-slate-950 border-2 ${error ? 'border-red-500' : 'border-slate-800'} focus:border-violet-600 outline-none p-5 rounded-[2rem] text-white font-mono placeholder:text-slate-900 transition-all shadow-inner text-sm font-bold tracking-widest`}
                placeholder="OGT{...}"
                value={flagInput}
                onChange={(e) => setFlagInput(e.target.value)}
                disabled={isSolved}
              />
              {isSolved && <div className="absolute right-6 top-1/2 -translate-y-1/2"><CheckCircle className="text-emerald-500" size={24} /></div>}
            </div>
            <motion.button
              whileTap={{ scale: 0.98 }}
              disabled={isSolved}
              className={`w-full py-5 rounded-[2rem] font-black uppercase tracking-[0.2em] italic transition-all shadow-2xl ${
                isSolved
                  ? 'bg-emerald-600 text-white'
                  : 'bg-violet-600 text-white hover:bg-violet-500'
              }`}
            >
              {isSolved ? 'Mission Success' : 'Verify Flag'}
            </motion.button>
          </form>
        </div>
      </div>

      <div className="flex-1 p-10 bg-slate-950 flex flex-col h-full overflow-hidden relative">
        <div className="mb-8 flex items-center justify-between relative z-10">
          <div>
            <h2 className="text-2xl font-black font-mono tracking-tighter italic uppercase text-slate-200">Simulation Environment</h2>
          </div>
          
          {challenge.simulatorType === 'browser' && (
            <button 
              onClick={() => setViewSource(!viewSource)}
              className={`flex items-center space-x-3 px-6 py-3 rounded-2xl text-[10px] font-black uppercase tracking-widest transition-all shadow-xl ${
                viewSource 
                  ? 'bg-emerald-600 text-white' 
                  : 'bg-slate-900 text-slate-400 border border-slate-800 hover:text-white hover:bg-slate-800'
              }`}
            >
              {viewSource ? <><Eye size={16} /> <span>Inspect UI</span></> : <><Code size={16} /> <span>Inspect Source</span></>}
            </button>
          )}
        </div>

        <div className="flex-1 relative overflow-hidden flex flex-col rounded-[3rem] shadow-[0_40px_100px_rgba(0,0,0,0.8)] border border-slate-800 bg-black relative z-10">
          <AnimatePresence>
            {isSolved && (
              <motion.div 
                initial={{ opacity: 0, scale: 0.9 }} animate={{ opacity: 1, scale: 1 }}
                className="absolute inset-0 z-50 pointer-events-none flex items-center justify-center bg-emerald-600/5 backdrop-blur-md"
              >
                <div className="p-16 bg-black/80 border-4 border-emerald-500/50 rounded-full text-emerald-400 font-black text-8xl italic tracking-tighter uppercase">
                  CLEARED
                </div>
              </motion.div>
            )}
          </AnimatePresence>
          
          <div className="flex-1 flex flex-col">
            {challenge.simulatorType === 'terminal' ? (
              <TerminalSimulator onCommand={handleTerminalCommand} />
            ) : (
              <BrowserSimulator 
                initialUrl={currentUrl}
                onNavigate={(url) => setCurrentUrl(url)}
              >
                {renderBrowserContent()}
              </BrowserSimulator>
            )}
          </div>
        </div>

        <div className="mt-10 bg-slate-900/50 border border-slate-800/80 p-6 rounded-[2.5rem] flex items-center justify-between relative z-10 shadow-2xl backdrop-blur-md">
           <div className="flex items-center space-x-6">
              <div className="w-14 h-14 rounded-2xl bg-violet-600/10 border border-violet-500/20 flex items-center justify-center text-violet-400 font-black italic text-2xl shadow-inner">!</div>
              <div>
                <div className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em] mb-1 italic">Operative Protocol Log</div>
                <div className="text-sm text-slate-300 font-bold italic">Inject payloads carefully. Standard WAF is bypassed.</div>
              </div>
           </div>
        </div>
      </div>
    </div>
  );
};

export default ChallengePage;
