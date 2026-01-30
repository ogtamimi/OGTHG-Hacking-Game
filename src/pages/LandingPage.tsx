
import React from 'react';
import { Link } from 'react-router-dom';
import { Shield, Zap, Terminal, Trophy, ChevronRight, Github, Info, Cpu } from 'lucide-react';
import { motion } from 'framer-motion';

const LandingPage: React.FC = () => {
  return (
    <div className="min-h-screen bg-slate-950 text-slate-50 selection:bg-violet-500 selection:text-white">
      {/* Navbar */}
      <header className="fixed w-full z-50 bg-slate-950/80 backdrop-blur-md border-b border-slate-800">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex justify-between items-center py-4">
            <div className="flex items-center space-x-2">
              <div className="w-8 h-8 bg-violet-600 rounded-lg flex items-center justify-center shadow-lg shadow-violet-600/20">
                <Shield className="text-white" size={20} />
              </div>
              <span className="text-xl font-black tracking-tighter uppercase italic">OGTHG</span>
            </div>
            <div className="hidden md:flex items-center space-x-8">
              <a href="#features" className="text-sm font-bold text-slate-400 hover:text-violet-400 transition-colors uppercase tracking-widest">Features</a>
              <a href="#about" className="text-sm font-bold text-slate-400 hover:text-violet-400 transition-colors uppercase tracking-widest">About</a>
              <Link to="/initialize" className="px-5 py-2 bg-violet-600 text-white rounded-full text-sm font-black hover:bg-violet-500 transition-all shadow-lg shadow-violet-600/20 uppercase italic">
                Enter System
              </Link>
            </div>
          </div>
        </div>
      </header>

      {/* Hero Section */}
      <section className="relative pt-32 pb-20 md:pt-48 md:pb-32 overflow-hidden">
        <div className="absolute top-0 left-1/2 -translate-x-1/2 w-full h-full pointer-events-none overflow-hidden -z-10">
           <div className="absolute top-1/4 left-1/4 w-[500px] h-[500px] bg-violet-600/10 rounded-full blur-[120px]" />
           <div className="absolute bottom-1/4 right-1/4 w-[500px] h-[500px] bg-blue-600/10 rounded-full blur-[120px]" />
        </div>

        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 relative">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
            className="text-center"
          >
            <span className="inline-block px-4 py-1.5 rounded-full bg-violet-600/10 text-violet-400 text-[10px] font-black uppercase tracking-[0.2em] border border-violet-500/20 mb-6">
              Official Hacking Game Platform
            </span>
            <h1 className="text-5xl md:text-8xl font-black tracking-tighter mb-6 bg-gradient-to-r from-white via-white to-slate-500 bg-clip-text text-transparent italic uppercase">
              Master the <br />
              <span className="text-violet-500">Dark Arts</span>
            </h1>
            <p className="text-lg text-slate-400 max-w-2xl mx-auto mb-10 font-medium leading-relaxed">
              The premier educational platform for Web CTF. From basic SQL injection to advanced session hijacking. Real targets, real exploits, real glory.
            </p>
            <div className="flex flex-col sm:flex-row items-center justify-center space-y-4 sm:space-y-0 sm:space-x-4">
              <Link to="/initialize" className="w-full sm:w-auto px-10 py-5 bg-violet-600 text-white rounded-2xl font-black flex items-center justify-center hover:bg-violet-500 transition-all shadow-2xl shadow-violet-600/40 group uppercase italic tracking-widest">
                Start Mission <ChevronRight size={20} className="ml-2 group-hover:translate-x-1 transition-transform" />
              </Link>
              <a 
                href="https://github.com/ogtamimi/Web-CTF-Challenges" 
                target="_blank" 
                rel="noopener noreferrer"
                className="w-full sm:w-auto px-10 py-5 bg-slate-900 border border-slate-800 text-white rounded-2xl font-black flex items-center justify-center hover:bg-slate-800 transition-all uppercase italic tracking-widest"
              >
                <Github size={20} className="mr-2" /> Source Code
              </a>
            </div>
          </motion.div>
        </div>
      </section>

      {/* About Section */}
      <section id="about" className="py-24 bg-slate-950 border-t border-slate-900">
        <div className="max-w-7xl mx-auto px-4">
          <div className="grid md:grid-cols-2 gap-16 items-center">
            <div>
              <span className="text-violet-500 font-black uppercase tracking-widest text-xs mb-4 block italic">Behind the Nexus</span>
              <h2 className="text-4xl font-black mb-6 uppercase italic tracking-tighter">What is OGTHG?</h2>
              <p className="text-slate-400 leading-relaxed font-medium mb-8">
                OGTHG (The OG Tamimi Hacking Game) is a cutting-edge playground for aspiring security researchers. Unlike traditional platforms, we focus on high-fidelity simulations of real-world web vulnerabilities. 
                <br /><br />
                Our mission is to bridge the gap between theoretical knowledge and practical exploitation in a safe, legal, and highly gamified environment.
              </p>
              <div className="grid grid-cols-2 gap-6">
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-slate-800">
                  <Info className="text-violet-400 mb-2" size={24} />
                  <div className="text-white font-black italic text-sm uppercase">Educational</div>
                  <div className="text-slate-500 text-xs mt-1">Guided steps for every mission.</div>
                </div>
                <div className="bg-slate-900/50 p-4 rounded-2xl border border-slate-800">
                  <Cpu className="text-blue-400 mb-2" size={24} />
                  <div className="text-white font-black italic text-sm uppercase">Simulated</div>
                  <div className="text-slate-500 text-xs mt-1">Realistic sandbox targets.</div>
                </div>
              </div>
            </div>
            <div className="relative">
              <div className="absolute -inset-4 bg-violet-600/20 blur-3xl rounded-full" />
              <div className="relative bg-slate-900 border border-slate-800 p-8 rounded-[3rem] shadow-2xl overflow-hidden group">
                 <div className="font-mono text-[10px] text-violet-500/50 space-y-1 mb-6">
                   <div>[OK] NODE_INITIALIZED</div>
                   <div>[OK] SECURITY_KERNEL_V1_ACTIVE</div>
                   <div>[OK] SIMULATOR_SYNC_COMPLETE</div>
                   <div>[WARN] ACCESS_LOG_OVERFLOW</div>
                 </div>
                 <div className="h-40 flex items-center justify-center">
                    <Terminal className="text-violet-600 animate-pulse" size={100} />
                 </div>
                 <div className="mt-6 p-4 bg-slate-950 rounded-2xl border border-slate-800 text-center">
                    <span className="text-xs font-black uppercase text-slate-500">System Ready for Operatives</span>
                 </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      {/* Features */}
      <section id="features" className="py-24 bg-slate-900/20 border-t border-slate-900">
        <div className="max-w-7xl mx-auto px-4">
          <div className="text-center mb-20">
            <h2 className="text-3xl md:text-5xl font-black mb-4 uppercase italic tracking-tighter">The OGTHG Arsenal</h2>
            <p className="text-slate-400 font-medium">State-of-the-art tools for the modern security researcher.</p>
          </div>
          <div className="grid md:grid-cols-3 gap-8">
            {[
              { title: 'Live Simulators', desc: 'Execute payloads in a safe, isolated browser or terminal environment built for learning.', icon: Terminal },
              { title: 'AI Mentor: Omar', desc: 'Stuck? Omar is our expert AI mentor. He explains complex exploits in simple terms.', icon: Zap },
              { title: 'Global Fame', desc: 'Rise through the ranks, earn badges, and dominate the global Hall of Fame.', icon: Trophy },
            ].map((feature, i) => (
              <motion.div
                key={i}
                whileHover={{ y: -10 }}
                className="p-10 rounded-[2.5rem] bg-slate-900/50 border border-slate-800 hover:border-violet-500/50 transition-all shadow-xl"
              >
                <div className="w-14 h-14 bg-violet-600/10 rounded-2xl flex items-center justify-center mb-8 border border-violet-500/20">
                  <feature.icon className="text-violet-400" size={28} />
                </div>
                <h3 className="text-2xl font-black mb-4 italic uppercase tracking-tighter">{feature.title}</h3>
                <p className="text-slate-400 leading-relaxed font-medium">{feature.desc}</p>
              </motion.div>
            ))}
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="py-12 border-t border-slate-900 bg-slate-950 text-slate-500">
        <div className="max-w-7xl mx-auto px-4 text-center">
          <div className="mb-6 flex justify-center items-center space-x-2">
            <Shield size={28} className="text-violet-500" />
            <span className="text-white font-black tracking-tighter uppercase italic text-2xl">OGTHG</span>
          </div>
          <p className="text-xs font-bold uppercase tracking-widest">© 2024 OGTHG Hacking Game Platform. Unauthorized access is strictly encouraged (in our sandbox).</p>
        </div>
      </footer>
    </div>
  );
};

export default LandingPage;
