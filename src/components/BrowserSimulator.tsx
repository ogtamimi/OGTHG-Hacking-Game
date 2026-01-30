
import React, { useState } from 'react';
import { Globe, RefreshCw, ChevronLeft, ChevronRight, Lock } from 'lucide-react';

interface BrowserSimulatorProps {
  initialUrl: string;
  onNavigate?: (url: string) => void;
  onPayload?: (payload: string) => void;
  children: React.ReactNode;
}

const BrowserSimulator: React.FC<BrowserSimulatorProps> = ({ initialUrl, onNavigate, onPayload, children }) => {
  const [url, setUrl] = useState(initialUrl);

  const handleGo = (e: React.FormEvent) => {
    e.preventDefault();
    onNavigate?.(url);
  };

  return (
    <div className="bg-slate-900 rounded-[2rem] border border-slate-700 overflow-hidden shadow-2xl flex flex-col h-full">
      <div className="bg-slate-800 p-3 flex items-center space-x-3 border-b border-slate-700">
        <div className="flex space-x-3 px-2">
          <ChevronLeft className="text-slate-600 w-5 h-5 cursor-not-allowed" />
          <ChevronRight className="text-slate-600 w-5 h-5 cursor-not-allowed" />
          <RefreshCw className="text-slate-400 w-5 h-5 hover:text-white cursor-pointer transition-colors" />
        </div>
        <form onSubmit={handleGo} className="flex-1">
          <div className="bg-slate-950 flex items-center px-4 py-2.5 rounded-2xl border border-slate-700 focus-within:border-violet-600 transition-all shadow-inner">
            <Lock className="text-violet-500 w-3.5 h-3.5 mr-3" />
            <input
              className="bg-transparent border-none outline-none text-slate-300 text-sm w-full font-mono font-medium"
              value={url}
              onChange={(e) => setUrl(e.target.value)}
            />
          </div>
        </form>
        <Globe className="text-slate-500 w-5 h-5 mx-3" />
      </div>
      <div className="flex-1 overflow-auto bg-white text-slate-900 relative">
        {children}
      </div>
    </div>
  );
};

export default BrowserSimulator;
