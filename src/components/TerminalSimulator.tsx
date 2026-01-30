
import React, { useState, useRef, useEffect } from 'react';

interface TerminalSimulatorProps {
  onCommand: (cmd: string) => string;
  placeholder?: string;
}

const TerminalSimulator: React.FC<TerminalSimulatorProps> = ({ onCommand, placeholder }) => {
  const [history, setHistory] = useState<{ type: 'input' | 'output'; content: string }[]>([
    { type: 'output', content: 'OGTHG OS v2.1.0 (GNU/Linux x86_64)' },
    { type: 'output', content: 'Secure session initialized. Welcome, operative.' },
  ]);
  const [input, setInput] = useState('');
  const bottomRef = useRef<HTMLDivElement>(null);

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!input.trim()) return;

    const output = onCommand(input);
    setHistory([...history, { type: 'input', content: input }, { type: 'output', content: output }]);
    setInput('');
  };

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' });
  }, [history]);

  return (
    <div className="bg-black rounded-lg border border-slate-700 h-96 flex flex-col overflow-hidden shadow-2xl font-mono text-sm">
      <div className="bg-slate-800 px-4 py-2 border-b border-slate-700 flex items-center justify-between">
        <div className="flex space-x-2">
          <div className="w-3 h-3 rounded-full bg-red-500" />
          <div className="w-3 h-3 rounded-full bg-yellow-500" />
          <div className="w-3 h-3 rounded-full bg-green-500" />
        </div>
        <span className="text-xs text-slate-400 uppercase tracking-widest">OGT Console</span>
      </div>
      <div className="flex-1 overflow-y-auto p-4 space-y-1">
        {history.map((line, i) => (
          <div key={i} className={line.type === 'input' ? 'text-emerald-400' : 'text-slate-300'}>
            {line.type === 'input' ? <span className="mr-2">user@ogt:~$</span> : null}
            <span className="whitespace-pre-wrap">{line.content}</span>
          </div>
        ))}
        <div ref={bottomRef} />
      </div>
      <form onSubmit={handleSubmit} className="p-4 bg-slate-900/50 flex border-t border-slate-800">
        <span className="text-emerald-400 mr-2 shrink-0">user@ogt:~$</span>
        <input
          autoFocus
          className="bg-transparent border-none outline-none text-white w-full"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder={placeholder || "Type a command..."}
        />
      </form>
    </div>
  );
};

export default TerminalSimulator;
