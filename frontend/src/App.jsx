import { useState } from 'react'
import URLAnalysis from './pages/URLAnalysis'

function App() {
const [activePage, setActivePage] = useState('Dashboard')

const menuItems = [
{ name: 'Dashboard', icon: '⌂' },
{ name: 'URL Analysis', icon: '↗' },
{ name: 'File Analysis', icon: '▤' },
{ name: 'Email Analysis', icon: '✉' },
{ name: 'History', icon: '◷' },
]

return ( <div className="min-h-screen bg-slate-950 text-slate-100 flex">

```
  {/* Sidebar */}
  <aside className="w-64 bg-slate-900 border-r border-slate-800 p-6 flex flex-col">

    <div className="mb-12">
      <h1 className="text-2xl font-bold text-cyan-400">
        CyberShield
      </h1>
      <p className="text-xs text-slate-500 mt-1">
        AI Cyber Threat Detection
      </p>
    </div>

    <p className="text-xs uppercase tracking-widest text-slate-500 mb-4">
      Main Menu
    </p>

    <nav className="space-y-2">
      {menuItems.map((item) => (
        <button
          key={item.name}
          onClick={() => setActivePage(item.name)}
          className={`w-full flex items-center gap-3 px-4 py-3 rounded-lg text-sm transition ${
            activePage === item.name
              ? 'bg-cyan-500/10 text-cyan-400 border border-cyan-500/20'
              : 'text-slate-400 hover:bg-slate-800 hover:text-white'
          }`}
        >
          <span className="text-lg">{item.icon}</span>
          {item.name}
        </button>
      ))}
    </nav>

    <div className="mt-auto border-t border-slate-800 pt-5">
      <p className="text-xs text-slate-500">SYSTEM STATUS</p>
      <div className="flex items-center gap-2 mt-3">
        <span className="w-2 h-2 rounded-full bg-green-400"></span>
        <span className="text-sm text-slate-400">System Online</span>
      </div>
    </div>

  </aside>

  {/* Main Content */}
  <main className="flex-1">

    {/* Navbar */}
    <header className="h-20 border-b border-slate-800 flex items-center justify-between px-8">
      <div>
        <h2 className="text-xl font-semibold">{activePage}</h2>
        <p className="text-xs text-slate-500 mt-1">
          CyberShield / {activePage}
        </p>
      </div>

      <div className="flex items-center gap-3">
        <div className="text-right">
          <p className="text-sm font-medium">Administrator</p>
          <p className="text-xs text-slate-500">Security Analyst</p>
        </div>
        <div className="w-10 h-10 rounded-full bg-cyan-500/20 border border-cyan-500/30 flex items-center justify-center text-cyan-400 font-bold">
          A
        </div>
      </div>
    </header>

    {/* Dashboard Content */}
    <section className="p-8">

      {activePage === 'URL Analysis' ? (
       <URLAnalysis />
           ) : (
            <>
      <div className="mb-8">
        <h1 className="text-3xl font-bold">
          Welcome to CyberShield
        </h1>
        <p className="text-slate-400 mt-2">
          Monitor, analyze and detect potential cyber threats.
        </p>
      </div>

      {/* Statistics */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-sm text-slate-400">URLs Analyzed</p>
          <h2 className="text-3xl font-bold mt-3">--</h2>
          <p className="text-xs text-slate-500 mt-2">
            Total URLs scanned
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-sm text-slate-400">Threats Detected</p>
          <h2 className="text-3xl font-bold text-red-400 mt-3">--</h2>
          <p className="text-xs text-slate-500 mt-2">
            Potential malicious URLs
          </p>
        </div>

        <div className="bg-slate-900 border border-slate-800 rounded-xl p-6">
          <p className="text-sm text-slate-400">System Status</p>
          <h2 className="text-3xl font-bold text-green-400 mt-3">
            Online
          </h2>
          <p className="text-xs text-slate-500 mt-2">
            All services operational
          </p>
        </div>

      </div>

      {/* Quick Analysis */}
      <div className="mt-8 bg-slate-900 border border-slate-800 rounded-xl p-8">
        <h2 className="text-xl font-semibold">
          Quick Analysis
        </h2>
        <p className="text-sm text-slate-400 mt-2">
          Select a security module to begin threat analysis.
        </p>

        <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mt-6">
          {menuItems.slice(1, 4).map((item) => (
            <button
              key={item.name}
              onClick={() => setActivePage(item.name)}
              className="text-left bg-slate-800/60 border border-slate-700 rounded-lg p-5 hover:border-cyan-500/50 transition"
            >
              <span className="text-2xl text-cyan-400">
                {item.icon}
              </span>
              <h3 className="font-semibold mt-3">{item.name}</h3>
              <p className="text-xs text-slate-400 mt-2">
                Open analysis module →
              </p>
            </button>
          ))}
        </div>
      </div>
      </>
     )}
    </section>
  </main>
</div>


)
}

export default App
