import { useState } from 'react'

function URLAnalysis() {
const [url, setUrl] = useState('')
const [result, setResult] = useState(null)
const [loading, setLoading] = useState(false)
const [error, setError] = useState('')

const handleAnalyze = async () => {
if (!url.trim()) {
setError('Please enter a URL.')
return
}


setLoading(true)
setError('')
setResult(null)

try {
  const response = await fetch(
    'http://127.0.0.1:8000/api/url/analyze',
    {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({ url: url.trim() }),
    }
  )

  const data = await response.json()

  if (!response.ok) {
    throw new Error(
      data.detail?.[0]?.msg || 'Unable to analyze URL.'
    )
  }

  setResult(data)
} catch (err) {
  setError(err.message || 'Could not connect to the backend.')
} finally {
  setLoading(false)
}


}

return ( <div> <div className="mb-8"> <h1 className="text-3xl font-bold">URL Analysis</h1> <p className="text-slate-400 mt-2">
Analyze URLs to identify potential phishing threats. </p> </div>


  <div className="bg-slate-900 border border-slate-800 rounded-xl p-8">
    <h2 className="text-xl font-semibold mb-2">
      Analyze a URL
    </h2>

    <p className="text-sm text-slate-400 mb-6">
      Enter a URL for static security analysis.
    </p>

    <label className="block text-sm text-slate-300 mb-2">
      Website URL
    </label>

    <input
      type="text"
      value={url}
      onChange={(e) => setUrl(e.target.value)}
      onKeyDown={(e) => {
        if (e.key === 'Enter') handleAnalyze()
      }}
     placeholder="Enter website URL (e.g. google.com)"
      className="w-full bg-slate-800 border border-slate-700 rounded-lg px-4 py-3 text-white outline-none focus:border-cyan-500"
    />

    <button
      onClick={handleAnalyze}
      disabled={loading}
      className="mt-5 bg-cyan-500 hover:bg-cyan-400 disabled:opacity-50 text-slate-950 font-semibold px-6 py-3 rounded-lg transition"
    >
      {loading ? 'Analyzing...' : 'Analyze URL'}
    </button>

    {error && (
      <p className="text-red-400 text-sm mt-4">{error}</p>
    )}
  </div>

  {result && (
    <div className="mt-8 bg-slate-900 border border-slate-800 rounded-xl p-8">
      <h2 className="text-xl font-semibold">
        Analysis Results
      </h2>

      <p className="text-sm text-slate-400 mt-2 break-all">
        URL: {result.url}
      </p>

      <div className="mt-5 inline-block bg-green-500/10 text-green-400 border border-green-500/20 rounded-lg px-4 py-2 text-sm">
        {result.status.toUpperCase()}
      </div>

      <h3 className="font-semibold mt-8 mb-4">
        Extracted Features
      </h3>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
        {Object.entries(result.features).map(([name, value]) => (
          <div
            key={name}
            className="bg-slate-800/70 border border-slate-700 rounded-lg p-4"
          >
            <p className="text-xs text-slate-400 break-all">
              {name.replaceAll('_', ' ')}
            </p>
            <p className="text-xl font-semibold text-cyan-400 mt-2">
              {value}
            </p>
          </div>
        ))}
      </div>
    </div>
  )}
</div>

)
}

export default URLAnalysis
