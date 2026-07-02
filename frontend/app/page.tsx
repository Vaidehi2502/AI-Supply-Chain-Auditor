"use client";
import { useState } from "react";
import { Shield, Search, AlertTriangle, CheckCircle, XCircle, ChevronDown, ChevronUp, Loader2 } from "lucide-react";

// ── Types ──────────────────────────────────────────────────────────────
type RiskLevel = "SAFE" | "WARNING" | "DANGER" | "ERROR";

interface ScanResult {
  model_id?: string;
  overall_risk: RiskLevel;
  repo_info?: {
    author: string;
    downloads: number;
    likes: number;
    tags: string[];
  };
  files_found?: string[];
  files_scanned?: string[];
  findings_summary?: string[];
  scan_results?: Record<string, any>;
}

// ── Risk styling ───────────────────────────────────────────────────────
const riskConfig = {
  SAFE:    { color: "text-emerald-400", bg: "bg-emerald-400/10", border: "border-emerald-400/30", icon: CheckCircle },
  WARNING: { color: "text-amber-400",   bg: "bg-amber-400/10",   border: "border-amber-400/30",   icon: AlertTriangle },
  DANGER:  { color: "text-red-400",     bg: "bg-red-400/10",     border: "border-red-400/30",     icon: XCircle },
  ERROR:   { color: "text-purple-400",  bg: "bg-purple-400/10",  border: "border-purple-400/30",  icon: XCircle },
};

// ── Risk Badge ─────────────────────────────────────────────────────────
function RiskBadge({ level }: { level: RiskLevel }) {
  const config = riskConfig[level] || riskConfig.ERROR;
  const Icon = config.icon;
  return (
    <span className={`inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-sm font-semibold border ${config.color} ${config.bg} ${config.border}`}>
      <Icon size={14} />
      {level}
    </span>
  );
}

// ── Expandable finding row ─────────────────────────────────────────────
function FindingRow({ text }: { text: string }) {
  const isWarning = text.toLowerCase().includes("pickle") || text.toLowerCase().includes("warning");
  const isDanger  = text.toLowerCase().includes("danger") || text.toLowerCase().includes("nan") || text.toLowerCase().includes("inf");
  const color = isDanger ? "text-red-300" : isWarning ? "text-amber-300" : "text-slate-300";
  return (
    <div className={`flex items-start gap-2 p-3 rounded-lg bg-slate-800/50 text-sm ${color}`}>
      <span className="mt-0.5 shrink-0">›</span>
      <span>{text}</span>
    </div>
  );
}

// ── Scan detail card ───────────────────────────────────────────────────
function ScanCard({ title, data }: { title: string; data: any }) {
  const [open, setOpen] = useState(true);
  if (!data) return null;
  const risk: RiskLevel = data.risk_level || "SAFE";
  const config = riskConfig[risk];

  return (
    <div className={`rounded-xl border ${config.border} bg-slate-900/50 overflow-hidden`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between p-4 hover:bg-slate-800/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className="text-slate-200 font-medium">{title}</span>
          <RiskBadge level={risk} />
        </div>
        {open ? <ChevronUp size={16} className="text-slate-400" /> : <ChevronDown size={16} className="text-slate-400" />}
      </button>

      {open && (
        <div className="px-4 pb-4 space-y-2">
          {(data.findings || []).map((f: string, i: number) => (
            <FindingRow key={i} text={f} />
          ))}
          {data.recommendation && (
            <div className="p-3 rounded-lg bg-teal-900/30 border border-teal-700/30 text-teal-300 text-sm">
              💡 {data.recommendation}
            </div>
          )}
          {data.ml_analysis?.anomalous_layers?.length > 0 && (
            <div className="mt-3">
              <p className="text-xs text-slate-500 uppercase tracking-wider mb-2">ML Anomaly Detection</p>
              {data.ml_analysis.anomalous_layers.map((a: any, i: number) => (
                <div key={i} className="flex items-center justify-between p-2 rounded bg-slate-800/50 mb-1">
                  <span className="text-xs text-slate-300 font-mono">{a.layer}</span>
                  <span className={`text-xs font-semibold ${a.severity === "HIGH" ? "text-red-400" : "text-amber-400"}`}>
                    {a.severity} ({a.anomaly_score})
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ── Main page ──────────────────────────────────────────────────────────
export default function Home() {
  const [url, setUrl]         = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult]   = useState<ScanResult | null>(null);
  const [error, setError]     = useState("");

  async function runScan() {
    if (!url.trim()) return;
    setLoading(true);
    setError("");
    setResult(null);

    try {
      const res = await fetch("http://127.0.0.1:8000/scan/huggingface", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ model_url: url.trim() }),
      });

      if (!res.ok) throw new Error(`API error: ${res.status}`);
      const data = await res.json();
      setResult(data);
    } catch (e: any) {
      setError(e.message || "Scan failed. Is the API running?");
    } finally {
      setLoading(false);
    }
  }

  const risk = result?.overall_risk;
  const riskCfg = risk ? riskConfig[risk] : null;

  return (
    <main className="min-h-screen bg-slate-950 text-white">

      {/* Header */}
      <header className="border-b border-slate-800 px-6 py-4 flex items-center gap-3">
        <Shield className="text-teal-400" size={24} />
        <div>
          <h1 className="font-bold text-lg leading-none">AI Supply Chain Auditor</h1>
          <p className="text-slate-400 text-xs mt-0.5">VirusTotal for open-source AI models</p>
        </div>
      </header>

      <div className="max-w-3xl mx-auto px-4 py-10 space-y-6">

        {/* Search bar */}
        <div className="rounded-2xl border border-slate-700 bg-slate-900 p-6 space-y-4">
          <h2 className="text-slate-200 font-semibold">Scan a HuggingFace Model</h2>
          <div className="flex gap-3">
            <input
              value={url}
              onChange={e => setUrl(e.target.value)}
              onKeyDown={e => e.key === "Enter" && runScan()}
              placeholder="e.g. prajjwal1/bert-tiny or full HuggingFace URL"
              className="flex-1 bg-slate-800 border border-slate-700 rounded-xl px-4 py-3 text-sm text-white placeholder-slate-500 outline-none focus:border-teal-500 transition-colors"
            />
            <button
              onClick={runScan}
              disabled={loading || !url.trim()}
              className="flex items-center gap-2 bg-teal-600 hover:bg-teal-500 disabled:bg-slate-700 disabled:text-slate-500 text-white px-5 py-3 rounded-xl text-sm font-semibold transition-colors"
            >
              {loading
                ? <><Loader2 size={16} className="animate-spin" /> Scanning...</>
                : <><Search size={16} /> Scan</>
              }
            </button>
          </div>
          <p className="text-slate-500 text-xs">
            Paste any public HuggingFace model ID or URL — we'll download and audit it automatically
          </p>
        </div>

        {/* Error */}
        {error && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/10 p-4 text-red-300 text-sm">
            ⚠️ {error}
          </div>
        )}

        {/* Loading state */}
        {loading && (
          <div className="rounded-2xl border border-slate-700 bg-slate-900 p-8 text-center space-y-3">
            <Loader2 className="animate-spin text-teal-400 mx-auto" size={32} />
            <p className="text-slate-300 font-medium">Scanning model...</p>
            <p className="text-slate-500 text-sm">Downloading files · Running serialization checks · Analyzing weights with ML</p>
          </div>
        )}

        {/* Results */}
        {result && !loading && (
          <div className="space-y-4">

            {/* Overall risk banner */}
            <div className={`rounded-2xl border ${riskCfg?.border} ${riskCfg?.bg} p-6`}>
              <div className="flex items-center justify-between flex-wrap gap-4">
                <div>
                  <p className="text-slate-400 text-sm mb-1">Overall Risk</p>
                  <RiskBadge level={result.overall_risk} />
                </div>
                {result.repo_info && (
                  <div className="flex gap-6 text-center">
                    <div>
                      <p className="text-lg font-bold text-white">{result.repo_info.downloads?.toLocaleString()}</p>
                      <p className="text-slate-400 text-xs">Downloads</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold text-white">{result.repo_info.likes}</p>
                      <p className="text-slate-400 text-xs">Likes</p>
                    </div>
                    <div>
                      <p className="text-lg font-bold text-white">{result.files_scanned?.length || 0}</p>
                      <p className="text-slate-400 text-xs">Files Scanned</p>
                    </div>
                  </div>
                )}
              </div>

              {/* Tags */}
              {result.repo_info?.tags?.length > 0 && (
                <div className="flex flex-wrap gap-1.5 mt-4">
                  {result.repo_info.tags.slice(0, 8).map((tag: string) => (
                    <span key={tag} className="px-2 py-0.5 rounded-full bg-slate-800 text-slate-400 text-xs">{tag}</span>
                  ))}
                </div>
              )}
            </div>

            {/* Findings summary */}
            {result.findings_summary && result.findings_summary.length > 0 && (
              <div className="rounded-2xl border border-slate-700 bg-slate-900 p-5 space-y-2">
                <h3 className="text-slate-300 font-semibold text-sm uppercase tracking-wider">Findings Summary</h3>
                {result.findings_summary.map((f, i) => (
                  <FindingRow key={i} text={f} />
                ))}
              </div>
            )}

            {/* Per-file scan details */}
            {result.scan_results && Object.entries(result.scan_results).map(([filename, scans]: [string, any]) => (
              <div key={filename} className="space-y-3">
                <p className="text-slate-400 text-xs uppercase tracking-wider font-mono px-1">📄 {filename}</p>
                {scans.serialization && <ScanCard title="🔐 Serialization Safety" data={scans.serialization} />}
                {scans.weights      && <ScanCard title="🧠 ML Weight Analysis"   data={scans.weights} />}
              </div>
            ))}

          </div>
        )}
      </div>
    </main>
  );
}