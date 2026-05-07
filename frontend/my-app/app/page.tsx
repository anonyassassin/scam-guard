"use client"
import Image from "next/image";
import { useEffect, useState } from "react";


type Stats = {
  scams_blocked: number;
  emails_flagged: number;
  risky_sites_visited: number;
};

type BlockedSite = {
  id: number;
  domain: string;
  url: string;
  timestamp: string;
};


export default function Home() {
  const [stats, setStats] = useState<Stats | null>(null);
  const [sites, setSites] = useState<BlockedSite[]>([])
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    fetch("http://127.0.0.1:8000/stats")
      .then(res => res.json())
      .then(setStats)

    fetch("http://127.0.0.1:8000/sites-blocked")
      .then(res => res.json())
      .then(data => {
        setSites(data);
        setLoading(false);
      })
      .catch(() => setLoading(false));

  }, [])
  return (
    <main className="min-h-screen bg-slate-900 text-slate-100">
      {/* Top Navbar */}
      <header className="flex items-center justify-between px-6 py-4 border-b border-slate-700 bg-slate-800">
        <h1 className="text-xl font-semibold">ScamGuard</h1>
        <span className="text-sm text-green-400 font-medium">
          Protection Active
        </span>
      </header>

      {/* Content */}
      <div className="p-6 grid grid-cols-1 lg:grid-cols-3 gap-6">

        {/* Left Column */}
        <div className="lg:col-span-2 space-y-6">

          {/* Stats */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
            <StatCard title="Scams Blocked" value={String(stats?.scams_blocked)} />
            <StatCard title="Emails Flagged" value={String(stats?.emails_flagged)} />
            <StatCard title="Risky Sites Visited" value={String(stats?.risky_sites_visited)} />
          </div>

          {/* Blocked Sites */}
          <section className="bg-slate-800 rounded-xl border border-slate-700">
            <div className="px-4 py-3 border-b border-slate-700 font-medium">
              Blocked Websites
            </div>

            <table className="w-full text-sm">
              <thead className="text-slate-400">
                <tr>
                  <th className="text-left px-4 py-2">Domain</th>
                  <th className="text-left px-4 py-2">Reason</th>
                  <th className="text-left px-4 py-2">Risk</th>
                </tr>
              </thead>
              <tbody>


                {(sites || []).map(site => (
                  <Row key={site.id} domain={site.domain} reason="Phishing Page" risk="High" />
                ))}
              </tbody>
            </table>
          </section>
        </div>

        {/* Right Column */}
        <div className="space-y-6">

          {/* News */}
          <section className="bg-slate-800 rounded-xl border border-slate-700">
            <div className="px-4 py-3 border-b border-slate-700 font-medium">
              Scam Alerts
            </div>

            <ul className="divide-y divide-slate-700 text-sm">
              <a href="https://www.business-standard.com/finance/personal-finance/another-delivery-scam-surfaces-pib-flags-fake-india-post-sms-125102000484_1.html"><NewsItem text="Fake delivery SMS scams targeting India Post users" /></a>
              <a href="https://www.bbc.com/news/business-39798022"><NewsItem text="Google Docs phishing emails spreading credential stealers" /></a>
              <a href="https://ccoe.dsci.in/blog/common-upi-scams-and-how-to-avoid-them"><NewsItem text="UPI refund scam resurfaces on WhatsApp" /></a>
            </ul>
          </section>

          {/* Status */}
          <section className="bg-slate-800 rounded-xl border border-slate-700 p-4">
            <h2 className="font-medium mb-2">System Status</h2>
            <ul className="text-sm text-slate-400 space-y-1">
              <li>Web Protection: <span className="text-green-400">Enabled</span></li>
              <li>Email Protection: <span className="text-green-400">Enabled</span></li>
              <li>Backend: <span className="text-green-400">Running</span></li>
            </ul>
          </section>

        </div>
      </div>
    </main>
  );
}

/* --- Components --- */

function StatCard({ title, value }: { title: string; value: string }) {
  return (
    <div className="bg-slate-800 border border-slate-700 rounded-xl p-4">
      <p className="text-sm text-slate-400">{title}</p>
      <p className="text-2xl font-semibold mt-1">{value}</p>
    </div>
  );
}

function Row({ domain, reason, risk }: { domain: string; reason: string; risk: string }) {
  return (
    <tr className="border-t border-slate-700">
      <td className="px-4 py-2">{domain}</td> <td className="px-4 py-2 text-slate-400">{reason}</td>
      <td className="px-4 py-2">
        <span className="px-2 py-1 text-xs rounded bg-red-500/20 text-red-400">
          {risk}
        </span>
      </td>
    </tr>
  );
}

function NewsItem({ text }: { text: string }) {
  return (
    <li className="px-4 py-3 hover:bg-slate-700/50 cursor-pointer">
      {text}
    </li>
  );
}
