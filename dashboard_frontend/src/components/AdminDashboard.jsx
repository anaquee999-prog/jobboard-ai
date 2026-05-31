import { lazy, Suspense, useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  BellRing,
  BriefcaseBusiness,
  Loader2,
  MessageSquareWarning,
  RefreshCw,
  Send,
  ShieldAlert,
  Zap,
} from "lucide-react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const AnimatedSphere = lazy(() => import("./AnimatedSphere"));

const endpoints = {
  scamStats: "/api/scam-stats",
  jobs: "/api/jobs",
  urgentJobs: "/api/urgent-jobs",
  trustDistribution: "/api/trust-distribution",
  communityReports: "/api/community-reports",
  discordTest: "/admin/discord-test",
};

const demoDashboardData = {
  scamStats: {
    scam_jobs: 7,
    total_jobs: 80,
    urgent_jobs: 12,
    community_reports: 18,
  },
  urgentJobs: {
    count: 12,
    jobs: [
      { id: 1, title: "Urgent Frontend Developer", trust_score: 92 },
      { id: 2, title: "Customer Support Officer", trust_score: 84 },
      { id: 3, title: "Warehouse Coordinator", trust_score: 79 },
    ],
  },
  trustDistribution: [
    { range: "0-39", count: 7 },
    { range: "40-59", count: 11 },
    { range: "60-79", count: 24 },
    { range: "80-100", count: 38 },
  ],
  communityReports: {
    reports: [
      { status: "pending", count: 8 },
      { status: "reviewed", count: 6 },
      { status: "resolved", count: 4 },
    ],
  },
  jobs: [],
};

const trustColors = ["#ef4444", "#f59e0b", "#14b8a6", "#22c55e", "#3b82f6"];
const reportColors = ["#ef4444", "#f59e0b", "#6366f1", "#14b8a6"];

function isStaticGitHubPages() {
  return window.location.hostname.endsWith("github.io");
}

async function fetchJson(url, errorMessage, options) {
  const response = await fetch(url, options);
  let payload = null;

  try {
    payload = await response.json();
  } catch {
    payload = null;
  }

  if (!response.ok) {
    throw new Error(payload?.message || payload?.error || errorMessage);
  }

  return payload;
}

function toNumber(value) {
  const numberValue = Number(value);
  return Number.isFinite(numberValue) ? numberValue : 0;
}

function pickCount(payload, keys = []) {
  if (typeof payload === "number") return payload;
  if (Array.isArray(payload)) return payload.length;

  for (const key of keys) {
    if (payload?.[key] !== undefined) return toNumber(payload[key]);
  }

  if (Array.isArray(payload?.items)) return payload.items.length;
  if (Array.isArray(payload?.reports)) return payload.reports.length;
  if (Array.isArray(payload?.jobs)) return payload.jobs.length;

  return 0;
}

function normalizeTrustDistribution(payload) {
  const source = payload?.distribution || payload?.items || payload?.data || payload || [];

  if (Array.isArray(source)) {
    return source.map((item, index) => ({
      range: item.range || item.label || item.bucket || item.score_range || `Bucket ${index + 1}`,
      count: toNumber(item.count || item.total || item.value),
    }));
  }

  return Object.entries(source).map(([range, count]) => ({
    range,
    count: toNumber(count),
  }));
}

function normalizeCommunityReports(payload) {
  const source = payload?.by_status || payload?.distribution || payload?.items || payload?.reports || payload || [];

  if (Array.isArray(source)) {
    const grouped = source.reduce((acc, item) => {
      const status = item.status || item.type || item.category || "reported";
      acc[status] = (acc[status] || 0) + toNumber(item.count || item.total || item.value || 1);
      return acc;
    }, {});

    return Object.entries(grouped).map(([status, count]) => ({ status, count }));
  }

  return Object.entries(source).map(([status, count]) => ({
    status,
    count: toNumber(count),
  }));
}

function normalizeJobs(payload) {
  const source = payload?.items || payload?.jobs || payload?.data || payload || [];
  return Array.isArray(source) ? source : [];
}

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("th-TH", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

function MetricCard({ title, value, icon: Icon, tone, loading }) {
  return (
    <article className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
      <div className="flex items-center justify-between gap-4">
        <div className="min-w-0">
          <p className="text-sm font-medium text-slate-500">{title}</p>
          <p className="mt-3 text-3xl font-semibold text-slate-950">
            {loading ? "..." : new Intl.NumberFormat("en").format(value)}
          </p>
        </div>
        <div className={`grid h-12 w-12 shrink-0 place-items-center rounded-xl ${tone}`}>
          <Icon className="h-6 w-6" aria-hidden="true" />
        </div>
      </div>
    </article>
  );
}

function ChartCard({ title, icon: Icon, children }) {
  return (
    <section className="rounded-2xl border border-slate-200 bg-white p-5 shadow-soft">
      <div className="mb-5 flex items-center justify-between gap-3">
        <h2 className="text-base font-semibold text-slate-950 sm:text-lg">{title}</h2>
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-slate-100 text-slate-700">
          <Icon className="h-5 w-5" aria-hidden="true" />
        </div>
      </div>
      <div className="h-72 w-full">{children}</div>
    </section>
  );
}

function RecentJobsTable({ jobs }) {
  return (
    <section className="overflow-hidden rounded-2xl border border-slate-200 bg-white shadow-soft">
      <div className="flex items-center justify-between gap-3 border-b border-slate-200 px-5 py-4">
        <div>
          <h2 className="text-base font-semibold text-slate-950 sm:text-lg">Recent Jobs</h2>
          <p className="mt-1 text-sm text-slate-500">{jobs.length} latest listings from Flask API</p>
        </div>
        <div className="grid h-10 w-10 shrink-0 place-items-center rounded-xl bg-emerald-100 text-emerald-700">
          <BriefcaseBusiness className="h-5 w-5" aria-hidden="true" />
        </div>
      </div>

      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200">
          <thead className="bg-slate-50">
            <tr>
              {["Job", "Company", "Location", "Trust", "Risk", "Date"].map((heading) => (
                <th
                  key={heading}
                  className="px-5 py-3 text-left text-xs font-semibold uppercase tracking-wide text-slate-500"
                >
                  {heading}
                </th>
              ))}
            </tr>
          </thead>
          <tbody className="divide-y divide-slate-100 bg-white">
            {jobs.map((job) => (
              <tr key={job.id || job.slug || job.title} className="transition hover:bg-slate-50">
                <td className="min-w-80 px-5 py-4">
                  <p className="line-clamp-2 text-sm font-semibold text-slate-950">{job.title || "-"}</p>
                  <p className="mt-1 text-xs text-slate-500">#{job.id || "-"}</p>
                </td>
                <td className="min-w-64 px-5 py-4 text-sm text-slate-600">{job.company_name || job.company || "-"}</td>
                <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-600">{job.location || "-"}</td>
                <td className="whitespace-nowrap px-5 py-4 text-sm font-semibold text-emerald-700">
                  {job.trust_score ?? "-"}
                </td>
                <td className="whitespace-nowrap px-5 py-4">
                  <span className="inline-flex rounded-full bg-emerald-50 px-3 py-1 text-xs font-semibold text-emerald-700 ring-1 ring-emerald-100">
                    {job.risk_level || "LOW"}
                  </span>
                </td>
                <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-500">
                  {formatDate(job.created_at || job.date)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {jobs.length === 0 ? (
        <div className="px-5 py-8 text-center text-sm font-medium text-slate-500">No jobs found from /api/jobs.</div>
      ) : null}
    </section>
  );
}

export default function AdminDashboard() {
  const [dashboardData, setDashboardData] = useState({
    scamStats: null,
    jobs: [],
    urgentJobs: null,
    trustDistribution: [],
    communityReports: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [demoMode, setDemoMode] = useState(false);
  const [discordState, setDiscordState] = useState({
    loading: false,
    status: "",
    message: "",
  });

  async function loadDashboard() {
    setLoading(true);
    setError("");
    setDemoMode(false);

    try {
      const [scamStats, jobs, urgentJobs, trustDistribution, communityReports] = await Promise.all([
        fetchJson(endpoints.scamStats, "Unable to load scam job stats"),
        fetchJson(endpoints.jobs, "Unable to load jobs"),
        fetchJson(endpoints.urgentJobs, "Unable to load urgent jobs"),
        fetchJson(endpoints.trustDistribution, "Unable to load trust score distribution"),
        fetchJson(endpoints.communityReports, "Unable to load community reports"),
      ]);

      setDashboardData({
        scamStats,
        jobs: normalizeJobs(jobs),
        urgentJobs,
        trustDistribution: normalizeTrustDistribution(trustDistribution),
        communityReports,
      });
    } catch (dashboardError) {
      if (isStaticGitHubPages()) {
        setDemoMode(true);
        setDashboardData(demoDashboardData);
      } else {
        setError(dashboardError.message);
      }
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    loadDashboard();
  }, []);

  const metrics = useMemo(
    () => [
      {
        title: "Scam Jobs",
        value: pickCount(dashboardData.scamStats, ["scam_jobs", "scam_count", "count", "total"]),
        icon: ShieldAlert,
        tone: "bg-rose-100 text-rose-700",
      },
      {
        title: "Urgent Jobs",
        value: pickCount(dashboardData.urgentJobs, ["urgent_jobs", "urgent_count", "count", "total"]),
        icon: Zap,
        tone: "bg-amber-100 text-amber-700",
      },
      {
        title: "Community Reports",
        value: pickCount(dashboardData.communityReports, [
          "community_reports",
          "report_count",
          "count",
          "total",
        ]),
        icon: MessageSquareWarning,
        tone: "bg-indigo-100 text-indigo-700",
      },
    ],
    [dashboardData],
  );

  const reportDistribution = useMemo(
    () => normalizeCommunityReports(dashboardData.communityReports),
    [dashboardData.communityReports],
  );

  async function testDiscordWebhook() {
    setDiscordState({ loading: true, status: "", message: "" });

    if (isStaticGitHubPages()) {
      setDiscordState({
        loading: false,
        status: "DEMO",
        message: "Static GitHub Pages demo mode. Run the Flask backend to send a real Discord alert.",
      });
      return;
    }

    try {
      const result = await fetchJson(endpoints.discordTest, "Discord webhook test failed", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
      });

      setDiscordState({
        loading: false,
        status: "OK",
        message: result?.message || "Discord webhook is reachable.",
      });
    } catch (discordError) {
      setDiscordState({
        loading: false,
        status: "ERROR",
        message: discordError.message,
      });
    }
  }

  return (
    <main className="min-h-screen bg-slate-100 text-slate-950">
      <div className="mx-auto flex w-full max-w-7xl flex-col gap-6 px-4 py-6 sm:px-6 lg:px-8">
        <header className="flex flex-col gap-4 rounded-2xl border border-slate-800 bg-slate-950 px-5 py-6 text-white shadow-soft sm:px-7 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-medium text-cyan-200">JobBoard AI Anti-Scam</p>
            <h1 className="mt-2 text-3xl font-semibold sm:text-4xl">Admin Dashboard</h1>
          </div>
          <div className="flex flex-col gap-3 sm:flex-row sm:items-center">
            <button
              type="button"
              onClick={loadDashboard}
              disabled={loading}
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-white px-4 py-2 text-sm font-semibold text-slate-950 shadow-sm transition hover:bg-cyan-50 disabled:cursor-not-allowed disabled:opacity-60"
            >
              <RefreshCw className={`h-4 w-4 ${loading ? "animate-spin" : ""}`} aria-hidden="true" />
              Refresh
            </button>
            <button
              type="button"
              onClick={testDiscordWebhook}
              disabled={discordState.loading}
              className="inline-flex min-h-11 items-center justify-center gap-2 rounded-xl bg-cyan-400 px-4 py-2 text-sm font-semibold text-slate-950 shadow-sm transition hover:bg-cyan-300 disabled:cursor-not-allowed disabled:opacity-60"
            >
              {discordState.loading ? (
                <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />
              ) : (
                <Send className="h-4 w-4" aria-hidden="true" />
              )}
              Test Discord
            </button>
          </div>
        </header>

        {discordState.status ? (
          <div
            className={`rounded-2xl border px-4 py-3 text-sm font-medium shadow-sm ${
              discordState.status === "OK"
                ? "border-emerald-200 bg-emerald-50 text-emerald-800"
                : discordState.status === "DEMO"
                  ? "border-cyan-200 bg-cyan-50 text-cyan-800"
                : "border-rose-200 bg-rose-50 text-rose-800"
            }`}
          >
            Discord webhook: {discordState.status}
            {discordState.message ? <span className="ml-2 font-normal">{discordState.message}</span> : null}
          </div>
        ) : null}

        {demoMode ? (
          <div className="rounded-2xl border border-cyan-200 bg-cyan-50 px-4 py-3 text-sm font-medium text-cyan-800 shadow-sm">
            Static demo mode: GitHub Pages cannot run Flask API endpoints. The dashboard is showing sample data.
          </div>
        ) : null}

        {error ? (
          <div className="flex items-start gap-3 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-800 shadow-sm">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        ) : null}

        <section className="grid gap-6 lg:grid-cols-[1.7fr,1fr]">
          <div className="rounded-3xl border border-slate-200 bg-slate-950 p-5 shadow-soft ring-1 ring-white/10">
            <div className="mb-4 flex items-center justify-between gap-3">
              <div>
                <p className="text-sm font-medium uppercase tracking-[0.3em] text-cyan-300/90">
                  Interactive 3D Insight
                </p>
                <h2 className="mt-2 text-xl font-semibold text-white">Trust Sphere</h2>
              </div>
              <span className="rounded-2xl bg-white/10 px-3 py-2 text-sm font-semibold text-white shadow-sm">
                Live animation
              </span>
            </div>
            <div className="h-[260px] w-full overflow-hidden rounded-[2rem] bg-slate-900">
              <Suspense fallback={<div className="h-full w-full bg-slate-900" />}>
                <AnimatedSphere />
              </Suspense>
            </div>
          </div>

          <section className="grid gap-4 md:grid-cols-3">
            {metrics.map((metric) => (
              <MetricCard key={metric.title} {...metric} loading={loading} />
            ))}
          </section>
        </section>

        {loading ? (
          <section className="grid min-h-72 place-items-center rounded-2xl border border-slate-200 bg-white p-8 text-center shadow-soft">
            <div>
              <Loader2 className="mx-auto h-8 w-8 animate-spin text-cyan-600" aria-hidden="true" />
              <p className="mt-3 text-sm font-medium text-slate-500">Loading dashboard data...</p>
            </div>
          </section>
        ) : (
          <section className="grid gap-6 lg:grid-cols-2">
            <ChartCard title="Trust Score Distribution" icon={BarChart3}>
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={dashboardData.trustDistribution} margin={{ top: 8, right: 8, bottom: 12, left: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#e2e8f0" />
                  <XAxis dataKey="range" tick={{ fill: "#475569", fontSize: 12 }} />
                  <YAxis allowDecimals={false} tick={{ fill: "#475569", fontSize: 12 }} />
                  <Tooltip />
                  <Bar dataKey="count" name="Jobs" radius={[8, 8, 0, 0]}>
                    {dashboardData.trustDistribution.map((entry, index) => (
                      <Cell key={entry.range} fill={trustColors[index % trustColors.length]} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </ChartCard>

            <ChartCard title="Community Reports" icon={BellRing}>
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={reportDistribution}
                    dataKey="count"
                    nameKey="status"
                    cx="50%"
                    cy="50%"
                    innerRadius={58}
                    outerRadius={96}
                    paddingAngle={3}
                    label
                  >
                    {reportDistribution.map((entry, index) => (
                      <Cell key={entry.status} fill={reportColors[index % reportColors.length]} />
                    ))}
                  </Pie>
                  <Tooltip />
                  <Legend />
                </PieChart>
              </ResponsiveContainer>
            </ChartCard>
          </section>
        )}

        {!loading ? <RecentJobsTable jobs={dashboardData.jobs.slice(0, 10)} /> : null}
      </div>
    </main>
  );
}
