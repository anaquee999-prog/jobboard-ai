import { useEffect, useMemo, useState } from "react";
import {
  AlertTriangle,
  BarChart3,
  BellRing,
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

const endpoints = {
  scamStats: "/api/scam-stats",
  urgentJobs: "/api/urgent-jobs",
  trustDistribution: "/api/trust-distribution",
  communityReports: "/api/community-reports",
  discordTest: "/admin/discord-test",
};

const trustColors = ["#ef4444", "#f59e0b", "#14b8a6", "#22c55e", "#3b82f6"];
const reportColors = ["#ef4444", "#f59e0b", "#6366f1", "#14b8a6"];

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

export default function AdminDashboard() {
  const [dashboardData, setDashboardData] = useState({
    scamStats: null,
    urgentJobs: null,
    trustDistribution: [],
    communityReports: null,
  });
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [discordState, setDiscordState] = useState({
    loading: false,
    status: "",
    message: "",
  });

  async function loadDashboard() {
    setLoading(true);
    setError("");

    try {
      const [scamStats, urgentJobs, trustDistribution, communityReports] = await Promise.all([
        fetchJson(endpoints.scamStats, "Unable to load scam job stats"),
        fetchJson(endpoints.urgentJobs, "Unable to load urgent jobs"),
        fetchJson(endpoints.trustDistribution, "Unable to load trust score distribution"),
        fetchJson(endpoints.communityReports, "Unable to load community reports"),
      ]);

      setDashboardData({
        scamStats,
        urgentJobs,
        trustDistribution: normalizeTrustDistribution(trustDistribution),
        communityReports,
      });
    } catch (dashboardError) {
      setError(dashboardError.message);
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
                : "border-rose-200 bg-rose-50 text-rose-800"
            }`}
          >
            Discord webhook: {discordState.status}
            {discordState.message ? <span className="ml-2 font-normal">{discordState.message}</span> : null}
          </div>
        ) : null}

        {error ? (
          <div className="flex items-start gap-3 rounded-2xl border border-rose-200 bg-rose-50 px-4 py-3 text-sm font-medium text-rose-800 shadow-sm">
            <AlertTriangle className="mt-0.5 h-5 w-5 shrink-0" aria-hidden="true" />
            <span>{error}</span>
          </div>
        ) : null}

        <section className="grid gap-4 md:grid-cols-3">
          {metrics.map((metric) => (
            <MetricCard key={metric.title} {...metric} loading={loading} />
          ))}
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
      </div>
    </main>
  );
}
