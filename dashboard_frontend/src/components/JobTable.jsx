import { motion } from "framer-motion";

const badgeStyles = {
  HIGH: "bg-rose-100 text-rose-700 ring-rose-200",
  MEDIUM: "bg-amber-100 text-amber-700 ring-amber-200",
  LOW: "bg-emerald-100 text-emerald-700 ring-emerald-200",
};

function formatDate(value) {
  if (!value) return "-";
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en", {
    dateStyle: "medium",
    timeStyle: "short",
  }).format(date);
}

export default function JobTable({ jobs }) {
  return (
    <motion.section
      initial={{ opacity: 0, y: 16 }}
      animate={{ opacity: 1, y: 0 }}
      transition={{ duration: 0.32, delay: 0.08 }}
      className="overflow-hidden rounded-2xl border border-white/70 bg-white shadow-soft"
    >
      <div className="border-b border-slate-200 px-5 py-4">
        <h2 className="text-lg font-semibold text-slate-950">Job Table</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full divide-y divide-slate-200">
          <thead className="bg-slate-50">
            <tr>
              {["ID", "Title", "Risk Level", "Date"].map((heading) => (
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
              <tr key={job.id} className="transition hover:bg-slate-50">
                <td className="whitespace-nowrap px-5 py-4 text-sm font-medium text-slate-700">
                  #{job.id}
                </td>
                <td className="min-w-64 px-5 py-4 text-sm font-semibold text-slate-950">
                  {job.title}
                </td>
                <td className="whitespace-nowrap px-5 py-4">
                  <span
                    className={`inline-flex rounded-full px-3 py-1 text-xs font-semibold ring-1 ${
                      badgeStyles[job.risk_level] || badgeStyles.LOW
                    }`}
                  >
                    {job.risk_level}
                  </span>
                </td>
                <td className="whitespace-nowrap px-5 py-4 text-sm text-slate-500">
                  {formatDate(job.date)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </motion.section>
  );
}
