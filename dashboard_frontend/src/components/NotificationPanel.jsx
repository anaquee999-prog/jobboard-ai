import { motion } from "framer-motion";
import { Bell } from "lucide-react";

function formatDate(value) {
  if (!value) return "";
  const date = new Date(String(value).replace(" ", "T"));
  if (Number.isNaN(date.getTime())) return value;
  return new Intl.DateTimeFormat("en", { dateStyle: "medium" }).format(date);
}

export default function NotificationPanel({ notifications }) {
  return (
    <motion.aside
      initial={{ opacity: 0, x: 16 }}
      animate={{ opacity: 1, x: 0 }}
      transition={{ duration: 0.32, delay: 0.16 }}
      className="rounded-2xl border border-white/70 bg-white p-5 shadow-soft"
    >
      <div className="flex items-center justify-between">
        <h2 className="text-lg font-semibold text-slate-950">Notifications</h2>
        <div className="grid h-10 w-10 place-items-center rounded-xl bg-indigo-100 text-indigo-700">
          <Bell className="h-5 w-5" aria-hidden="true" />
        </div>
      </div>
      <div className="mt-5 space-y-3">
        {notifications.map((item) => (
          <motion.div
            key={item.id}
            whileHover={{ x: 3 }}
            className="rounded-xl border border-slate-100 bg-slate-50 p-4 transition hover:border-indigo-100 hover:bg-indigo-50/60"
          >
            <div className="flex items-start justify-between gap-3">
              <p className="text-sm font-semibold text-slate-900">{item.title}</p>
              <span className="shrink-0 text-xs text-slate-400">{formatDate(item.created_at)}</span>
            </div>
            {item.message ? (
              <p className="mt-1 line-clamp-2 text-sm text-slate-500">{item.message}</p>
            ) : null}
          </motion.div>
        ))}
      </div>
    </motion.aside>
  );
}
