import { motion } from "framer-motion";

export default function StatisticCard({ label, value, icon: Icon, accent }) {
  return (
    <motion.article
      initial={{ opacity: 0, y: 14 }}
      animate={{ opacity: 1, y: 0 }}
      whileHover={{ y: -4, scale: 1.01 }}
      transition={{ duration: 0.28 }}
      className="rounded-2xl border border-white/70 bg-white/85 p-5 shadow-soft backdrop-blur"
    >
      <div className="flex items-center justify-between gap-4">
        <div>
          <p className="text-sm font-medium text-slate-500">{label}</p>
          <p className="mt-2 text-3xl font-semibold text-slate-950">{value}</p>
        </div>
        <div className={`grid h-12 w-12 place-items-center rounded-xl ${accent}`}>
          <Icon className="h-6 w-6" aria-hidden="true" />
        </div>
      </div>
    </motion.article>
  );
}
