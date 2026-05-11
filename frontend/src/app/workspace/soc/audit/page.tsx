"use client";

import { useQuery } from "@tanstack/react-query";

export default function AuditPage() {
  const { data, isLoading, refetch } = useQuery<{ lines: string[] }>({
    queryKey: ["soc", "audit"],
    queryFn: async () => {
      const res = await fetch("/api/soc/queue/audit?lines=200");
      return res.json();
    },
    refetchInterval: 10_000,
  });

  return (
    <div className="p-6 space-y-4">
      <div className="flex items-center justify-between">
        <h1 className="text-xl font-semibold">审计日志</h1>
        <button
          className="text-sm border rounded px-3 py-1"
          onClick={() => refetch()}
        >
          刷新
        </button>
      </div>

      <div className="border rounded-lg bg-black text-green-400 p-4 font-mono text-xs h-[600px] overflow-y-auto whitespace-pre-wrap">
        {isLoading
          ? "加载中..."
          : data?.lines?.join("\n") || "无日志"}
      </div>
    </div>
  );
}
