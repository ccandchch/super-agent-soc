"use client";
import { useQuery } from "@tanstack/react-query";

export interface AlertItem {
  id: string;
  defense_line: string;
  alert_name: string;
  severity: string;
  type: string;
  entities: { type: string; value: string }[];
  fingerprint: string;
  alarm_id: string | null;
  aggregation: Record<string, unknown> | null;
  created_at: string;
}

export function useAlerts(filters?: Record<string, string>) {
  return useQuery({
    queryKey: ["soc", "alerts", filters],
    queryFn: async () => {
      const params = new URLSearchParams(filters ?? {});
      const res = await fetch(`/api/soc/queue/alerts?${params}`);
      if (!res.ok) throw new Error("Failed to fetch alerts");
      return res.json() as Promise<{ alerts: AlertItem[]; total: number }>;
    },
    refetchInterval: 10_000,
  });
}
