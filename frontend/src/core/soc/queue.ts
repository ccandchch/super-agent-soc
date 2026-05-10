"use client";
import { useQuery } from "@tanstack/react-query";

export function useQueueStatus() {
  return useQuery({
    queryKey: ["soc", "queue", "status"],
    queryFn: async () => {
      const res = await fetch("/api/soc/queue/status");
      if (!res.ok) throw new Error("Failed to fetch queue status");
      return res.json() as Promise<{ depth: number }>;
    },
    refetchInterval: 5_000,
  });
}
