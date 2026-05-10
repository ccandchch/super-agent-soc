"use client";
import { useQuery } from "@tanstack/react-query";

export interface TriageResult {
  result_id: string; verdict: string; confidence: number;
  confidence_level: string; severity: string; summary: string;
  evidence_timeline: { step: number; name: string; tool: string; finding: string }[];
  action_suggestion: { primary: string; params: Record<string, string>; rationale: string } | null;
  uncertainties: string[];
}

export function useTriageResult(threadId: string) {
  return useQuery({
    queryKey: ["soc", "triage", threadId],
    queryFn: async () => {
      const res = await fetch(`/api/soc/results/${threadId}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new Error("Failed to fetch triage result");
      return res.json() as Promise<TriageResult>;
    },
    refetchInterval: 10_000,
  });
}
