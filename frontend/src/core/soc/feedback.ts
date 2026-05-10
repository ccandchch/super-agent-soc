"use client";
import { useMutation } from "@tanstack/react-query";

export function useSubmitFeedback() {
  return useMutation({
    mutationFn: async (data: {
      result_id: string;
      action: "accepted" | "rejected" | "escalated";
      reject_reason?: string; comment?: string;
    }) => {
      const res = await fetch("/api/soc/feedback", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(data),
      });
      if (!res.ok) throw new Error("Failed to submit feedback");
      return res.json();
    },
  });
}
