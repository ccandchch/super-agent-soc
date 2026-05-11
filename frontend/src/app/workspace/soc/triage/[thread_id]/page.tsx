"use client";
import { useParams } from "next/navigation";
import { useQuery } from "@tanstack/react-query";

import { AlertSummary } from "@/components/soc/alert-summary";
import { TriageResultPanel } from "@/components/soc/triage-result";

interface AlertMeta {
  thread_id: string;
  alert_id: string;
  defense_line: string;
  alert_name: string;
  severity: string;
  created_at: string;
}

export default function TriagePage() {
  const params = useParams();
  const threadId = params.thread_id as string;

  const { data: alertMeta, isLoading } = useQuery<AlertMeta | null>({
    queryKey: ["soc", "alert-info", threadId],
    queryFn: async () => {
      const res = await fetch(`/api/soc/queue/alert-info/${threadId}`);
      if (res.status === 404) return null;
      if (!res.ok) throw new Error("Failed to fetch alert info");
      return res.json();
    },
  });

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      {isLoading ? (
        <div className="border-b px-4 py-2 text-sm text-muted-foreground">
          加载告警信息...
        </div>
      ) : alertMeta ? (
        <AlertSummary
          defenseLine={alertMeta.defense_line}
          alertName={alertMeta.alert_name}
          severity={alertMeta.severity}
          createdAt={alertMeta.created_at}
        />
      ) : (
        <div className="border-b px-4 py-2 text-sm text-muted-foreground">
          告警信息不可用
        </div>
      )}
      <div className="flex flex-1 overflow-hidden">
        <div className="flex-1 overflow-y-auto p-4">
          <p className="text-sm text-muted-foreground">
            Agent 研判对话流（复用 DeerFlow Chat 组件渲染 Thread 消息）
          </p>
        </div>
        <TriageResultPanel threadId={threadId} />
      </div>
    </div>
  );
}
