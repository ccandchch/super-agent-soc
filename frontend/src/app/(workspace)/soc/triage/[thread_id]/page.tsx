"use client";
import { useParams } from "next/navigation";

import { AlertSummary } from "@/components/soc/alert-summary";
import { TriageResultPanel } from "@/components/soc/triage-result";

export default function TriagePage() {
  const params = useParams();
  const threadId = params.thread_id as string;

  return (
    <div className="flex flex-col flex-1 overflow-hidden">
      <AlertSummary defenseLine="endpoint" alertName="Endpoint_Abnormal_Process_Outbound"
        severity="high" createdAt="2026-05-10T14:32:00Z" />
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
