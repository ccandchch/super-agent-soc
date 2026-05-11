"use client";

import { useQueueStatus } from "@/core/soc/queue";

export default function DashboardPage() {
  const { data: queue } = useQueueStatus();

  return (
    <div className="p-6 space-y-6">
      <h1 className="text-xl font-semibold">运营仪表盘</h1>

      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="队列积压" value={queue?.depth ?? "—"} />
        <MetricCard label="今日已处置" value="—" />
        <MetricCard label="Agent 准确率" value="—" />
        <MetricCard label="平均研判耗时" value="—" />
      </div>

      <div className="grid grid-cols-2 gap-4">
        <div className="border rounded-lg p-4">
          <h2 className="text-sm font-medium mb-2">系统健康</h2>
          <div className="space-y-2 text-sm text-muted-foreground">
            <div className="flex justify-between">
              <span>Ingestion 服务</span>
              <span className="text-green-600">● 正常</span>
            </div>
            <div className="flex justify-between">
              <span>Dispatcher</span>
              <span className="text-green-600">● 运行中</span>
            </div>
            <div className="flex justify-between">
              <span>Memory-SOC</span>
              <span className="text-yellow-600">● 未启动</span>
            </div>
            <div className="flex justify-between">
              <span>MCP Servers</span>
              <span className="text-yellow-600">● 未启动</span>
            </div>
          </div>
        </div>

        <div className="border rounded-lg p-4">
          <h2 className="text-sm font-medium mb-2">研判质量</h2>
          <p className="text-sm text-muted-foreground">
            Agent 编排层实现后启用
          </p>
        </div>
      </div>
    </div>
  );
}

function MetricCard({ label, value }: { label: string; value: string | number }) {
  return (
    <div className="border rounded-lg p-4">
      <p className="text-xs text-muted-foreground">{label}</p>
      <p className="text-2xl font-mono font-bold mt-1">{value}</p>
    </div>
  );
}
