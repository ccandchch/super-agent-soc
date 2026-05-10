"use client";

import { Badge } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

const DEFENSE_LINE_LABELS: Record<string, string> = {
  endpoint: "终端",
  server: "服务器",
  application: "应用",
  network: "网络",
  email: "邮件",
  account: "账号",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-400",
};

const SEVERITY_LABELS: Record<string, string> = {
  critical: "严重",
  high: "高危",
  medium: "中危",
  low: "低危",
  info: "信息",
};

interface AlertSummaryProps {
  defenseLine: string;
  alertName: string;
  severity: string;
  createdAt: string;
}

function formatTime(iso: string): string {
  try {
    const d = new Date(iso);
    return d.toLocaleString("zh-CN", {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return iso;
  }
}

export function AlertSummary({
  defenseLine,
  alertName,
  severity,
  createdAt,
}: AlertSummaryProps) {
  const defenseLabel =
    DEFENSE_LINE_LABELS[defenseLine] ?? defenseLine;
  const severityColor = SEVERITY_COLORS[severity] ?? "bg-gray-400";
  const severityLabel = SEVERITY_LABELS[severity] ?? severity;

  return (
    <div className="flex h-12 shrink-0 items-center gap-3 border-b px-4 bg-background">
      {/* Defense line badge */}
      <Badge variant="secondary" className="shrink-0 text-xs">
        {defenseLabel}
      </Badge>

      {/* Alert name */}
      <span className="font-mono text-sm font-semibold truncate">
        {alertName}
      </span>

      {/* Severity badge */}
      <div className="flex items-center gap-1.5 shrink-0">
        <span
          className={cn("size-2 rounded-full", severityColor)}
          aria-hidden="true"
        />
        <span className="text-xs font-medium">{severityLabel}</span>
      </div>

      {/* Spacer */}
      <div className="flex-1" />

      {/* Created at */}
      <span className="text-xs text-muted-foreground shrink-0">
        {formatTime(createdAt)}
      </span>
    </div>
  );
}
