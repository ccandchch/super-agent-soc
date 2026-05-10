"use client";

import Link from "next/link";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent } from "@/components/ui/card";
import type { AlertItem } from "@/core/soc/alerts";
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

function getMainEntity(entities: AlertItem["entities"]): string | null {
  if (!entities || entities.length === 0) return null;
  const ip = entities.find((e) => e.type === "ip");
  if (ip) return ip.value;
  const host = entities.find((e) => e.type === "hostname");
  if (host) return host.value;
  return entities[0]?.value ?? "—";
}

export function AlertCard({ alert }: { alert: AlertItem }) {
  const severityColor = SEVERITY_COLORS[alert.severity] ?? "bg-gray-400";
  const severityLabel = SEVERITY_LABELS[alert.severity] ?? alert.severity;
  const defenseLabel =
    DEFENSE_LINE_LABELS[alert.defense_line] ?? alert.defense_line;
  const mainEntity = getMainEntity(alert.entities);
  const isAggregated =
    alert.aggregation !== null && alert.aggregation !== undefined;

  return (
    <Link href={`/workspace/soc/triage/${alert.id}`}>
      <Card
        className={cn(
          "hover:bg-accent/50 transition-colors cursor-pointer",
          "border-l-4",
        )}
        style={{ borderLeftColor: severityColor }}
      >
        <CardContent className="flex items-center gap-3 px-4 py-3">
          {/* Severity dot + label */}
          <div className="flex items-center gap-1.5 shrink-0">
            <span
              className={cn("size-2 rounded-full", severityColor)}
              aria-hidden="true"
            />
            <span className="text-xs font-medium">{severityLabel}</span>
          </div>

          {/* Defense line */}
          <Badge variant="secondary" className="shrink-0 text-xs">
            {defenseLabel}
          </Badge>

          {/* Alert name */}
          <span className="font-mono text-sm truncate min-w-0 flex-1">
            {alert.alert_name}
          </span>

          {/* Main entity */}
          {mainEntity && (
            <span className="text-xs text-muted-foreground shrink-0 truncate max-w-[200px]">
              {mainEntity}
            </span>
          )}

          {/* Aggregation badge */}
          {isAggregated && (
            <Badge variant="outline" className="shrink-0 text-[10px]">
              聚合
            </Badge>
          )}
        </CardContent>
      </Card>
    </Link>
  );
}
