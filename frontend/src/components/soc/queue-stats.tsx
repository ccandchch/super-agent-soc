"use client";

import { Badge } from "@/components/ui/badge";
import { useQueueStatus } from "@/core/soc/queue";
import { cn } from "@/lib/utils";

const severityColorMap: Record<string, string> = {
  critical: "bg-red-600",
  high: "bg-orange-500",
  medium: "bg-yellow-500",
  low: "bg-blue-500",
  info: "bg-gray-400",
};

export function QueueStats() {
  const { data, isLoading } = useQueueStatus();

  return (
    <Badge
      variant="outline"
      className={cn(
        "gap-1.5 text-xs",
        isLoading && "animate-pulse",
      )}
    >
      <span className="text-muted-foreground">队列深度</span>
      <span className="font-mono font-semibold tabular-nums">
        {isLoading ? "—" : data?.depth ?? 0}
      </span>
    </Badge>
  );
}
