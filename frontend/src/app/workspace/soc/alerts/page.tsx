"use client";

import { useCallback, useMemo, useState } from "react";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { AlertCard } from "@/components/soc/alert-card";
import { AlertFilter } from "@/components/soc/alert-filter";
import { QueueStats } from "@/components/soc/queue-stats";
import { useAlerts } from "@/core/soc/alerts";

export default function AlertsPage() {
  const [filters, setFilters] = useState<Record<string, string>>({});

  const handleFilterChange = useCallback(
    (key: string, value: string | null) => {
      setFilters((prev) => {
        const next = { ...prev };
        if (value === null) {
          delete next[key];
        } else {
          next[key] = value;
        }
        return next;
      });
    },
    [],
  );

  const queryFilters = useMemo(() => {
    const q: Record<string, string> = {};
    if (filters.defense_line) q.defense_line = filters.defense_line;
    if (filters.severity) q.severity = filters.severity;
    if (filters.time_range) q.time_range = filters.time_range;
    return q;
  }, [filters]);

  const { data, isLoading } = useAlerts(queryFilters);
  const alerts = data?.alerts ?? [];

  return (
    <div className="flex h-full">
      {/* Left filter sidebar */}
      <aside className="w-56 shrink-0 border-r bg-background flex flex-col">
        <div className="flex h-10 items-center px-4 border-b">
          <span className="text-xs font-semibold text-muted-foreground uppercase tracking-wider">
            筛选
          </span>
        </div>
        <ScrollArea className="flex-1">
          <AlertFilter onChange={handleFilterChange} />
        </ScrollArea>
      </aside>

      {/* Main content area */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Header bar */}
        <div className="flex h-10 shrink-0 items-center justify-between border-b px-4">
          <h1 className="text-sm font-semibold">告警工作台</h1>
          <QueueStats />
        </div>

        {/* Alert list */}
        <ScrollArea className="flex-1">
          <div className="p-4">
            {isLoading && alerts.length === 0 && (
              <div className="flex flex-col gap-2">
                {Array.from({ length: 5 }).map((_, i) => (
                  <div
                    key={i}
                    className="h-14 rounded-lg border bg-muted/30 animate-pulse"
                  />
                ))}
              </div>
            )}

            {!isLoading && alerts.length === 0 && (
              <div className="flex items-center justify-center h-64 text-sm text-muted-foreground">
                暂无告警数据
              </div>
            )}

            {alerts.length > 0 && (
              <div className="flex flex-col gap-2">
                {alerts.map((alert) => (
                  <AlertCard key={alert.id} alert={alert} />
                ))}
              </div>
            )}
          </div>
        </ScrollArea>
      </div>
    </div>
  );
}
