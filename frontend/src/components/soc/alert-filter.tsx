"use client";

import { useState, useCallback } from "react";
import { Button } from "@/components/ui/button";
import { Separator } from "@/components/ui/separator";
import { cn } from "@/lib/utils";

const DEFENSE_LINES = [
  { key: "endpoint", label: "终端" },
  { key: "server", label: "服务器" },
  { key: "application", label: "应用" },
  { key: "network", label: "网络" },
  { key: "email", label: "邮件" },
  { key: "account", label: "账号" },
];

const SEVERITIES = [
  { key: "critical", label: "严重" },
  { key: "high", label: "高危" },
  { key: "medium", label: "中危" },
  { key: "low", label: "低危" },
  { key: "info", label: "信息" },
];

const TIME_RANGES = [
  { key: "1h", label: "最近 1 小时" },
  { key: "24h", label: "最近 24 小时" },
  { key: "7d", label: "最近 7 天" },
];

export interface AlertFilterValues {
  defense_lines: string[];
  severities: string[];
  time_range: string;
}

interface AlertFilterProps {
  onChange: (key: string, value: string | null) => void;
}

export function AlertFilter({ onChange }: AlertFilterProps) {
  const [defenseLines, setDefenseLines] = useState<string[]>([]);
  const [severities, setSeverities] = useState<string[]>([]);
  const [timeRange, setTimeRange] = useState<string>("24h");

  const toggleDefenseLine = useCallback(
    (key: string) => {
      setDefenseLines((prev) => {
        const next = prev.includes(key)
          ? prev.filter((k) => k !== key)
          : [...prev, key];
        onChange("defense_line", next.length > 0 ? next.join(",") : null);
        return next;
      });
    },
    [onChange],
  );

  const toggleSeverity = useCallback(
    (key: string) => {
      setSeverities((prev) => {
        const next = prev.includes(key)
          ? prev.filter((k) => k !== key)
          : [...prev, key];
        onChange("severity", next.length > 0 ? next.join(",") : null);
        return next;
      });
    },
    [onChange],
  );

  const selectTimeRange = useCallback(
    (key: string) => {
      setTimeRange(key);
      onChange("time_range", key);
    },
    [onChange],
  );

  return (
    <div className="flex flex-col gap-4 p-4">
      {/* Defense Lines */}
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">
          防线
        </h3>
        <div className="flex flex-col gap-1">
          {DEFENSE_LINES.map((dl) => (
            <label
              key={dl.key}
              className={cn(
                "flex items-center gap-2 px-2 py-1.5 rounded-md text-sm cursor-pointer transition-colors",
                "hover:bg-accent",
                defenseLines.includes(dl.key) && "bg-accent",
              )}
            >
              <input
                type="checkbox"
                className="size-3.5 rounded border-muted-foreground/30 accent-primary"
                checked={defenseLines.includes(dl.key)}
                onChange={() => toggleDefenseLine(dl.key)}
              />
              <span>{dl.label}</span>
            </label>
          ))}
        </div>
      </div>

      <Separator />

      {/* Severities */}
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">
          严重等级
        </h3>
        <div className="flex flex-col gap-1">
          {SEVERITIES.map((s) => (
            <label
              key={s.key}
              className={cn(
                "flex items-center gap-2 px-2 py-1.5 rounded-md text-sm cursor-pointer transition-colors",
                "hover:bg-accent",
                severities.includes(s.key) && "bg-accent",
              )}
            >
              <input
                type="checkbox"
                className="size-3.5 rounded border-muted-foreground/30 accent-primary"
                checked={severities.includes(s.key)}
                onChange={() => toggleSeverity(s.key)}
              />
              <span>{s.label}</span>
            </label>
          ))}
        </div>
      </div>

      <Separator />

      {/* Time Range */}
      <div>
        <h3 className="text-xs font-semibold text-muted-foreground mb-2 uppercase tracking-wider">
          时间范围
        </h3>
        <div className="flex flex-col gap-1">
          {TIME_RANGES.map((tr) => (
            <label
              key={tr.key}
              className={cn(
                "flex items-center gap-2 px-2 py-1.5 rounded-md text-sm cursor-pointer transition-colors",
                "hover:bg-accent",
                timeRange === tr.key && "bg-accent",
              )}
            >
              <input
                type="radio"
                name="time-range"
                className="size-3.5 border-muted-foreground/30 accent-primary"
                checked={timeRange === tr.key}
                onChange={() => selectTimeRange(tr.key)}
              />
              <span>{tr.label}</span>
            </label>
          ))}
        </div>
      </div>
    </div>
  );
}
