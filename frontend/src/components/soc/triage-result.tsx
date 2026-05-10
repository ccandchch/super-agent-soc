"use client";

import { useState } from "react";

import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useSubmitFeedback } from "@/core/soc/feedback";
import { useTriageResult } from "@/core/soc/triage";
import { cn } from "@/lib/utils";

const VERDICT_CONFIG: Record<string, { label: string; color: string }> = {
  malicious: { label: "恶意", color: "text-red-600" },
  false_positive: { label: "误报", color: "text-green-600" },
  benign_anomaly: { label: "良性异常", color: "text-blue-600" },
  uncertain: { label: "不确定", color: "text-yellow-600" },
};

function getVerdictConfig(verdict: string) {
  return VERDICT_CONFIG[verdict] ?? { label: verdict, color: "text-foreground" };
}

export function TriageResultPanel({ threadId }: { threadId: string }) {
  const { data: result, isLoading, isError } = useTriageResult(threadId);
  const submitFeedback = useSubmitFeedback();
  const [feedbackSubmitted, setFeedbackSubmitted] = useState<string | null>(null);

  const handleAction = (action: "accepted" | "rejected" | "escalated") => {
    if (!result) return;
    submitFeedback.mutate(
      { result_id: result.result_id, action },
      {
        onSuccess: () => {
          setFeedbackSubmitted(action);
        },
      },
    );
  };

  return (
    <div className="w-80 shrink-0 border-l bg-card flex flex-col">
      {/* Panel header */}
      <div className="flex h-10 shrink-0 items-center border-b px-4">
        <h2 className="text-sm font-semibold">研判结果</h2>
      </div>

      <ScrollArea className="flex-1">
        <div className="p-4">
          {/* Loading state */}
          {isLoading && (
            <div className="flex items-center justify-center h-32 text-sm text-muted-foreground animate-pulse">
              加载研判结果...
            </div>
          )}

          {/* Error state */}
          {isError && (
            <div className="flex items-center justify-center h-32 text-sm text-red-500">
              加载失败，请重试
            </div>
          )}

          {/* Waiting state */}
          {!isLoading && !isError && !result && (
            <div className="flex items-center justify-center h-32 text-sm text-muted-foreground">
              等待研判完成...
            </div>
          )}

          {/* Result exists */}
          {result && (
            <div className="flex flex-col gap-4">
              {/* Verdict */}
              <Card>
                <CardHeader className="pb-2">
                  <CardTitle className="text-xs font-medium text-muted-foreground">
                    研判结论
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {(() => {
                    const vc = getVerdictConfig(result.verdict);
                    return (
                      <span className={cn("text-lg font-bold", vc.color)}>
                        {vc.label}
                      </span>
                    );
                  })()}
                </CardContent>
              </Card>

              {/* Confidence */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">置信度</span>
                <span className="font-mono text-sm font-semibold">
                  {(result.confidence * 100).toFixed(0)}%
                </span>
                <Badge variant="outline" className="text-[10px]">
                  {result.confidence_level}
                </Badge>
              </div>

              {/* Severity */}
              <div className="flex items-center gap-2">
                <span className="text-xs text-muted-foreground">严重等级</span>
                <Badge variant="secondary" className="text-xs">
                  {result.severity}
                </Badge>
              </div>

              <Separator />

              {/* Summary */}
              <div>
                <h3 className="text-xs font-medium text-muted-foreground mb-1">
                  概述
                </h3>
                <p className="text-sm leading-relaxed">{result.summary}</p>
              </div>

              {/* Uncertainties */}
              {result.uncertainties && result.uncertainties.length > 0 && (
                <div>
                  <h3 className="text-xs font-medium text-muted-foreground mb-1">
                    不确定因素
                  </h3>
                  <ul className="list-disc list-inside text-sm text-yellow-600 space-y-0.5">
                    {result.uncertainties.map((u, i) => (
                      <li key={i}>{u}</li>
                    ))}
                  </ul>
                </div>
              )}

              <Separator />

              {/* Evidence Timeline */}
              {result.evidence_timeline &&
                result.evidence_timeline.length > 0 && (
                  <div>
                    <h3 className="text-xs font-medium text-muted-foreground mb-2">
                      研判依据
                    </h3>
                    <ol className="list-decimal list-inside text-sm space-y-2">
                      {result.evidence_timeline.map((step) => (
                        <li key={step.step} className="text-sm">
                          <span className="font-medium">{step.name}</span>
                          <span className="text-muted-foreground">
                            {" "}
                            · {step.tool}
                          </span>
                          <p className="text-xs text-muted-foreground mt-0.5 ml-5">
                            {step.finding}
                          </p>
                        </li>
                      ))}
                    </ol>
                  </div>
                )}

              <Separator />

              {/* Action Suggestion */}
              {result.action_suggestion && (
                <Card className="border-blue-200 bg-blue-50 dark:bg-blue-950/20">
                  <CardHeader className="pb-1">
                    <CardTitle className="text-xs font-medium text-blue-700 dark:text-blue-400">
                      建议动作
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <p className="text-sm font-semibold text-blue-800 dark:text-blue-300">
                      {result.action_suggestion.primary}
                    </p>
                    <p className="text-xs text-blue-600/70 dark:text-blue-400/70 mt-1">
                      {result.action_suggestion.rationale}
                    </p>
                  </CardContent>
                </Card>
              )}

              <Separator />

              {/* Feedback confirmation */}
              {feedbackSubmitted && (
                <div
                  className={cn(
                    "text-center text-sm font-medium py-2 rounded-md",
                    feedbackSubmitted === "accepted" &&
                      "bg-green-50 text-green-700 dark:bg-green-950/20 dark:text-green-400",
                    feedbackSubmitted === "rejected" &&
                      "bg-red-50 text-red-700 dark:bg-red-950/20 dark:text-red-400",
                    feedbackSubmitted === "escalated" &&
                      "bg-yellow-50 text-yellow-700 dark:bg-yellow-950/20 dark:text-yellow-400",
                  )}
                >
                  {feedbackSubmitted === "accepted" && "已采纳研判结果"}
                  {feedbackSubmitted === "rejected" && "已否决研判结果"}
                  {feedbackSubmitted === "escalated" && "已升级处理"}
                </div>
              )}

              {/* Action buttons */}
              {!feedbackSubmitted && (
                <div className="flex flex-col gap-2">
                  <Button
                    variant="default"
                    className="bg-green-600 hover:bg-green-700 text-white"
                    disabled={submitFeedback.isPending}
                    onClick={() => handleAction("accepted")}
                  >
                    {submitFeedback.isPending ? "提交中..." : "采纳"}
                  </Button>
                  <Button
                    variant="destructive"
                    disabled={submitFeedback.isPending}
                    onClick={() => handleAction("rejected")}
                  >
                    {submitFeedback.isPending ? "提交中..." : "否决"}
                  </Button>
                  <Button
                    variant="secondary"
                    className="bg-yellow-500 hover:bg-yellow-600 text-white"
                    disabled={submitFeedback.isPending}
                    onClick={() => handleAction("escalated")}
                  >
                    {submitFeedback.isPending ? "提交中..." : "升级"}
                  </Button>
                </div>
              )}
            </div>
          )}
        </div>
      </ScrollArea>
    </div>
  );
}
