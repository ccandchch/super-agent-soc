"use client";

import { useState } from "react";
import { useQuery, useMutation, useQueryClient } from "@tanstack/react-query";

interface Rule {
  id: string;
  rule_id: string;
  entity_pattern: Record<string, string>;
  status: string;
  created_at: string;
}

export default function RulesPage() {
  const queryClient = useQueryClient();
  const [newRule, setNewRule] = useState({
    rule_id: "",
    defense_line: "",
    entity_value: "",
  });

  const { data: rules = [], isLoading } = useQuery<Rule[]>({
    queryKey: ["soc", "rules"],
    queryFn: async () => {
      const res = await fetch("/api/soc/queue/rules");
      return res.json();
    },
  });

  const createRule = useMutation({
    mutationFn: (rule: Record<string, unknown>) =>
      fetch("/api/soc/queue/rules", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(rule),
      }).then((r) => r.json()),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["soc", "rules"] }),
  });

  const deleteRule = useMutation({
    mutationFn: (id: string) =>
      fetch(`/api/soc/queue/rules/${id}`, { method: "DELETE" }),
    onSuccess: () =>
      queryClient.invalidateQueries({ queryKey: ["soc", "rules"] }),
  });

  return (
    <div className="p-6 space-y-4">
      <h1 className="text-xl font-semibold">抑制规则管理</h1>

      <div className="flex gap-2">
        <input
          className="border rounded px-2 py-1 text-sm"
          placeholder="规则ID"
          value={newRule.rule_id}
          onChange={(e) =>
            setNewRule({ ...newRule, rule_id: e.target.value })
          }
        />
        <input
          className="border rounded px-2 py-1 text-sm"
          placeholder="防线"
          value={newRule.defense_line}
          onChange={(e) =>
            setNewRule({ ...newRule, defense_line: e.target.value })
          }
        />
        <input
          className="border rounded px-2 py-1 text-sm"
          placeholder="实体值"
          value={newRule.entity_value}
          onChange={(e) =>
            setNewRule({ ...newRule, entity_value: e.target.value })
          }
        />
        <button
          className="bg-primary text-primary-foreground px-3 py-1 rounded text-sm"
          onClick={() =>
            createRule.mutate({
              rule_id: newRule.rule_id,
              entity_pattern: {
                defense_line: newRule.defense_line,
                host: newRule.entity_value,
              },
            })
          }
        >
          添加规则
        </button>
      </div>

      {isLoading ? (
        <p className="text-sm text-muted-foreground">加载中...</p>
      ) : (
        <div className="border rounded-lg">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b bg-muted/50">
                <th className="text-left p-2">规则ID</th>
                <th className="text-left p-2">匹配模式</th>
                <th className="text-left p-2">状态</th>
                <th className="text-left p-2">操作</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((r) => (
                <tr key={r.id} className="border-b">
                  <td className="p-2 font-mono text-xs">{r.rule_id}</td>
                  <td className="p-2 font-mono text-xs">
                    {JSON.stringify(r.entity_pattern)}
                  </td>
                  <td className="p-2">
                    <span
                      className={
                        r.status === "active"
                          ? "text-green-600"
                          : "text-yellow-600"
                      }
                    >
                      {r.status}
                    </span>
                  </td>
                  <td className="p-2">
                    <button
                      className="text-red-600 hover:underline"
                      onClick={() => deleteRule.mutate(r.id)}
                    >
                      删除
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
