"use client";

import {
  BotIcon,
  ChevronRight,
  FileTextIcon,
  GaugeIcon,
  MessagesSquare,
  ScrollTextIcon,
  ShieldIcon,
} from "lucide-react";
import Link from "next/link";
import { usePathname } from "next/navigation";
import { useState } from "react";

import {
  SidebarGroup,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
} from "@/components/ui/sidebar";
import { useI18n } from "@/core/i18n/hooks";

export function WorkspaceNavChatList() {
  const { t } = useI18n();
  const pathname = usePathname();
  const socActive = pathname.startsWith("/workspace/soc");
  const [socOpen, setSocOpen] = useState(socActive);

  return (
    <SidebarGroup className="pt-1">
      <SidebarMenu>
        <SidebarMenuItem>
          <SidebarMenuButton isActive={pathname === "/workspace/chats"} asChild>
            <Link className="text-muted-foreground" href="/workspace/chats">
              <MessagesSquare />
              <span>{t.sidebar.chats}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>
        <SidebarMenuItem>
          <SidebarMenuButton
            isActive={pathname.startsWith("/workspace/agents")}
            asChild
          >
            <Link className="text-muted-foreground" href="/workspace/agents">
              <BotIcon />
              <span>{t.sidebar.agents}</span>
            </Link>
          </SidebarMenuButton>
        </SidebarMenuItem>

        {/* SOC — expandable submenu */}
        <SidebarMenuItem>
          <SidebarMenuButton
            isActive={socActive}
            onClick={() => setSocOpen(!socOpen)}
          >
            <ShieldIcon />
            <span>SOC</span>
            <ChevronRight
              className={`ml-auto size-3.5 transition-transform ${socOpen ? "rotate-90" : ""}`}
            />
          </SidebarMenuButton>
          {socOpen && (
            <SidebarMenuSub>
              <SidebarMenuSubItem>
                <SidebarMenuSubButton
                  isActive={pathname === "/workspace/soc/alerts"}
                  asChild
                >
                  <Link href="/workspace/soc/alerts">
                    <span>告警工作台</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
              <SidebarMenuSubItem>
                <SidebarMenuSubButton
                  isActive={pathname === "/workspace/soc/dashboard"}
                  asChild
                >
                  <Link href="/workspace/soc/dashboard">
                    <GaugeIcon className="size-3.5" />
                    <span>运营仪表盘</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
              <SidebarMenuSubItem>
                <SidebarMenuSubButton
                  isActive={pathname === "/workspace/soc/rules"}
                  asChild
                >
                  <Link href="/workspace/soc/rules">
                    <ScrollTextIcon className="size-3.5" />
                    <span>抑制规则</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
              <SidebarMenuSubItem>
                <SidebarMenuSubButton
                  isActive={pathname === "/workspace/soc/audit"}
                  asChild
                >
                  <Link href="/workspace/soc/audit">
                    <FileTextIcon className="size-3.5" />
                    <span>审计日志</span>
                  </Link>
                </SidebarMenuSubButton>
              </SidebarMenuSubItem>
            </SidebarMenuSub>
          )}
        </SidebarMenuItem>
      </SidebarMenu>
    </SidebarGroup>
  );
}
