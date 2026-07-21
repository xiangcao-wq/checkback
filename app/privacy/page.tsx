"use client";

import { ArrowLeft, ShieldCheck, Trash } from "@phosphor-icons/react";
import Link from "next/link";
import { useState } from "react";
import { clearAllCheckbackData } from "../lib/area-store";
import { useAppLocale } from "../locale-provider";
import { localize } from "../lib/locale";

export default function PrivacyPage() {
  const [cleared, setCleared] = useState(false);
  const { locale } = useAppLocale();
  const l = (chinese: string, english: string) => localize(locale, chinese, english);

  const clearLocalPhoto = async () => {
    await clearAllCheckbackData();
    setCleared(true);
  };

  return (
    <main className="privacy-stage">
      <article className="privacy-card">
        <Link className="privacy-back" href="/">
          <ArrowLeft size={18} aria-hidden="true" />
          {l("返回 CheckBack", "Back to CheckBack")}
        </Link>

        <div className="privacy-title-mark" aria-hidden="true">
          <ShieldCheck size={28} weight="duotone" />
        </div>
        <h1>{l("照片处理与隐私", "Photo processing and privacy")}</h1>
        <p className="privacy-lead">
          {l("拍摄前，请先了解两张照片会如何被处理。", "Before capturing, see how your two photos are handled.")}
        </p>

        <section>
          <h2>{l("保存在这台设备上", "Stored on this device")}</h2>
          <p>{l(
            "区域、标准照片和最近检查历史保存在当前浏览器中，最多保留每个区域最近 30 次检查，直到你主动清除。",
            "Areas, reference photos, and recent history stay in this browser. Up to 30 checks per area are kept until you clear them.",
          )}</p>
        </section>

        <section>
          <h2>{l("检查时发送给 Qwen", "Sent to Qwen during a check")}</h2>
          <p>{l(
            "每次检查会将标准照片和当前照片加密传输到 CheckBack 服务器，再发送给 Qwen 完成视觉比较。疑似缺失时，系统可能进行第二次保守复核。",
            "Each check securely sends the reference and current photos to the CheckBack server, then to Qwen for visual comparison. Possible missing items may receive a second conservative review.",
          )}</p>
        </section>

        <section>
          <h2>{l("语言判断在服务器本地完成", "Language detection happens locally on the server")}</h2>
          <p>{l(
            "首次访问时，CheckBack 会把 IP 地址映射为国家码来推荐语言。查询使用服务器上的本地国家数据库，不会把访客 IP 发送给定位服务，也不会为了语言判断保存 IP。",
            "On your first visit, CheckBack maps the IP address to a country code to recommend a language. The lookup uses a local country database on the server; the visitor IP is not sent to a location service or stored for language detection.",
          )}</p>
        </section>

        <section>
          <h2>{l("CheckBack 不建立照片库", "CheckBack does not build a photo library")}</h2>
          <p>{l(
            "检查照片仅保存在当前浏览器的本地历史中，不会写入 CheckBack 服务端数据库，服务器也不会记录请求正文。模型服务商仍会按其服务协议处理调用数据，请避免拍入证件、密码、聊天内容或其他敏感信息。",
            "Check photos remain only in this browser's local history. They are not written to a CheckBack server database, and the server does not log request bodies. The model provider still handles request data under its service terms, so avoid capturing IDs, passwords, chats, or other sensitive information.",
          )}</p>
        </section>

        <button className="privacy-clear" type="button" onClick={() => void clearLocalPhoto()}>
          <Trash size={18} aria-hidden="true" />
          {cleared
            ? l("本机区域与历史已清除", "Local areas and history cleared")
            : l("清除本机区域、照片与历史", "Clear local areas, photos, and history")}
        </button>
      </article>
    </main>
  );
}
