/* Chinese is the source language; the map holds English overrides. A key
   with no entry falls through to the Chinese literal, so adding UI text
   never breaks the other language. */

export type Lang = "zh" | "en";

const en: Record<string, string> = {
  概览: "Overview",
  证书: "Certificates",
  "ACME 账户": "ACME accounts",
  "DNS 提供商": "DNS providers",
  部署目标: "Deploy targets",
  操作日志: "Audit log",
  设置: "Settings",
  语言: "Language",
  退出登录: "Log out",
  复制: "copy",
  已复制: "copied",
  关闭: "Close",

  登录: "Sign in",
  用户名: "Username",
  密码: "Password",
  "用户名或密码错误": "Incorrect username or password",

  新建: "New",
  新建证书: "New certificate",
  域名: "Domain",
  附加域名: "Additional names (SAN)",
  状态: "Status",
  到期: "Expires",
  有效期: "Validity",
  自动续期: "Auto-renew",
  操作: "Actions",
  续期: "Renew",
  部署: "Deploy",
  删除: "Delete",
  下载: "Download",
  保存: "Save",
  取消: "Cancel",
  创建: "Create",
  导入: "Import",
  编辑: "Edit",
  搜索: "Search",
  全部: "All",

  待签发: "Pending",
  已签发: "Issued",
  失败: "Failed",
  已过期: "Expired",
  即将过期: "Expiring",

  证书总数: "Certificates",
  运行正常: "Healthy",
  需要关注: "Needs attention",

  证书详情: "Certificate",
  概要: "Summary",
  "X.509 详情": "X.509",
  时间线: "Timeline",
  部署状态: "Deployments",

  暂无数据: "Nothing here yet",
  加载中: "Loading…",
  名称: "Name",
  类型: "Type",
  配置: "Configuration",
  邮箱: "Email",
  目录地址: "Directory URL",
  创建时间: "Created",
  修改密码: "Change password",
  当前密码: "Current password",
  新密码: "New password",
};

let current: Lang = (localStorage.getItem("lang") as Lang) || "zh";

export function getLang(): Lang {
  return current;
}

export function setLang(lang: Lang) {
  current = lang;
  localStorage.setItem("lang", lang);
  // A full reload is the honest way to re-render every string without
  // threading a context through components that only read text.
  window.location.reload();
}

export function t(zh: string): string {
  if (current === "zh") return zh;
  return en[zh] ?? zh;
}
