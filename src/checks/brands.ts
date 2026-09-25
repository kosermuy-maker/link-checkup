// Curated list of official brand domains used by the lookalike check.
/**
 * Official domains of frequently-imitated brands. Data only.
 * A host whose registrable domain is listed here is never flagged as a lookalike.
 * `label` is the distinctive name compared against suspicious domains.
 */
export interface Brand {
  name: string;
  label: string;
  domains: string[];
}

export const BRANDS: Brand[] = [
  { name: "Google", label: "google", domains: ["google.com", "google.co.uk", "google.de", "google.fr", "google.co.jp", "google.com.hk", "googleusercontent.com", "goo.gl", "g.co"] },
  { name: "Gmail", label: "gmail", domains: ["gmail.com"] },
  { name: "YouTube", label: "youtube", domains: ["youtube.com", "youtu.be"] },
  { name: "Facebook", label: "facebook", domains: ["facebook.com", "fb.com", "fb.me"] },
  { name: "Instagram", label: "instagram", domains: ["instagram.com"] },
  { name: "WhatsApp", label: "whatsapp", domains: ["whatsapp.com", "whatsapp.net", "wa.me"] },
  { name: "Meta", label: "meta", domains: ["meta.com"] },
  { name: "Apple", label: "apple", domains: ["apple.com"] },
  { name: "iCloud", label: "icloud", domains: ["icloud.com"] },
  { name: "Microsoft", label: "microsoft", domains: ["microsoft.com", "microsoftonline.com"] },
  { name: "Outlook", label: "outlook", domains: ["outlook.com", "live.com", "office.com", "office365.com", "hotmail.com"] },
  { name: "Amazon", label: "amazon", domains: ["amazon.com", "amazon.co.uk", "amazon.de", "amazon.co.jp", "amazon.cn", "amazon.fr", "amazon.in", "amazonaws.com"] },
  { name: "AWS", label: "aws", domains: ["aws.amazon.com", "aws.dev"] },
  { name: "PayPal", label: "paypal", domains: ["paypal.com", "paypal.me"] },
  { name: "Netflix", label: "netflix", domains: ["netflix.com"] },
  { name: "LinkedIn", label: "linkedin", domains: ["linkedin.com", "lnkd.in"] },
  { name: "X / Twitter", label: "twitter", domains: ["twitter.com", "x.com", "t.co"] },
  { name: "GitHub", label: "github", domains: ["github.com", "github.io", "githubusercontent.com"] },
  { name: "Dropbox", label: "dropbox", domains: ["dropbox.com"] },
  { name: "Adobe", label: "adobe", domains: ["adobe.com"] },
  { name: "DocuSign", label: "docusign", domains: ["docusign.com", "docusign.net"] },
  { name: "Chase", label: "chase", domains: ["chase.com"] },
  { name: "Wells Fargo", label: "wellsfargo", domains: ["wellsfargo.com"] },
  { name: "Bank of America", label: "bankofamerica", domains: ["bankofamerica.com"] },
  { name: "Coinbase", label: "coinbase", domains: ["coinbase.com"] },
  { name: "Binance", label: "binance", domains: ["binance.com"] },
  { name: "MetaMask", label: "metamask", domains: ["metamask.io"] },
  { name: "Steam", label: "steamcommunity", domains: ["steamcommunity.com", "steampowered.com"] },
  { name: "Discord", label: "discord", domains: ["discord.com", "discord.gg", "discordapp.com"] },
  { name: "Telegram", label: "telegram", domains: ["telegram.org", "t.me"] },
  { name: "Alipay", label: "alipay", domains: ["alipay.com"] },
  { name: "Taobao", label: "taobao", domains: ["taobao.com"] },
  { name: "Tmall", label: "tmall", domains: ["tmall.com"] },
  { name: "WeChat", label: "wechat", domains: ["wechat.com", "weixin.qq.com", "qq.com"] },
  { name: "Baidu", label: "baidu", domains: ["baidu.com"] },
  { name: "ICBC", label: "icbc", domains: ["icbc.com.cn"] },
  { name: "China Railway 12306", label: "12306", domains: ["12306.cn"] },
  { name: "DHL", label: "dhl", domains: ["dhl.com", "dhl.de"] },
  { name: "FedEx", label: "fedex", domains: ["fedex.com"] },
  { name: "USPS", label: "usps", domains: ["usps.com"] },
  { name: "UPS", label: "ups", domains: ["ups.com"] },
  { name: "Booking.com", label: "booking", domains: ["booking.com"] },
  { name: "Airbnb", label: "airbnb", domains: ["airbnb.com"] },
  { name: "eBay", label: "ebay", domains: ["ebay.com", "ebay.co.uk", "ebay.de"] },
  { name: "Walmart", label: "walmart", domains: ["walmart.com"] },
  { name: "OpenAI", label: "openai", domains: ["openai.com", "chatgpt.com"] },
  { name: "Kiro", label: "kiro", domains: ["kiro.dev"] },
  { name: "Spotify", label: "spotify", domains: ["spotify.com"] },
  { name: "Roblox", label: "roblox", domains: ["roblox.com"] },
];

export const OFFICIAL_DOMAINS: ReadonlySet<string> = new Set(BRANDS.flatMap((b) => b.domains));
