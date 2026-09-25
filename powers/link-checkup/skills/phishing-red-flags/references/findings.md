# Finding ids → plain language

| id | English | 中文 | Advice |
|---|---|---|---|
| `blocklist.urlhaus` / `blocklist.phishingArmy` | Already reported as malicious | 已被举报为恶意 | Don't open. Delete the message. |
| `lookalike.homoglyph` | Uses look-alike letters (1 for l, Cyrillic а) to copy a brand | 用形近字母仿冒品牌 | Type the brand's address yourself. |
| `lookalike.typosquat` | One typo away from a brand | 与品牌域名只差一个字符 | Same as above. |
| `lookalike.combosquat` | Brand name + words like "secure-login" | 品牌名 + “secure-login”之类的词 | Brands don't use such domains. |
| `lookalike.brandInSubdomain` | Brand name placed before the real domain | 把品牌名放在真实域名前面 | Read the part right before the ending. |
| `lookalike.mixedScript` | Mixes alphabets | 混用字母表 | Almost always deceptive. |
| `rdap.veryNew` / `rdap.new` | Domain registered days/weeks ago | 域名刚注册不久 | Phishing sites are short-lived. |
| `redirects.crossDomain` | Ends up on a different site | 最终跳转到其他网站 | Judge the final site, not the first. |
| `redirects.blockedTarget` | Points into a private network | 指向内网地址 | Never legitimate for a public link. |
| `tls.invalid` | Certificate invalid | 证书无效 | Never type passwords there. |
| `dns.nxdomain` | Domain doesn't exist | 域名不存在 | Taken down or fake. |
| `urlShape.userinfo` | "@" trick hides the real host | “@”障眼法隐藏真实主机 | Everything before @ is ignored. |
