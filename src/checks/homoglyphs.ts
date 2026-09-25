/**
 * Confusable characters → the ASCII letter they imitate.
 * Subset inspired by Unicode TR39 confusables, focused on what phishing domains actually use.
 */
export const HOMOGLYPHS: Record<string, string> = {
  // digits & ASCII look-alikes
  "0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t", "8": "b", i: "l",
  // Cyrillic
  "а": "a", "б": "b", "в": "b", "г": "r", "е": "e", "ё": "e", "з": "e", "и": "u", "к": "k", "м": "m", "н": "h",
  "о": "o", "р": "p", "с": "c", "т": "t", "у": "y", "х": "x", "ѕ": "s", "і": "l", "ї": "l", "ј": "j", "ԁ": "d",
  "ɡ": "g", "һ": "h", "ԛ": "q", "ԝ": "w", "ү": "y", "ӏ": "l", "ո": "n", "ս": "u", "օ": "o",
  // Greek
  "α": "a", "β": "b", "ε": "e", "η": "n", "ι": "l", "κ": "k", "ν": "v", "ο": "o", "ρ": "p", "τ": "t", "υ": "u",
  "χ": "x", "ω": "w",
  // Latin extended / IPA
  "ı": "l", "ł": "l", "ƚ": "l", "ɩ": "l", "ǀ": "l", "ɑ": "a", "à": "a", "á": "a", "â": "a", "ã": "a", "ä": "a",
  "å": "a", "ā": "a", "ç": "c", "è": "e", "é": "e", "ê": "e", "ë": "e", "ē": "e", "ì": "l", "í": "l", "î": "l",
  "ï": "l", "ñ": "n", "ò": "o", "ó": "o", "ô": "o", "õ": "o", "ö": "o", "ø": "o", "ō": "o", "ù": "u", "ú": "u",
  "û": "u", "ü": "u", "ý": "y", "ÿ": "y", "ś": "s", "ș": "s", "ț": "t", "ž": "z", "ż": "z", "ɢ": "g", "ʀ": "r",
};

/** Multi-character sequences that render like a single letter in most fonts. */
const SEQUENCES: Array<[RegExp, string]> = [
  [/rn/g, "m"],
  [/vv/g, "w"],
];

/**
 * Reduce a (Unicode) label to a canonical "skeleton" so that visually confusable labels compare equal.
 * `paypa1` → `paypal`, `аpple` (Cyrillic а) → `apple`, `rnicrosoft` → `mlcrosoft` (same as `microsoft`).
 */
export function skeleton(label: string): string {
  let out = "";
  for (const ch of label.toLowerCase()) out += HOMOGLYPHS[ch] ?? ch;
  out = out.replace(/-/g, "");
  for (const [re, rep] of SEQUENCES) out = out.replace(re, rep);
  return out;
}

/** Characters (other than the letter itself) that imitate `ascii`. */
export function confusablesFor(ascii: string): string[] {
  const target = HOMOGLYPHS[ascii] ?? ascii;
  return Object.keys(HOMOGLYPHS).filter((k) => HOMOGLYPHS[k] === target && k !== ascii);
}
