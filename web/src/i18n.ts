import catalogs from './locales.json';
export const locales = ['en', 'ko', 'ja', 'es', 'zh-Hans', 'zh-Hant'] as const;
export type Locale = typeof locales[number];
export type MessageKey = keyof typeof catalogs.en;
export const localeNames: Record<Locale, string> = { en: 'English', ko: '한국어', ja: '日本語', es: 'Español', 'zh-Hans': '简体中文', 'zh-Hant': '繁體中文' };
export function initialLocale(): Locale {
  try { const saved = localStorage.getItem('fw.locale'); if (locales.includes(saved as Locale)) return saved as Locale; } catch { /* Storage may be disabled. */ }
  const lang = navigator.language;
  if (/^zh-(TW|HK|Hant)/i.test(lang)) return 'zh-Hant';
  if (/^zh/i.test(lang)) return 'zh-Hans';
  return locales.find(l => lang.startsWith(l)) ?? 'en';
}
export function translator(locale: Locale) {
  return (key: MessageKey, values: Record<string, string | number> = {}): string => {
    const message = catalogs[locale][key] ?? catalogs.en[key];
    return message.replace(/\{(\w+)\}/g, (match, name: string) => String(values[name] ?? match));
  };
}
export type Translate = ReturnType<typeof translator>;
export function formatTime(value: unknown, locale: Locale): string {
  if (typeof value !== 'string' || Number.isNaN(Date.parse(value))) return '—';
  return new Intl.DateTimeFormat(locale, { dateStyle: 'medium', timeStyle: 'medium', timeZone: 'UTC' }).format(new Date(value)) + ' UTC';
}
