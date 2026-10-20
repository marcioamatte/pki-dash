import { en, type MessageKey } from './messages/en';
import { ptBR } from './messages/pt-BR';

export type Locale = 'en' | 'pt-BR';
export const locales: { code: Locale; label: string }[] = [
  { code: 'en', label: 'English' },
  { code: 'pt-BR', label: 'Português (Brasil)' },
];

const catalogs: Record<Locale, Record<MessageKey, string>> = { en, 'pt-BR': ptBR };
const STORAGE_KEY = 'pki-dash.locale';

function isLocale(v: unknown): v is Locale {
  return v === 'en' || v === 'pt-BR';
}

/** The saved choice, else the browser's language, else English. Storage can be unavailable. */
export function detectLocale(navLang: string | undefined, saved: string | null): Locale {
  if (isLocale(saved)) return saved;
  return navLang?.toLowerCase().startsWith('pt') ? 'pt-BR' : 'en';
}

function initial(): Locale {
  let saved: string | null = null;
  try {
    saved = localStorage.getItem(STORAGE_KEY);
  } catch {
    /* private mode or blocked storage */
  }
  return detectLocale(typeof navigator === 'undefined' ? undefined : navigator.language, saved);
}

const state = $state({ locale: initial() });

export function getLocale(): Locale {
  return state.locale;
}

export function setLocale(l: Locale): void {
  state.locale = l;
  try {
    localStorage.setItem(STORAGE_KEY, l);
  } catch {
    /* not persisted, still applied */
  }
  if (typeof document !== 'undefined') document.documentElement.lang = l;
}

/** Fills {name} placeholders. Values are inserted as text; callers never receive HTML. */
export function interpolate(template: string, params?: Record<string, string | number>): string {
  if (!params) return template;
  return template.replace(/\{(\w+)\}/g, (m, k: string) => (k in params ? String(params[k]) : m));
}

export function t(key: MessageKey, params?: Record<string, string | number>): string {
  return interpolate(catalogs[state.locale][key] ?? en[key], params);
}

export function formatDate(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : new Intl.DateTimeFormat(state.locale, { dateStyle: 'medium' }).format(d);
}

export function formatDateTime(iso: string): string {
  const d = new Date(iso);
  return Number.isNaN(d.getTime())
    ? iso
    : new Intl.DateTimeFormat(state.locale, { dateStyle: 'medium', timeStyle: 'medium' }).format(d);
}

if (typeof document !== 'undefined') document.documentElement.lang = state.locale;
