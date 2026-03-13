function inferDefaultApiBaseUrl() {
  if (typeof window === 'undefined') {
    return 'http://localhost:8000';
  }

  const { protocol, hostname } = window.location;
  if (hostname === 'localhost' || hostname === '127.0.0.1') {
    return 'http://localhost:8000';
  }

  const rootHost = hostname.replace(/^www\./i, '');
  return `${protocol}//api.${rootHost}`;
}

const DEFAULT_API_BASE_URL = inferDefaultApiBaseUrl();

function stripTrailingSlash(value) {
  return value.replace(/\/+$/, '');
}

function normalizeApiBaseUrl(value) {
  const raw = stripTrailingSlash((value || '').trim());
  if (!raw) return DEFAULT_API_BASE_URL;
  if (raw.toLowerCase().endsWith('/api')) {
    return raw.slice(0, -4);
  }
  return raw;
}

const configuredApiUrl =
  import.meta.env.VITE_API_URL ||
  import.meta.env.NEXT_PUBLIC_API_URL ||
  import.meta.env.API_URL;

export const API_BASE_URL = normalizeApiBaseUrl(configuredApiUrl);
export const API_URL = `${API_BASE_URL}/api`;

export function buildWebSocketUrl(path) {
  const normalizedPath = path.startsWith('/') ? path : `/${path}`;
  try {
    const base = new URL(API_BASE_URL);
    const wsProtocol = base.protocol === 'https:' ? 'wss:' : 'ws:';
    return `${wsProtocol}//${base.host}${normalizedPath}`;
  } catch {
    const fallback = API_BASE_URL.replace(/^http/, 'ws');
    return `${stripTrailingSlash(fallback)}${normalizedPath}`;
  }
}