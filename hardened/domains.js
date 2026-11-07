import rules from './vendor/public-suffix-rules.js';

const exact = new Set();
const wildcard = new Set();
const exceptions = new Set();
for (const rule of rules) {
  if (rule.startsWith('!')) exceptions.add(rule.slice(1));
  else if (rule.startsWith('*.')) wildcard.add(rule.slice(2));
  else exact.add(rule);
}

// Inputs come from URL.hostname, already lower-case and ASCII/IDNA canonical.
// IPs, single-label names and trailing-dot names receive no parent-domain fallback.
export function registrableDomain(host) {
  if (typeof host !== 'string' || host.length > 253 || !/^[a-z0-9.-]+$/.test(host)
      || host.endsWith('.') || /^[0-9.]+$/.test(host)) return null;
  const labels = host.split('.');
  if (labels.length < 2 || labels.some(label => !label || label.length > 63 || label.startsWith('-') || label.endsWith('-'))) return null;
  let suffixLength = 0; // Unknown/local suffixes stay exact-origin only.
  for (let index = 0; index < labels.length; index += 1) {
    const suffix = labels.slice(index).join('.');
    const length = labels.length - index;
    if (exceptions.has(suffix)) return labels.slice(-(length)).join('.');
    if (exact.has(suffix)) suffixLength = Math.max(suffixLength, length);
    if (index > 0 && wildcard.has(suffix)) suffixLength = Math.max(suffixLength, length + 1);
  }
  return suffixLength > 0 && labels.length > suffixLength ? labels.slice(-(suffixLength + 1)).join('.') : null;
}

export function matchesSavedUrl(saved, destination) {
  if (saved.origin === destination.origin) return true;
  if (saved.protocol !== 'https:' || destination.protocol !== 'https:' || saved.port !== destination.port) return false;
  if (!destination.hostname.endsWith('.' + saved.hostname)) return false;
  const domain = registrableDomain(saved.hostname);
  return domain !== null && registrableDomain(destination.hostname) === domain;
}
