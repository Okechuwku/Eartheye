export function normalizeRole(role) {
  const value = (role || 'Free').trim().toLowerCase();
  if (['admin', 'administrator'].includes(value)) return 'Administrator';
  if (['premium', 'premium user', 'premium user ($25 plan)'].includes(value)) return 'Premium';
  if (['user', 'free', 'free user'].includes(value)) return 'Free';
  return role || 'Free';
}

export function isAdminRole(role) {
  return normalizeRole(role) === 'Administrator';
}

export function isPremiumRole(role) {
  return ['Premium', 'Administrator'].includes(normalizeRole(role));
}

export function roleBadge(role) {
  const normalized = normalizeRole(role);
  if (normalized === 'Administrator') return 'Administrator';
  if (normalized === 'Premium') return 'Premium user ($25 plan)';
  return 'Free user';
}
