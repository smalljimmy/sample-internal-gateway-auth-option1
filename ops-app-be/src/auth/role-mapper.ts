/**
 * Maps identity (sub, email) to a concrete role for mi6 authZ.
 * Ops App BE uses this before issuing the gateway token so mi6 receives a resolved role.
 */

export interface Identity {
  sub: string;
  email?: string;
  name?: string;
}

/**
 * Resolve role for the given identity. Replace with DB/config lookup in production.
 * Env: ROLE_MAP_JSON optional, e.g. {"user@example.com":"admin"} or default role via DEFAULT_ROLE.
 */
export async function mapIdentityToRole(identity: Identity): Promise<string> {
  const mapJson = process.env.ROLE_MAP_JSON;
  if (mapJson) {
    try {
      const map = JSON.parse(mapJson) as Record<string, string>;
      if (identity.email && map[identity.email]) return map[identity.email];
      if (map[identity.sub]) return map[identity.sub];
    } catch {
      /* ignore parse error, fall back to default */
    }
  }
  return process.env.DEFAULT_ROLE ?? 'user';
}
