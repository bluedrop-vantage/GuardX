// Auth context — supports three modes selectable by Vite env config:
//
//   1. Supabase Auth (recommended for prod)
//      Set VITE_SUPABASE_URL + VITE_SUPABASE_ANON_KEY. Login form email/password
//      and the JWT flows through `session.access_token` → Bearer header on
//      every API call. Role comes from a custom claim `app_metadata.guardx_role`
//      that a Supabase admin sets via the dashboard or a management API call.
//
//   2. Manual JWT (universal fallback)
//      Any OIDC provider's JWT can be pasted directly. Useful for Keycloak /
//      Auth0 / Okta demos where you already have a token.
//
//   3. API key (dev / service tokens)
//      The legacy X-GuardX-Key header path. Keep for automation-plane
//      services; hide from the login form when OIDC is configured.
import {
  createContext, useCallback, useContext, useEffect, useMemo, useState,
  type ReactNode,
} from "react";
import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const SUPABASE_URL      = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const SUPABASE_ANON_KEY = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;
export const OIDC_ENABLED = !!SUPABASE_URL && !!SUPABASE_ANON_KEY;

let supabase: SupabaseClient | null = null;
if (OIDC_ENABLED) {
  supabase = createClient(SUPABASE_URL!, SUPABASE_ANON_KEY!, {
    auth: { persistSession: true, autoRefreshToken: true },
  });
}
export function getSupabase(): SupabaseClient | null { return supabase; }

// --- Session shape (provider-agnostic) --------------------------------------

export type AuthMode = "supabase" | "manual-jwt" | "api-key";

export interface Session {
  mode: AuthMode;
  bearer?: string;   // for supabase | manual-jwt
  apiKey?: string;   // for api-key
  subject?: string;  // display name (email / sub)
}

// --- Storage keys ----------------------------------------------------------

const MANUAL_JWT_KEY = "guardx.manualJwt";
const API_KEY_KEY    = "guardx.apiKey";

// --- Context --------------------------------------------------------------

interface AuthContextValue {
  session: Session | null;
  ready: boolean;
  loginSupabase: (email: string, password: string) => Promise<void>;
  loginManualJwt: (jwt: string) => void;
  loginApiKey: (key: string) => void;
  logout: () => Promise<void>;
  authHeaders: () => Record<string, string>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export function AuthProvider({ children }: { children: ReactNode }) {
  const [session, setSession] = useState<Session | null>(null);
  const [ready, setReady] = useState(false);

  // Initial load: prefer Supabase session, then manual JWT, then API key.
  useEffect(() => {
    let cancelled = false;
    (async () => {
      if (supabase) {
        const { data } = await supabase.auth.getSession();
        if (!cancelled && data.session?.access_token) {
          setSession({
            mode: "supabase",
            bearer: data.session.access_token,
            subject: data.session.user.email ?? data.session.user.id,
          });
          setReady(true);
          return;
        }
      }
      const jwt = localStorage.getItem(MANUAL_JWT_KEY);
      if (!cancelled && jwt) {
        setSession({ mode: "manual-jwt", bearer: jwt, subject: parseSub(jwt) });
        setReady(true);
        return;
      }
      const key = localStorage.getItem(API_KEY_KEY);
      if (!cancelled && key) {
        setSession({ mode: "api-key", apiKey: key, subject: "api-key" });
      }
      if (!cancelled) setReady(true);
    })();
    return () => { cancelled = true; };
  }, []);

  // Refresh session when Supabase token rotates (autoRefreshToken).
  useEffect(() => {
    if (!supabase) return;
    const { data: sub } = supabase.auth.onAuthStateChange((_ev, s) => {
      if (s?.access_token) {
        setSession({
          mode: "supabase",
          bearer: s.access_token,
          subject: s.user.email ?? s.user.id,
        });
      } else {
        setSession(null);
      }
    });
    return () => { sub.subscription.unsubscribe(); };
  }, []);

  const loginSupabase = useCallback(async (email: string, password: string) => {
    if (!supabase) throw new Error("Supabase not configured");
    const { error } = await supabase.auth.signInWithPassword({ email, password });
    if (error) throw error;
    // onAuthStateChange populates `session` for us.
  }, []);

  const loginManualJwt = useCallback((jwt: string) => {
    localStorage.setItem(MANUAL_JWT_KEY, jwt);
    setSession({ mode: "manual-jwt", bearer: jwt, subject: parseSub(jwt) });
  }, []);

  const loginApiKey = useCallback((key: string) => {
    localStorage.setItem(API_KEY_KEY, key);
    setSession({ mode: "api-key", apiKey: key, subject: "api-key" });
  }, []);

  const logout = useCallback(async () => {
    if (supabase) await supabase.auth.signOut();
    localStorage.removeItem(MANUAL_JWT_KEY);
    localStorage.removeItem(API_KEY_KEY);
    setSession(null);
  }, []);

  const authHeaders = useCallback((): Record<string, string> => {
    if (!session) return {};
    if (session.bearer) return { Authorization: `Bearer ${session.bearer}` };
    if (session.apiKey) return { "X-GuardX-Key": session.apiKey };
    return {};
  }, [session]);

  const value = useMemo<AuthContextValue>(() => ({
    session, ready,
    loginSupabase, loginManualJwt, loginApiKey, logout, authHeaders,
  }), [session, ready, loginSupabase, loginManualJwt, loginApiKey, logout, authHeaders]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth(): AuthContextValue {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within <AuthProvider>");
  return ctx;
}

// --- helpers ---------------------------------------------------------------

function parseSub(jwt: string): string {
  try {
    const parts = jwt.split(".");
    if (parts.length < 2) return "unknown";
    const payload = JSON.parse(atob(parts[1].replace(/-/g, "+").replace(/_/g, "/")));
    return payload.email || payload.sub || "unknown";
  } catch {
    return "unknown";
  }
}
