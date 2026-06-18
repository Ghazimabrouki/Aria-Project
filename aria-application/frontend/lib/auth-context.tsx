"use client";

import {
  createContext,
  useContext,
  useState,
  useEffect,
  useCallback,
  ReactNode,
} from "react";
import { useRouter } from "next/navigation";

export interface AuthUser {
  id: string;
  username: string;
  email?: string | null;
  role: "super_admin" | "server_user";
  asset_id?: string | null;
  scope_all_assets: boolean;
  is_active: boolean;
  is_banned: boolean;
}

interface AuthContextValue {
  user: AuthUser | null;
  token: string | null;
  isLoading: boolean;
  login: (username: string, password: string) => Promise<void>;
  logout: () => void;
}

const AuthContext = createContext<AuthContextValue>({
  user: null,
  token: null,
  isLoading: true,
  login: async () => {},
  logout: () => {},
});

const TOKEN_KEY = "aria_auth_token";

export function AuthProvider({ children }: { children: ReactNode }) {
  const router = useRouter();
  const [token, setToken] = useState<string | null>(null);
  const [user, setUser] = useState<AuthUser | null>(null);
  const [isLoading, setIsLoading] = useState(true);

  const logout = useCallback(() => {
    if (typeof window !== "undefined") {
      localStorage.removeItem(TOKEN_KEY);
    }
    setToken(null);
    setUser(null);
    router.push("/login");
  }, [router]);

  const fetchMe = useCallback(
    async (currentToken: string) => {
      try {
        const res = await fetch(
          `${process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8001"}/api/v1/auth/me`,
          {
            headers: {
              Authorization: `Bearer ${currentToken}`,
            },
            cache: "no-store",
          }
        );
        if (!res.ok) {
          throw new Error("Token invalid");
        }
        const data = await res.json();
        setUser(data.user);
        setToken(currentToken);
      } catch {
        logout();
      } finally {
        setIsLoading(false);
      }
    },
    [logout]
  );

  useEffect(() => {
    if (typeof window === "undefined") return;
    const saved = localStorage.getItem(TOKEN_KEY);
    if (saved) {
      fetchMe(saved);
    } else {
      setIsLoading(false);
    }
  }, [fetchMe]);

  const login = useCallback(
    async (username: string, password: string) => {
      const res = await fetch(
        `${process.env.NEXT_PUBLIC_API_URL ?? "http://127.0.0.1:8001"}/api/v1/auth/login`,
        {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ username, password }),
          cache: "no-store",
        }
      );
      const data = await res.json();
      if (!res.ok) {
        throw new Error(data.detail || "Login failed");
      }
      if (typeof window !== "undefined") {
        localStorage.setItem(TOKEN_KEY, data.access_token);
      }
      setToken(data.access_token);
      setUser(data.user);
    },
    []
  );

  return (
    <AuthContext.Provider value={{ user, token, isLoading, login, logout }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  return useContext(AuthContext);
}
