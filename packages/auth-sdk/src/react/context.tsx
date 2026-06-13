import {
  createContext,
  createElement,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from "react";

import type { AuthClient, AuthState, SignInOptions } from "../client/auth-client.js";
import type { User } from "../index.js";

export interface AuthContextValue {
  state: AuthState;
  signIn: (options?: SignInOptions) => Promise<void>;
  signOut: (options?: { postLogoutRedirectUri?: string }) => Promise<void>;
  getAccessToken: (options?: { forceRefresh?: boolean }) => Promise<string>;
}

const AuthContext = createContext<AuthContextValue | undefined>(undefined);

export function AuthProvider(props: {
  client: AuthClient;
  children: ReactNode;
}): ReactNode {
  const { client, children } = props;
  const [state, setState] = useState<AuthState>(() => client.getState());

  useEffect(() => {
    setState(client.getState());
    return client.onStateChange(setState);
  }, [client]);

  const value = useMemo<AuthContextValue>(
    () => ({
      state,
      signIn: (options) => client.signInWithRedirect(options),
      signOut: (options) => client.signOut(options),
      getAccessToken: (options) => client.getAccessToken(options),
    }),
    [client, state],
  );

  return createElement(AuthContext.Provider, { value }, children);
}

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error("useAuth must be used within an <AuthProvider>");
  }
  return context;
}

export function useUser(): User | undefined {
  const { state } = useAuth();
  return state.status === "authenticated" ? state.user : undefined;
}
