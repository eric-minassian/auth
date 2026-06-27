import { useEffect } from "react";

const SUFFIX = "ericminassian.com";

/** Set the document title for a route, restoring nothing (SPA, one title at a time). */
export function useTitle(title: string): void {
  useEffect(() => {
    document.title = `${title} · ${SUFFIX}`;
  }, [title]);
}
