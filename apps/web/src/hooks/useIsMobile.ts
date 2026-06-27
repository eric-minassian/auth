import { useEffect, useState } from "react";

const QUERY = "(max-width: 767px)";

/**
 * Like the design system's `useIsMobile`, but resolves synchronously on the
 * first render (lazy `useState` init from `matchMedia`) so the account page
 * paints the correct orientation immediately — no desktop→mobile layout flash.
 */
export function useIsMobile(): boolean {
  const [isMobile, setIsMobile] = useState(
    () => typeof window !== "undefined" && window.matchMedia(QUERY).matches,
  );

  useEffect(() => {
    const mql = window.matchMedia(QUERY);
    const onChange = () => setIsMobile(mql.matches);
    mql.addEventListener("change", onChange);
    onChange();
    return () => mql.removeEventListener("change", onChange);
  }, []);

  return isMobile;
}
