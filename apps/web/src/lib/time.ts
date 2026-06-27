/** Timestamp formatting helpers. Server times are Unix epoch *seconds*. */

const RELATIVE = new Intl.RelativeTimeFormat(undefined, { numeric: "auto" });

const DIVISIONS: { amount: number; unit: Intl.RelativeTimeFormatUnit }[] = [
  { amount: 60, unit: "second" },
  { amount: 60, unit: "minute" },
  { amount: 24, unit: "hour" },
  { amount: 7, unit: "day" },
  { amount: 4.34524, unit: "week" },
  { amount: 12, unit: "month" },
  { amount: Number.POSITIVE_INFINITY, unit: "year" },
];

/** "2 hours ago", "just now", "in 3 days" — from an epoch-seconds timestamp. */
export function formatRelative(epochSeconds: number, now = Date.now()): string {
  let delta = epochSeconds - now / 1000;
  if (Math.abs(delta) < 45) return "just now";
  for (const { amount, unit } of DIVISIONS) {
    if (Math.abs(delta) < amount) return RELATIVE.format(Math.round(delta), unit);
    delta /= amount;
  }
  return RELATIVE.format(Math.round(delta), "year");
}

/** Full localized date+time, used for the title/hover tooltip. */
export function formatAbsolute(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toLocaleString();
}

/** ISO 8601 string for a `<time dateTime>` attribute. */
export function toIso(epochSeconds: number): string {
  return new Date(epochSeconds * 1000).toISOString();
}
