import { formatAbsolute, formatRelative, toIso } from "../lib/time.js";

/**
 * A timestamp rendered as a semantic `<time>` element: concise relative text
 * ("2 hours ago") with the full date+time as the native hover/`title` tooltip.
 */
export function Time(props: { at: number; className?: string }) {
  return (
    <time dateTime={toIso(props.at)} title={formatAbsolute(props.at)} className={props.className}>
      {formatRelative(props.at)}
    </time>
  );
}
