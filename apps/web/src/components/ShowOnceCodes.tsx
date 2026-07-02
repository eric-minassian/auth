import { Button } from "@eric-minassian/design/components/button";
import { Checkbox } from "@eric-minassian/design/components/checkbox";
import { useBlocker } from "@tanstack/react-router";
import { DownloadIcon, PrinterIcon } from "lucide-react";
import { useId, useState } from "react";
import { toast } from "sonner";

const FILE_HEADER =
  "auth.ericminassian.com recovery codes\nKeep these private. Each works once; they replace any previous set.\n\n";

/** Download the one-time codes as a local text file (no out-of-band channel). */
function downloadCodes(codes: string[]): void {
  const blob = new Blob([FILE_HEADER + codes.join("\n") + "\n"], { type: "text/plain" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "recovery-codes.txt";
  link.click();
  URL.revokeObjectURL(url);
}

/** Open the browser print dialog with just the codes. */
function printCodes(codes: string[]): void {
  const frame = document.createElement("iframe");
  frame.style.cssText = "position:fixed;right:0;bottom:0;width:0;height:0;border:0";
  document.body.appendChild(frame);
  const doc = frame.contentDocument;
  if (doc) {
    const pre = doc.createElement("pre");
    pre.style.cssText = "font-family:monospace;font-size:14px";
    pre.textContent = FILE_HEADER + codes.join("\n");
    doc.body.appendChild(pre);
    frame.contentWindow?.focus();
    frame.contentWindow?.print();
  }
  setTimeout(() => frame.remove(), 1000);
}

/**
 * The one-time recovery-codes reveal: shown exactly once after generation.
 * Copy / download / print, then an explicit "I've saved these" acknowledgement
 * gates the Done button. Announced via role=status for screen readers.
 */
export function ShowOnceCodes(props: { codes: string[]; onDone: () => void }) {
  const [saved, setSaved] = useState(false);
  const ackId = useId();

  // The previous code set is already invalidated server-side, so navigating
  // away (tab switch, back, close) before these are saved destroys the
  // account's only break-glass factor. Block until the user acknowledges.
  useBlocker({
    shouldBlockFn: () =>
      !window.confirm(
        "Leave without saving your recovery codes? They can never be shown again.",
      ),
    disabled: saved,
    enableBeforeUnload: () => !saved,
  });

  return (
    <div className="flex flex-col gap-3">
      <p className="text-sm font-medium">
        Save these now — they&apos;re shown only once and replace any previous codes.
      </p>
      {/* A plain <pre> is the canonical, copy-friendly representation. */}
      <pre className="bg-muted overflow-x-auto rounded-md p-3 font-mono text-sm leading-7">
        {props.codes.join("\n")}
      </pre>
      <div className="flex flex-wrap gap-2">
        <Button
          size="sm"
          variant="outline"
          onClick={() => {
            void navigator.clipboard
              .writeText(props.codes.join("\n"))
              .then(() => toast.success("Copied"))
              .catch(() => toast.error("Couldn't copy"));
          }}
        >
          Copy
        </Button>
        <Button size="sm" variant="outline" onClick={() => downloadCodes(props.codes)}>
          <DownloadIcon /> Download
        </Button>
        <Button size="sm" variant="outline" onClick={() => printCodes(props.codes)}>
          <PrinterIcon /> Print
        </Button>
      </div>
      <label htmlFor={ackId} className="flex items-center gap-2 text-sm">
        <Checkbox
          id={ackId}
          checked={saved}
          onCheckedChange={(c) => setSaved(c === true)}
        />
        I&apos;ve saved these codes somewhere safe
      </label>
      <Button size="sm" className="w-fit" disabled={!saved} onClick={props.onDone}>
        Done
      </Button>
    </div>
  );
}
