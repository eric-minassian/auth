import { Button } from "@eric-minassian/design/components/button";
import {
  Dialog,
  DialogClose,
  DialogContent,
  DialogDescription,
  DialogFooter,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@eric-minassian/design/components/dialog";
import { Field, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import type { ReactNode } from "react";
import { useState } from "react";

/** Rename a passkey via a proper dialog (replaces a blocking window.prompt). */
export function RenamePasskeyDialog(props: {
  currentName: string;
  onSave: (name: string) => void | Promise<void>;
  trigger: ReactNode;
}) {
  const [open, setOpen] = useState(false);
  const [name, setName] = useState(props.currentName);

  // Reset the field to the current name whenever the dialog (re)opens.
  function onOpenChange(next: boolean) {
    if (next) setName(props.currentName);
    setOpen(next);
  }

  function save() {
    const trimmed = name.trim();
    if (!trimmed || trimmed === props.currentName) {
      setOpen(false);
      return;
    }
    void props.onSave(trimmed);
    setOpen(false);
  }

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogTrigger asChild>{props.trigger}</DialogTrigger>
      <DialogContent>
        <DialogHeader>
          <DialogTitle>Rename passkey</DialogTitle>
          <DialogDescription>A label to help you recognize this device.</DialogDescription>
        </DialogHeader>
        <Field>
          <FieldLabel htmlFor="passkey-name">Passkey name</FieldLabel>
          <Input
            id="passkey-name"
            value={name}
            autoFocus
            onChange={(e) => setName(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter") save();
            }}
          />
        </Field>
        <DialogFooter>
          <DialogClose asChild>
            <Button variant="outline" size="sm">
              Cancel
            </Button>
          </DialogClose>
          <Button onClick={save} size="sm" disabled={!name.trim()}>
            Save
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}
