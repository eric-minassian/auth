import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
  AlertDialogTrigger,
} from "@eric-minassian/design/components/alert-dialog";
import type { ReactNode } from "react";

/**
 * A destructive action gated behind an AlertDialog confirmation. Reused for
 * removing passkeys, revoking sessions, and deleting the account.
 */
export function ConfirmDelete(props: {
  title: string;
  description: string;
  onConfirm: () => void | Promise<void>;
  /** The element that opens the dialog. Defaults to a ghost "Remove" button. */
  trigger: ReactNode;
  confirmLabel?: string;
}) {
  return (
    <AlertDialog>
      <AlertDialogTrigger asChild>{props.trigger}</AlertDialogTrigger>
      <AlertDialogContent>
        <AlertDialogHeader>
          <AlertDialogTitle>{props.title}</AlertDialogTitle>
          <AlertDialogDescription>{props.description}</AlertDialogDescription>
        </AlertDialogHeader>
        <AlertDialogFooter>
          <AlertDialogCancel size="sm">Cancel</AlertDialogCancel>
          <AlertDialogAction size="sm" variant="destructive" onClick={() => void props.onConfirm()}>
            {props.confirmLabel ?? "Delete"}
          </AlertDialogAction>
        </AlertDialogFooter>
      </AlertDialogContent>
    </AlertDialog>
  );
}
