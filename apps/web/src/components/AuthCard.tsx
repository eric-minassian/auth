import {
  Card,
  CardContent,
  CardDescription,
  CardHeader,
  CardTitle,
} from "@eric-minassian/design/components/card";
import type { ReactNode } from "react";

export function AuthCard(props: {
  title: string;
  description?: string;
  children: ReactNode;
  footer?: ReactNode;
}) {
  return (
    <Card className="w-full max-w-sm">
      <CardHeader>
        <CardTitle>{props.title}</CardTitle>
        {props.description ? <CardDescription>{props.description}</CardDescription> : null}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">{props.children}</CardContent>
      {props.footer ? (
        <div className="text-muted-foreground border-t px-6 py-4 text-center text-sm">
          {props.footer}
        </div>
      ) : null}
    </Card>
  );
}
