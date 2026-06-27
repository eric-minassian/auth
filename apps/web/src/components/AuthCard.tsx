import {
  Card,
  CardContent,
  CardDescription,
  CardFooter,
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
        <CardTitle>
          <h1>{props.title}</h1>
        </CardTitle>
        {props.description ? <CardDescription>{props.description}</CardDescription> : null}
      </CardHeader>
      <CardContent className="flex flex-col gap-4">{props.children}</CardContent>
      {props.footer ? (
        <CardFooter className="text-muted-foreground justify-center border-t text-center text-xs">
          {props.footer}
        </CardFooter>
      ) : null}
    </Card>
  );
}
