# Investigation Report: `eric-minassian/design`

Public GitHub repo (default branch `main`, last pushed 2026-06-12). Sources inspected via `gh api` (file tree, package.json, README, globals.css, components.json, component sources, stories).

## 1. What it is

A **personal design system / component library**, built by vendoring **shadcn/ui** components (the `radix-mira` style, shadcn preset `b5KHubhs8`: sky theme on neutral base, Geist font, small radius `--radius: 0.45rem`). It is NOT a shadcn-style copy-paste registry for consumers and NOT just tokens — it is a real installable npm-style package (`@eric-minassian/design`) that ships compiled ESM + `.d.ts` plus source, with per-component subpath exports. It also includes a full Storybook (stories from the `shadcn-storybook-registry`, `@storybook` namespace in `components.json`) with design-token docs stories (Color, Radius, Shadow, Spacing, Typography), deployed to GitHub Pages via `.github/workflows/deploy-storybook.yml` on push to `main`.

## 2. package.json

- **Name**: `@eric-minassian/design`
- **Version**: `0.1.0`, MIT, `"type": "module"`, `"sideEffects": ["**/*.css"]`
- **Files shipped**: `dist`, `src`, excluding `src/**/*.stories.tsx`
- **Exports map** (per-component, wildcard subpaths; conditions `source` → `src`, `types` → `dist/*.d.ts`, `default` → `dist/*.js`):
  - `./globals.css` → `./src/styles/globals.css`
  - `./components/*` → `src/components/*.tsx` | `dist/components/*.d.ts` | `dist/components/*.js`
  - `./lib/*`, `./hooks/*` — same pattern
  - There is **no root export** — you must import subpaths.
- **Internal imports map**: `#components/*`, `#lib/*`, `#hooks/*` (Node "imports" field with same source/types/default conditions). `tsconfig.json` uses `customConditions: ["source"]` so the repo itself resolves to `src/`.
- **peerDependencies**: `react ^18.0.0 || ^19.0.0`, `react-dom ^18.0.0 || ^19.0.0`, `tailwindcss ^4.0.0`
- **Build**: plain **`tsc -p tsconfig.build.json`** (no tsup/vite bundling) — emits ESM JS + declarations to `dist/`, `rootDir: src`, stories excluded. `tsc` leaves `#` import specifiers untouched; conditional `imports` resolve them at consume time. **`"prepare": "pnpm run build"`** means `dist/` is built automatically on install, including git installs (`dist/` is not committed; no releases exist).
- **Runtime deps** (bundled with package): `radix-ui ^1.5.0` (consolidated package), `@base-ui/react ^1.5.0` (combobox/native-select/direction), `class-variance-authority`, `clsx`, `tailwind-merge`, `tw-animate-css`, `lucide-react`, `cmdk`, `sonner`, `vaul`, `embla-carousel-react`, `input-otp`, `react-day-picker ^9` (pinned via `pnpm-workspace.yaml` overrides; v10 breaks the calendar), `react-resizable-panels`, `recharts 3.8.0`, `date-fns`, `next-themes`, `@fontsource-variable/geist`, `shadcn ^4.11.0` (its `tailwind.css` is imported by globals.css).
- Package manager: `pnpm@11.5.3`.

## 3. Distribution

- **Not published to npm** (registry 404 for `@eric-minassian/design`), no GitHub releases, no publishConfig for GitHub Packages.
- **Intended consumption: git dependency or local path** — README: `pnpm add github:eric-minassian/design` or `pnpm add ~/projects/design`. The `prepare` script makes git installs work by compiling `dist/` post-install.
- Not a copy/registry distribution for consumers; the shadcn CLI + `components.json` are used only *inside this repo* to pull/update components (aliases map to `#components`, `#lib/utils`, etc.).

## 4. Styling approach

- **Tailwind CSS v4** (peer dep `^4.0.0`), CSS-first config — no `tailwind.config.js`; the package's `globals.css` uses `@theme inline` and `@custom-variant`.
- `src/styles/globals.css` does: `@import "tw-animate-css"`, `@import "shadcn/tailwind.css"`, `@import "@fontsource-variable/geist"`, defines `@custom-variant dark (&:is(.dark *))`, maps semantic tokens in `@theme inline` (`--color-background/foreground/primary/secondary/muted/accent/destructive/border/input/ring/card/popover/chart-1..5/sidebar-*`, `--font-sans: 'Geist Variable'`, radius scale `--radius-sm..4xl` derived from `--radius`), and sets token values as **oklch CSS variables** on `:root` (light) and `.dark` (dark). Base layer applies `border-border`, `bg-background text-foreground`, `font-sans`.
- **Dark mode**: class-based — toggle `dark` on `<html>`; compatible with `next-themes` (which is a dependency) or a manual toggle.
- Components use `cva` variants + `cn()` (`clsx` + `tailwind-merge`).

## 5. Full inventory of exports

All imports are per-file: `@eric-minassian/design/components/<name>`, `/hooks/<name>`, `/lib/<name>`.

| Module | Named exports |
|---|---|
| accordion | Accordion, AccordionItem, AccordionTrigger, AccordionContent |
| alert | Alert, AlertTitle, AlertDescription, AlertAction |
| alert-dialog | AlertDialog, AlertDialogAction, AlertDialogCancel, AlertDialogContent, AlertDialogDescription, AlertDialogFooter, AlertDialogHeader, AlertDialogMedia, AlertDialogOverlay, AlertDialogPortal, AlertDialogTitle, AlertDialogTrigger |
| aspect-ratio | AspectRatio |
| avatar | Avatar, AvatarImage, AvatarFallback, AvatarGroup, AvatarGroupCount, AvatarBadge |
| badge | Badge, badgeVariants |
| breadcrumb | Breadcrumb, BreadcrumbList, BreadcrumbItem, BreadcrumbLink, BreadcrumbPage, BreadcrumbSeparator, BreadcrumbEllipsis |
| button | Button, buttonVariants |
| button-group | ButtonGroup, ButtonGroupSeparator, ButtonGroupText, buttonGroupVariants |
| calendar | Calendar, CalendarDayButton |
| card | Card, CardHeader, CardFooter, CardTitle, CardAction, CardDescription, CardContent |
| carousel | type CarouselApi, Carousel, CarouselContent, CarouselItem, CarouselPrevious, CarouselNext, useCarousel |
| chart | ChartContainer, ChartTooltip, ChartTooltipContent, ChartLegend, ChartLegendContent, ChartStyle |
| checkbox | Checkbox |
| collapsible | Collapsible, CollapsibleTrigger, CollapsibleContent |
| combobox | Combobox, ComboboxInput, ComboboxContent, ComboboxList, ComboboxItem, ComboboxGroup, ComboboxLabel, ComboboxCollection, ComboboxEmpty, ComboboxSeparator, ComboboxChips, ComboboxChip, ComboboxChipsInput, ComboboxTrigger, ComboboxValue, useComboboxAnchor |
| command | Command, CommandDialog, CommandInput, CommandList, CommandEmpty, CommandGroup, CommandItem, CommandShortcut, CommandSeparator |
| context-menu | ContextMenu + Trigger/Content/Item/CheckboxItem/RadioItem/Label/Separator/Shortcut/Group/Portal/Sub/SubContent/SubTrigger/RadioGroup |
| dialog | Dialog, DialogClose, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogOverlay, DialogPortal, DialogTitle, DialogTrigger |
| direction | DirectionProvider, useDirection |
| drawer | Drawer, DrawerPortal, DrawerOverlay, DrawerTrigger, DrawerClose, DrawerContent, DrawerHeader, DrawerFooter, DrawerTitle, DrawerDescription |
| dropdown-menu | DropdownMenu + Portal/Trigger/Content/Group/Label/Item/CheckboxItem/RadioGroup/RadioItem/Separator/Shortcut/Sub/SubTrigger/SubContent |
| empty | Empty, EmptyHeader, EmptyTitle, EmptyDescription, EmptyContent, EmptyMedia |
| field | Field, FieldLabel, FieldDescription, FieldError, FieldGroup, FieldLegend, FieldSeparator, FieldSet, FieldContent, FieldTitle |
| hover-card | HoverCard, HoverCardTrigger, HoverCardContent |
| input | Input |
| input-group | InputGroup, InputGroupAddon, InputGroupButton, InputGroupText, InputGroupInput, InputGroupTextarea |
| input-otp | InputOTP, InputOTPGroup, InputOTPSlot, InputOTPSeparator |
| item | Item, ItemMedia, ItemContent, ItemActions, ItemGroup, ItemSeparator, ItemTitle, ItemDescription, ItemHeader, ItemFooter |
| kbd | Kbd, KbdGroup |
| label | Label |
| menubar | Menubar + Portal/Menu/Trigger/Content/Group/Separator/Label/Item/Shortcut/CheckboxItem/RadioGroup/RadioItem/Sub/SubTrigger/SubContent |
| native-select | NativeSelect, NativeSelectOptGroup, NativeSelectOption |
| navigation-menu | NavigationMenu + List/Item/Content/Trigger/Link/Indicator/Viewport, navigationMenuTriggerStyle |
| pagination | Pagination + Content/Ellipsis/Item/Link/Next/Previous |
| popover | Popover, PopoverAnchor, PopoverContent, PopoverDescription, PopoverHeader, PopoverTitle, PopoverTrigger |
| progress | Progress |
| radio-group | RadioGroup, RadioGroupItem |
| resizable | ResizableHandle, ResizablePanel, ResizablePanelGroup |
| scroll-area | ScrollArea, ScrollBar |
| select | Select + Content/Group/Item/Label/ScrollDownButton/ScrollUpButton/Separator/Trigger/Value |
| separator | Separator |
| sheet | Sheet, SheetTrigger, SheetClose, SheetContent, SheetHeader, SheetFooter, SheetTitle, SheetDescription |
| sidebar | Sidebar + 20 subcomponents (Content/Footer/Group/GroupAction/GroupContent/GroupLabel/Header/Input/Inset/Menu/MenuAction/MenuBadge/MenuButton/MenuItem/MenuSkeleton/MenuSub/MenuSubButton/MenuSubItem/Provider/Rail/Separator/Trigger), useSidebar |
| skeleton | Skeleton |
| slider | Slider |
| sonner | Toaster |
| spinner | Spinner |
| switch | Switch |
| table | Table, TableHeader, TableBody, TableFooter, TableHead, TableRow, TableCell, TableCaption |
| tabs | Tabs, TabsList, TabsTrigger, TabsContent, tabsListVariants |
| textarea | Textarea |
| toggle | Toggle, toggleVariants |
| toggle-group | ToggleGroup, ToggleGroupItem |
| tooltip | Tooltip, TooltipContent, TooltipProvider, TooltipTrigger |

**Hooks**: `hooks/use-mobile` → `useIsMobile()` (768px breakpoint). Plus component-scoped hooks `useCarousel`, `useSidebar`, `useComboboxAnchor`, `useDirection`.
**Utilities**: `lib/utils` → `cn(...inputs)` (clsx + tailwind-merge).

There is **no `form.tsx`** — the README explicitly says the registry's `form` item ships no files for the `radix-mira` style; use `field` with your form library.

## 6. Login/signup UI relevance

- **Form primitives**: `Field`, `FieldGroup`, `FieldLabel`, `FieldDescription`, `FieldError`, `FieldSet`, `FieldLegend`, `FieldSeparator`, `FieldContent`, `FieldTitle` from `components/field`, plus `Input`, `Label`, `Checkbox` ("remember me"), `Button`, `Separator` (e.g., "or continue with"), `Spinner` (loading button state), `InputGroup`/`InputGroupAddon`/`InputGroupButton` (password show/hide, icon prefixes), `InputOTP` (2FA/email codes), `Card`/`CardHeader`/`CardTitle`/`CardDescription`/`CardContent`/`CardFooter` (auth card layout), `Alert` (error banners), `Toaster` from `components/sonner` (toasts).
- **Validation integration**: library-agnostic. `FieldError` accepts `errors?: Array<{ message?: string } | undefined>` (or `children`); invalid state is signaled via `data-invalid` on `Field` and `aria-invalid` on `Input`. The repo includes two reference story implementations:
  - **react-hook-form + zod** (`src/components/form-react-hook.stories.tsx`): `useForm({ resolver: zodResolver(schema) })` + `<Controller render={({ field, fieldState }) => <Field data-invalid={fieldState.invalid}>… <FieldError errors={[fieldState.error]} />}` 
  - **TanStack Form + zod** (`src/components/form-tanstack.stories.tsx`): `validators: { onSubmit: schema }`, `<form.Field>` render prop, mapping `field.state.meta.errors` into `FieldError`.
  - Note: `react-hook-form`/`@tanstack/react-form`/`zod`/`@hookform/resolvers` are **devDependencies only** — the consuming app must install its chosen form library itself. zod is overridden to `^4.4.3` in this repo.
- **Layout**: no dedicated page-layout primitives beyond `Card`, `Item`, `Empty`, `Separator`, `Sidebar` — use Tailwind utilities (`min-h-svh flex items-center justify-center`, etc.) for the auth page shell.

## 7. Consuming from a new React + Vite app

```sh
pnpm create vite my-app --template react-ts
cd my-app
pnpm add github:eric-minassian/design   # git dep; prepare script builds dist/ on install
pnpm add tailwindcss @tailwindcss/vite  # Tailwind v4 (peer dep)
# react/react-dom 18 or 19 already present from the Vite template
# for forms (pick one) + schema validation:
pnpm add react-hook-form @hookform/resolvers zod   # or @tanstack/react-form zod
```

`vite.config.ts`:
```ts
import tailwindcss from "@tailwindcss/vite";
import react from "@vitejs/plugin-react";
import { defineConfig } from "vite";

export default defineConfig({ plugins: [react(), tailwindcss()] });
```

`src/index.css` (order matters; `@source` makes Tailwind scan the package for class names):
```css
@import "tailwindcss";
@import "@eric-minassian/design/globals.css";
@source "../node_modules/@eric-minassian/design";
```

Usage:
```tsx
import { Button } from "@eric-minassian/design/components/button";
import { Card, CardContent, CardHeader, CardTitle } from "@eric-minassian/design/components/card";
import { Field, FieldError, FieldGroup, FieldLabel } from "@eric-minassian/design/components/field";
import { Input } from "@eric-minassian/design/components/input";
import { cn } from "@eric-minassian/design/lib/utils";
```

Caveats/notes:
- Per-subpath imports only; no barrel/root import.
- Dark mode: add/remove the `dark` class on `<html>` (manually or with `next-themes`, which the package already depends on).
- The git install relies on pnpm running the `prepare` lifecycle script (pnpm builds git deps by default); the package brings its own TypeScript as needed via `prepare` → `tsc`. If `dist/` is ever missing after install, run the package's build once.
- Geist font loads automatically via `@fontsource-variable/geist` imported in `globals.css`.
- During local development of the design system itself: `pnpm add ~/projects/design` (the repo lives at `/Users/eric/projects/design` per its README convention).