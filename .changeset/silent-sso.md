---
"@ericminassian/auth": minor
---

Add silent SSO. `signInSilently()` attempts authentication through a hidden
`prompt=none` iframe and resolves to the resulting state — picking up an
existing IdP session without a redirect, and never rejecting on
`login_required`. `handleCallback()` is the callback-page entry point: inside a
silent-auth iframe it relays the result to the opener, and at top level it
completes the redirect code exchange like `handleRedirectCallback()`.
