# Prompt 24: Public UID discovery

On 2026-11-26, at main commit ef0433f, each page was fetched with a fresh HTTPS client, TLS verification enabled, no credentials, no environment proxy and automatic redirects disabled.

| Public URL | HTTP status | Content type | Bytes |
| --- | --- | --- | --- |
| https://locket.cam/vt.l | 200 | text/html; charset=utf-8 | 8149 |
| https://locket.cam/missing7f1c94bd | 404 | text/html; charset=utf-8 | 3082 |

The successful page contained an invite link, Open Graph tags, an external analytics script and two inline JavaScript blocks. No JSON-LD script or explicit uid, firebase_uid, firebaseUid, user_id or userId field was found in URL-decoded HTML. Both responses returned HTML directly.

A CDN image URL on the profile used the storage path /v0/b/locket-img/o/users/<id>/public/<asset>. The account page associates this image with the profile, but the storage path alone does not establish that the directory name is its Firebase Authentication UID. The Open Graph image references a different bucket under invites. The 404 control had no invite link.

The existing public resolver extracts an invitation token. The separate authenticated lookup was not invoked. Neither identifier length nor a stored mapping was used as identity evidence. The result for vt.l is public_uid_unavailable with firebase_uid null. This describes the research result, not a deployed endpoint.

The research gate requires a publicly attributable Firebase UID before implementing a resolver. There was no second authorized test account with a known public identity binding. No runtime files changed, no tests or staging deployment were run, and no database writes were performed.
