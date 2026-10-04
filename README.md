# DSA People & Culture portal (live version)

## What to upload
Upload `index.html`, `og.png`, `vercel.json` and `.vercelignore` to your GitHub repo, replacing the old files. Vercel updates the site within a minute.

`vercel.json` adds the security headers (including a Content-Security-Policy). The policy only lets the page's own script run, identified by a fingerprint. **If you edit `index.html`, run `python3 qa/csp.py --fix` before uploading**, or the live page will not load. `python3 qa/csp.py` on its own checks without changing anything.

The `server` folder is the code that runs inside Supabase as the `hr-portal` Edge Function. When it changes, deploy it with `supabase functions deploy hr-portal --no-verify-jwt` (or through the Supabase dashboard).

## Passwords
Passwords are never written in this repository. This repository is public, so anything committed here can be read by anyone.

Change them in **Settings > Passwords**. New passwords:
- need at least 12 characters. A phrase of three or four unrelated words works well.
- are case-sensitive.
- must not be a common word or the clinic's name with numbers added.
- must be different for Admin and Staff.

Staff signed in with the old staff password are signed out straight away.

## How it works
- **One page, live data:** the page is the same single `index.html`. Data comes from your Supabase project "HR - DSA", in tables whose names start with `hr_`.
- **Files:** stored in the private Supabase Storage bucket `hr-files`, up to 25 MB each.
- **Signing in:** happens on the server, which only sends each person what their role allows. Staff never receive staff records, contact details, notes or anything you've hidden.
- **Changes are instant:** posting, hiding, uploading, sharing a document or changing staff access shows for staff straight away. There's nothing to publish.

## Controlling what staff see
- **Whole sections:** Settings > What staff can see turns Announcements, Policies, Documents, Team directory and HR Agent on or off.
- **Policies and announcements:** use **Hide from staff** on the item, or untick **Staff can see this** when editing.
- **Documents:** hidden by default. Tick **Staff can see this** when uploading, or click the people icon next to a file or letter.
- **Checking:** **Preview as staff** shows exactly what staff will see.

## Security tests
`qa/security` holds automated security checks: role isolation, session tampering, XSS, logout, Preview as staff, uploads and passwords. They run against throwaway QA data and never touch the live project.

    cd qa/security && npm install && npx playwright install chromium webkit
    node --test server.test.mjs && node browser.test.mjs

_Last updated: 4 October 2026_
