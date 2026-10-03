# DSA People & Culture portal (live version)

## What to upload
Upload `index.html` and `og.png` to your GitHub repo, replacing the old files. Vercel updates the site within a minute.

There are no Vercel settings to add. The `server` folder is a copy of the code that runs inside Supabase, kept for reference. You don't need to upload it.

## Passwords
- **Admin:** `mskadmin`
- **Staff:** `mskstaff`

You can change them in **Settings > Passwords**. Staff signed in with the old staff password are signed out straight away.

## How it works
- **One page, live data:** the page is the same single `index.html`. Data comes from your Supabase project, the "roster" project, in tables whose names start with `hr_`.
- **Files:** stored in the private Supabase Storage bucket `hr-files`, up to 25 MB each.
- **Signing in:** happens on the server, which only sends each person what their role allows. Staff never receive staff records, contact details, notes or anything you've hidden.
- **Changes are instant:** posting, hiding, uploading, sharing a document or changing staff access shows for staff straight away. There's nothing to publish.

## Controlling what staff see
- **Whole sections:** Settings > What staff can see turns Announcements, Policies, Documents, Team directory and HR Agent on or off.
- **Policies and announcements:** use **Hide from staff** on the item, or untick **Staff can see this** when editing.
- **Documents:** hidden by default. Tick **Staff can see this** when uploading, or click the people icon next to a file or letter.
- **Checking:** **Preview as staff** shows exactly what staff will see.

_Last updated: 3 October 2026_
