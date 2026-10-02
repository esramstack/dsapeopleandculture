# DSA People & Culture portal

A single static page. No build step, no backend.

## Files
- `index.html`: the whole portal (sign-in, announcements, people, policies, documents, HR Agent).
- `og.png`: the image WhatsApp shows when the link is shared.

## Deploy with GitHub and Vercel
1. Create a **private** GitHub repository and upload both files to its root.
2. In Vercel, choose **Add New > Project**, import the repository, set Framework Preset to **Other**, and deploy. No build command is needed.
3. Name the project `dsa-people-culture` so the address is `https://people.drsalmanaesthetics.com`.

## If your Vercel address is different
WhatsApp needs the full address of the preview image. Open `index.html`, find these two lines near the top, and replace `https://people.drsalmanaesthetics.com` with your real address:

    <meta property="og:url" content="https://people.drsalmanaesthetics.com/">
    <meta property="og:image" content="https://people.drsalmanaesthetics.com/og.png">

Commit the change and Vercel redeploys automatically.

## Checking the WhatsApp preview
- Open `https://YOUR-ADDRESS/og.png` in a browser. The image should load.
- Paste the link into a WhatsApp chat. The card appears after a few seconds.
- WhatsApp caches previews. If you shared the link before fixing anything, test with `https://YOUR-ADDRESS/?v=2`.

## Things to know
- Password: `DSA-People-2026`. Change it on the line marked CHANGE THE PASSWORD HERE.
- The password only hides the page. Anyone with the link can read the staff names and roles in the page source. The two termination notes have been removed from this copy.
- Edits and uploads are saved in each person's browser. Use Settings > Download updated page, then upload the new file to GitHub to share changes with everyone.
- The HR Agent shows its launch card until 1 November 2026. After that it needs an Anthropic API key in Settings on each device.
