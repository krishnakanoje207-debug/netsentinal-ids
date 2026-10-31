# Sign in with Google

Local username/password login works without Google configuration. Google login is
an additional login method for existing accounts; it never creates accounts or
grants permissions from browser-supplied profile fields.

1. In Google Cloud Console, configure the OAuth consent screen and create an OAuth
   client of type **Web application**. If the consent screen is in testing, add the
   intended accounts as test users.
2. Add `http://127.0.0.1:5173` to **Authorized JavaScript origins** for the local
   dashboard. Add `http://localhost:5173` too if you open that address. Origins must
   match the actual scheme, hostname and port. For another deployment, authorize
   its actual HTTPS dashboard origin. This integration uses Google's popup
   credential callback; no redirect URI or client secret is needed.
3. Create the intended users using the administrator's Users page and select
   **Administrator** or **Viewer** separately. Viewers can read alerts and models;
   they cannot change accounts, manage sensors, propose actions or approve them.
   Administrator permissions also remain separate from analyst approval duties.
4. Configure the API environment, using your public OAuth client ID and explicit
   mappings to existing local usernames. For example, in PowerShell before
   starting the API or native local launcher:

   ```powershell
   $env:NETSENTINEL_GOOGLE_CLIENT_ID = 'YOUR_ID.apps.googleusercontent.com'
   $env:NETSENTINEL_GOOGLE_GMAIL_ACCOUNTS = '{"owner@gmail.com":"admin","reader@gmail.com":"viewer"}'
   ```

   These are examples, not pre-authorized accounts. Replace both email addresses
   with the actual users. Gmail addresses must be lowercase. For identities
   outside Gmail, use stable Google subject IDs instead:

   ```powershell
   $env:NETSENTINEL_GOOGLE_ACCOUNTS = '{"GOOGLE_SUBJECT_ID":"local_username"}'
   ```

   The subject is the verified ID token's `sub` claim. Do not authorize other
   domains merely by email address. Do not put Google passwords or OAuth client
   secrets into these variables.
5. Restart the API and reload the login page. The Google button appears when both
   a client ID and at least one identity mapping exist. Without them, the page
   explains that local login is available. For Docker, the API service forwards
   the same three variables from the Compose environment; recreate the service
   after changing them.

The API verifies Google's signature, issuer, audience, token lifetime and verified
email using `google-auth`, then loads the mapped local account and its current
role. Disabled accounts are rejected for both login methods. Unknown identities
receive 401; a provider transport failure returns 503. Tokens and passwords are
not written to the audit log. Live Google login still requires a real OAuth client
and authorized identities; mocked verification tests do not establish that setup.

References: [Google server-side verification](https://developers.google.com/identity/gsi/web/guides/verify-google-id-token),
[Google JavaScript API](https://developers.google.com/identity/gsi/web/reference/js-reference).
