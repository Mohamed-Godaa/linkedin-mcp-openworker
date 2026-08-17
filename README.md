# LinkedIn MCP for OpenWorker

A local-first LinkedIn MCP server for OpenWorker. It runs over stdio, keeps tokens in environment variables or explicit tool inputs, and exposes small, approval-friendly tools for LinkedIn profile reads and post operations.

## Tools

- `linkedin_start_oauth_flow` starts the browser OAuth flow, captures the localhost callback, exchanges the code, and stores the token locally.
- `linkedin_auth_status` reports whether a stored token exists and when it expires.
- `linkedin_logout` deletes the stored token.
- `linkedin_exchange_authorization_code` exchanges an OAuth code and stores the token, for manual fallback flows.
- `linkedin_get_my_profile` reads the authenticated member profile from `/v2/userinfo`.
- `linkedin_create_text_post` publishes or drafts a text-only post through `/rest/posts`.
- `linkedin_get_post` retrieves a post by URN.
- `linkedin_find_posts_by_author` lists posts for a member or organization URN.

## Setup

```powershell
npm i linkedin-mcp-openworker
```

Create a LinkedIn developer app and request the products/scopes you need:

- `openid profile email` for Sign In with LinkedIn using OpenID Connect.
- `w_member_social` to publish as the authenticated member.
- Organization posting requires LinkedIn-approved organization scopes such as `w_organization_social`.

OpenWorker supports MCP servers through `Manage -> Integrations` using the same `mcpServers` JSON format as Claude Desktop and Cursor. After building, add a server like this:

```json
{
  "mcpServers": {
    "linkedin": {
      "command": "npm",
      "args": ["linkedin-mcp-openworker"],
      "env": {
        "LINKEDIN_CLIENT_ID": "paste-your-linkedin-client-id-here",
        "LINKEDIN_CLIENT_SECRET": "paste-your-linkedin-client-secret-here",
        "LINKEDIN_REDIRECT_URI": "http://127.0.0.1:33333/linkedin/oauth/callback",
        "LINKEDIN_VERSION": "202607"
      }
    }
  }
}
```

`LINKEDIN_VERSION` defaults to `202607`, matching LinkedIn Marketing API versioning guidance current at the time this project was created.

## OAuth Flow

1. In your LinkedIn developer app, add this authorized redirect URL:

```text
http://127.0.0.1:33333/linkedin/oauth/callback
```

2. Add the MCP server to OpenWorker with `LINKEDIN_CLIENT_ID`, `LINKEDIN_CLIENT_SECRET`, and `LINKEDIN_REDIRECT_URI`.
3. Ask OpenWorker to run `linkedin_start_oauth_flow`.
4. The MCP starts a localhost callback server, opens your browser to LinkedIn, validates the returned `state`, exchanges the authorization code, and stores the token at:

```text
~/.linkedin-mcp-openworker/token.json
```

5. After that, LinkedIn tools automatically use the stored token. Use `linkedin_auth_status` to inspect token status and `linkedin_logout` to delete it.

The default managed flow uses LinkedIn's regular 3-legged OAuth authorization endpoint:

```text
https://www.linkedin.com/oauth/v2/authorization
```

That is the endpoint LinkedIn documents for OpenID Connect. It requests `openid profile email w_member_social` by default, exchanges the authorization code with your `client_secret`, and stores the returned access token and ID token metadata locally. Do not use `auth_method: "pkce"` with OpenID scopes; LinkedIn rejects that combination with `Open ID permission is not supported for PKCE flows.`

LinkedIn's general 3-legged OAuth documentation says redirect URLs should be HTTPS. If LinkedIn rejects the localhost callback URL for your app, use an HTTPS callback/tunnel URL that forwards to this machine and set `LINKEDIN_REDIRECT_URI` to the exact URL registered in the LinkedIn Developer Portal.

By default, OAuth tools redact tokens in tool results. Pass `return_access_token: true` only when you explicitly want a result to include token values.

## Notes

LinkedIn API access depends on the products approved for your developer app. A token without `w_member_social` cannot publish member posts, and organization posts require organization permissions plus an authenticated member with the right page role.
