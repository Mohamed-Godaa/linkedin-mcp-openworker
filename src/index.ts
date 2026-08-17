#!/usr/bin/env node
import { spawn } from "node:child_process";
import { randomBytes, createHash } from "node:crypto";
import { promises as fs } from "node:fs";
import { createServer as createHttpServer, type IncomingMessage, type ServerResponse } from "node:http";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { McpServer } from "@modelcontextprotocol/server";
import { serveStdio } from "@modelcontextprotocol/server/stdio";
import * as z from "zod/v4";

const LINKEDIN_API_BASE = "https://api.linkedin.com";
const LINKEDIN_AUTH_BASE = "https://www.linkedin.com";
const DEFAULT_LINKEDIN_VERSION = "202607";
const DEFAULT_SCOPES = ["openid", "profile", "email", "w_member_social"];
const DEFAULT_REDIRECT_URI = "http://127.0.0.1:33333/linkedin/oauth/callback";
const TOKEN_FILE = join(homedir(), ".linkedin-mcp-openworker", "token.json");

type JsonObject = Record<string, unknown>;
type StoredToken = {
  access_token: string;
  expires_at?: number;
  refresh_token?: string;
  refresh_token_expires_at?: number;
  scope?: string;
  token_type?: string;
  created_at: string;
};

class LinkedInApiError extends Error {
  constructor(
    message: string,
    readonly status: number,
    readonly body: string
  ) {
    super(message);
  }
}

function env(name: string): string | undefined {
  const value = process.env[name];
  return value && value.trim() ? value.trim() : undefined;
}

function linkedinVersion(): string {
  return env("LINKEDIN_VERSION") ?? DEFAULT_LINKEDIN_VERSION;
}

async function accessToken(explicitToken?: string): Promise<string> {
  const stored = await readStoredToken();
  const token = explicitToken?.trim() || env("LINKEDIN_ACCESS_TOKEN") || stored?.access_token;
  if (!token) {
    throw new Error(
      "Not authenticated with LinkedIn. Run linkedin_start_oauth_flow, set LINKEDIN_ACCESS_TOKEN, or pass access_token for this call."
    );
  }
  if (!explicitToken && !env("LINKEDIN_ACCESS_TOKEN") && stored?.expires_at && Date.now() > stored.expires_at) {
    throw new Error("Stored LinkedIn access token is expired. Run linkedin_start_oauth_flow again.");
  }
  return token;
}

function jsonText(value: unknown): string {
  return JSON.stringify(value, null, 2);
}

function textResult(text: string, structuredContent?: JsonObject) {
  return {
    content: [{ type: "text" as const, text }],
    ...(structuredContent ? { structuredContent } : {})
  };
}

function errorResult(error: unknown) {
  const text =
    error instanceof LinkedInApiError
      ? `LinkedIn API error ${error.status}: ${error.body || error.message}`
      : error instanceof Error
        ? error.message
        : String(error);
  return {
    isError: true,
    content: [{ type: "text" as const, text }]
  };
}

function memberHeaders(token: string): HeadersInit {
  return {
    Authorization: `Bearer ${token}`
  };
}

function restHeaders(token: string, contentType = false): HeadersInit {
  return {
    Authorization: `Bearer ${token}`,
    "Linkedin-Version": linkedinVersion(),
    "X-Restli-Protocol-Version": "2.0.0",
    ...(contentType ? { "Content-Type": "application/json" } : {})
  };
}

async function readJsonResponse(response: Response): Promise<unknown> {
  const text = await response.text();
  if (!response.ok) {
    throw new LinkedInApiError(response.statusText, response.status, text);
  }
  if (!text) {
    return {};
  }
  try {
    return JSON.parse(text);
  } catch {
    return { raw: text };
  }
}

async function readStoredToken(): Promise<StoredToken | undefined> {
  try {
    const text = await fs.readFile(TOKEN_FILE, "utf8");
    return JSON.parse(text) as StoredToken;
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code === "ENOENT") {
      return undefined;
    }
    throw error;
  }
}

async function writeStoredToken(tokenResponse: JsonObject): Promise<StoredToken> {
  const now = Date.now();
  const expiresIn = typeof tokenResponse.expires_in === "number" ? tokenResponse.expires_in : undefined;
  const refreshExpiresIn =
    typeof tokenResponse.refresh_token_expires_in === "number"
      ? tokenResponse.refresh_token_expires_in
      : undefined;
  const access = tokenResponse.access_token;
  if (typeof access !== "string" || !access) {
    throw new Error("LinkedIn token response did not include an access_token.");
  }

  const stored: StoredToken = {
    access_token: access,
    expires_at: expiresIn ? now + expiresIn * 1000 : undefined,
    refresh_token:
      typeof tokenResponse.refresh_token === "string" ? tokenResponse.refresh_token : undefined,
    refresh_token_expires_at: refreshExpiresIn ? now + refreshExpiresIn * 1000 : undefined,
    scope: typeof tokenResponse.scope === "string" ? tokenResponse.scope : undefined,
    token_type: typeof tokenResponse.token_type === "string" ? tokenResponse.token_type : undefined,
    created_at: new Date(now).toISOString()
  };

  await fs.mkdir(dirname(TOKEN_FILE), { recursive: true });
  await fs.writeFile(TOKEN_FILE, JSON.stringify(stored, null, 2), { mode: 0o600 });
  return stored;
}

function safeTokenStatus(token: StoredToken | undefined): JsonObject {
  return {
    authenticated: Boolean(token?.access_token),
    token_file: TOKEN_FILE,
    created_at: token?.created_at,
    expires_at: token?.expires_at ? new Date(token.expires_at).toISOString() : undefined,
    refresh_token_expires_at: token?.refresh_token_expires_at
      ? new Date(token.refresh_token_expires_at).toISOString()
      : undefined,
    scope: token?.scope,
    has_refresh_token: Boolean(token?.refresh_token)
  };
}

function randomUrlSafe(bytes = 32): string {
  return randomBytes(bytes).toString("base64url");
}

function pkceChallenge(verifier: string): string {
  return createHash("sha256").update(verifier).digest("base64url");
}

function openBrowser(url: string): boolean {
  const command =
    process.platform === "win32" ? "rundll32" : process.platform === "darwin" ? "open" : "xdg-open";
  const args = process.platform === "win32" ? ["url.dll,FileProtocolHandler", url] : [url];
  try {
    const child = spawn(command, args, {
      detached: true,
      stdio: "ignore",
      windowsHide: true
    });
    child.unref();
    return true;
  } catch {
    return false;
  }
}

function writeCallbackResponse(response: ServerResponse, statusCode: number, message: string) {
  response.writeHead(statusCode, { "Content-Type": "text/html; charset=utf-8" });
  response.end(`<!doctype html>
<html lang="en">
<head><meta charset="utf-8"><title>LinkedIn MCP OAuth</title></head>
<body style="font-family: system-ui, sans-serif; margin: 3rem;">
<h1>LinkedIn MCP</h1>
<p>${message}</p>
<p>You can close this tab and return to OpenWorker.</p>
</body>
</html>`);
}

function waitForOAuthCallback(
  redirectUri: string,
  expectedState: string,
  timeoutMs: number
): Promise<{ code: string }> {
  const redirect = new URL(redirectUri);
  const port = Number(redirect.port);
  if (redirect.hostname !== "127.0.0.1" && redirect.hostname !== "localhost") {
    throw new Error("Managed browser OAuth requires a localhost or 127.0.0.1 redirect_uri.");
  }
  if (!port) {
    throw new Error("Managed browser OAuth redirect_uri must include an explicit port.");
  }

  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      server.close();
      reject(new Error("Timed out waiting for LinkedIn OAuth callback."));
    }, timeoutMs);

    const finish = (error?: Error, code?: string) => {
      clearTimeout(timeout);
      server.close();
      if (error) {
        reject(error);
      } else if (code) {
        resolve({ code });
      } else {
        reject(new Error("OAuth callback did not include a code."));
      }
    };

    const server = createHttpServer((request: IncomingMessage, response: ServerResponse) => {
      try {
        const requestUrl = new URL(request.url ?? "/", redirect.origin);
        if (requestUrl.pathname !== redirect.pathname) {
          response.writeHead(404);
          response.end("Not found");
          return;
        }

        const state = requestUrl.searchParams.get("state");
        const code = requestUrl.searchParams.get("code");
        const oauthError = requestUrl.searchParams.get("error");
        const oauthDescription = requestUrl.searchParams.get("error_description");

        if (state !== expectedState) {
          writeCallbackResponse(response, 401, "Authentication failed: OAuth state did not match.");
          finish(new Error("OAuth state did not match. Aborting to prevent CSRF."));
          return;
        }
        if (oauthError) {
          writeCallbackResponse(response, 400, `LinkedIn returned: ${oauthError}`);
          finish(new Error(`LinkedIn OAuth error: ${oauthError}${oauthDescription ? ` - ${oauthDescription}` : ""}`));
          return;
        }
        if (!code) {
          writeCallbackResponse(response, 400, "Authentication failed: missing authorization code.");
          finish(new Error("OAuth callback was missing an authorization code."));
          return;
        }

        writeCallbackResponse(response, 200, "Authentication complete.");
        finish(undefined, code);
      } catch (error) {
        writeCallbackResponse(response, 500, "Authentication failed.");
        finish(error instanceof Error ? error : new Error(String(error)));
      }
    });

    server.once("error", error => {
      clearTimeout(timeout);
      reject(error);
    });
    server.listen(port, redirect.hostname);
  });
}

async function exchangeAuthorizationCode(input: {
  client_id: string;
  redirect_uri: string;
  code: string;
  client_secret?: string;
  code_verifier?: string;
}): Promise<JsonObject> {
  const body = new URLSearchParams({
    grant_type: "authorization_code",
    code: input.code,
    redirect_uri: input.redirect_uri,
    client_id: input.client_id
  });
  if (input.client_secret) {
    body.set("client_secret", input.client_secret);
  }
  if (input.code_verifier) {
    body.set("code_verifier", input.code_verifier);
  }
  const response = await fetch(new URL("/oauth/v2/accessToken", LINKEDIN_AUTH_BASE), {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body
  });
  return (await readJsonResponse(response)) as JsonObject;
}

function redactTokenResponse(tokenResponse: JsonObject, returnAccessToken: boolean): JsonObject {
  return {
    ...tokenResponse,
    access_token:
      returnAccessToken && typeof tokenResponse.access_token === "string"
        ? tokenResponse.access_token
        : tokenResponse.access_token
          ? "[redacted]"
          : undefined,
    id_token:
      returnAccessToken && typeof tokenResponse.id_token === "string"
        ? tokenResponse.id_token
        : tokenResponse.id_token
          ? "[redacted]"
          : undefined,
    refresh_token:
      returnAccessToken && typeof tokenResponse.refresh_token === "string"
        ? tokenResponse.refresh_token
        : tokenResponse.refresh_token
          ? "[redacted]"
          : undefined
  };
}

async function linkedInGet(path: string, token: string, params?: URLSearchParams): Promise<unknown> {
  const url = new URL(path, LINKEDIN_API_BASE);
  if (params) {
    url.search = params.toString();
  }
  const response = await fetch(url, {
    method: "GET",
    headers: path.startsWith("/rest/") ? restHeaders(token) : memberHeaders(token)
  });
  return readJsonResponse(response);
}

async function linkedInPost(path: string, token: string, body: unknown): Promise<JsonObject> {
  const response = await fetch(new URL(path, LINKEDIN_API_BASE), {
    method: "POST",
    headers: restHeaders(token, true),
    body: JSON.stringify(body)
  });
  const data = await readJsonResponse(response);
  const postId = response.headers.get("x-restli-id");
  return {
    status: response.status,
    ...(postId ? { id: postId } : {}),
    response: data
  };
}

function buildPostBody(input: {
  author_urn: string;
  commentary: string;
  visibility: "PUBLIC" | "CONNECTIONS";
  lifecycle_state: "PUBLISHED" | "DRAFT";
  reshare_parent_urn?: string;
}) {
  return {
    author: input.author_urn,
    commentary: input.commentary,
    visibility: input.visibility,
    distribution: {
      feedDistribution: "MAIN_FEED",
      targetEntities: [],
      thirdPartyDistributionChannels: []
    },
    lifecycleState: input.lifecycle_state,
    isReshareDisabledByAuthor: false,
    ...(input.reshare_parent_urn
      ? { reshareContext: { parent: input.reshare_parent_urn } }
      : {})
  };
}

function createServer() {
  const server = new McpServer(
    { name: "linkedin-mcp-openworker", version: "0.1.0" },
    {
      instructions:
        "Use LinkedIn tools only for the authenticated user's intended LinkedIn work. Draft or preview copy before publishing. Write tools require explicit user intent because they can publish to LinkedIn."
    }
  );

  server.registerTool(
    "linkedin_start_oauth_flow",
    {
      description:
        "Start a browser-based LinkedIn OAuth flow, capture the localhost callback, exchange the code, and store the token locally.",
      inputSchema: z.object({
        client_id: z.string().min(1).optional().describe("Defaults to LINKEDIN_CLIENT_ID."),
        client_secret: z.string().min(1).optional().describe("Defaults to LINKEDIN_CLIENT_SECRET."),
        redirect_uri: z
          .string()
          .url()
          .default(env("LINKEDIN_REDIRECT_URI") ?? DEFAULT_REDIRECT_URI)
          .describe("Loopback redirect URI registered in the LinkedIn app."),
        scopes: z
          .array(z.string().min(1))
          .default(DEFAULT_SCOPES)
          .describe("OAuth scopes to request. Defaults include OIDC profile/email and w_member_social."),
        auth_method: z
          .enum(["pkce", "client_secret"])
          .default("client_secret")
          .describe("Use client_secret for OpenID Connect. PKCE is only for non-OpenID native OAuth scopes."),
        timeout_seconds: z.number().int().min(30).max(600).default(180),
        return_access_token: z
          .boolean()
          .default(false)
          .describe("When false, tokens are redacted from the tool result.")
      }),
      annotations: {
        title: "Start LinkedIn OAuth Flow",
        readOnlyHint: false,
        openWorldHint: true
      }
    },
    async ({ client_id, client_secret, redirect_uri, scopes, auth_method, timeout_seconds, return_access_token }) => {
      try {
        const resolvedClientId = client_id ?? env("LINKEDIN_CLIENT_ID");
        const resolvedClientSecret = client_secret ?? env("LINKEDIN_CLIENT_SECRET");
        if (!resolvedClientId) {
          throw new Error("Missing client_id. Pass client_id or set LINKEDIN_CLIENT_ID.");
        }
        const usesOpenId = scopes.includes("openid");
        if (usesOpenId && auth_method === "pkce") {
          throw new Error(
            "LinkedIn does not support the openid scope on the native PKCE endpoint. Use auth_method: \"client_secret\" for OpenID Connect."
          );
        }
        if (!resolvedClientSecret && auth_method === "client_secret") {
          throw new Error("Missing client_secret. Pass client_secret or set LINKEDIN_CLIENT_SECRET.");
        }

        const state = randomUrlSafe(24);
        const codeVerifier = auth_method === "pkce" ? randomUrlSafe(64) : undefined;
        const url = new URL(
          auth_method === "pkce" ? "/oauth/native-pkce/authorization" : "/oauth/v2/authorization",
          LINKEDIN_AUTH_BASE
        );
        url.searchParams.set("response_type", "code");
        url.searchParams.set("client_id", resolvedClientId);
        url.searchParams.set("redirect_uri", redirect_uri);
        url.searchParams.set("scope", scopes.join(" "));
        url.searchParams.set("state", state);
        if (auth_method === "client_secret") {
          url.searchParams.set("enable_extended_login", "true");
        }
        if (codeVerifier) {
          url.searchParams.set("code_challenge", pkceChallenge(codeVerifier));
          url.searchParams.set("code_challenge_method", "S256");
        }

        const callbackPromise = waitForOAuthCallback(redirect_uri, state, timeout_seconds * 1000);
        const browser_opened = openBrowser(url.toString());
        const { code } = await callbackPromise;
        const tokenResponse = await exchangeAuthorizationCode({
          client_id: resolvedClientId,
          client_secret: auth_method === "client_secret" ? resolvedClientSecret : undefined,
          redirect_uri,
          code,
          code_verifier: codeVerifier
        });
        const stored = await writeStoredToken(tokenResponse);
        const output = {
          browser_opened,
          authorization_url: browser_opened ? undefined : url.toString(),
          auth_method,
          token: redactTokenResponse(tokenResponse, return_access_token),
          status: safeTokenStatus(stored)
        };
        return textResult(jsonText(output), output);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_auth_status",
    {
      description: "Check whether this MCP server has a stored LinkedIn OAuth token.",
      inputSchema: z.object({}),
      annotations: {
        title: "LinkedIn Auth Status",
        readOnlyHint: true,
        openWorldHint: false
      }
    },
    async () => {
      try {
        const status = safeTokenStatus(await readStoredToken());
        return textResult(jsonText(status), status);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_logout",
    {
      description: "Delete the locally stored LinkedIn OAuth token for this MCP server.",
      inputSchema: z.object({}),
      annotations: {
        title: "LinkedIn Logout",
        destructiveHint: true,
        readOnlyHint: false,
        openWorldHint: false
      }
    },
    async () => {
      try {
        await fs.rm(TOKEN_FILE, { force: true });
        return textResult("Deleted stored LinkedIn token.", { authenticated: false, token_file: TOKEN_FILE });
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_exchange_authorization_code",
    {
      description:
        "Exchange a LinkedIn OAuth authorization code for tokens and store the token locally.",
      inputSchema: z.object({
        client_id: z.string().min(1),
        client_secret: z.string().min(1),
        redirect_uri: z.string().url(),
        code: z.string().min(1),
        return_access_token: z
          .boolean()
          .default(false)
          .describe("When false, access_token is redacted from the tool result.")
      }),
      annotations: {
        title: "Exchange LinkedIn OAuth Code",
        destructiveHint: false,
        readOnlyHint: false,
        openWorldHint: true
      }
    },
    async ({ client_id, client_secret, redirect_uri, code, return_access_token }) => {
      try {
        const tokenResponse = await exchangeAuthorizationCode({
          client_id,
          client_secret,
          redirect_uri,
          code
        });
        await writeStoredToken(tokenResponse);
        const safeResponse = redactTokenResponse(tokenResponse, return_access_token);
        return textResult(jsonText(safeResponse), safeResponse);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_get_my_profile",
    {
      description:
        "Read the authenticated LinkedIn member profile using the OIDC userinfo endpoint.",
      inputSchema: z.object({
        access_token: z.string().optional().describe("Optional token. Defaults to the stored OAuth token, then LINKEDIN_ACCESS_TOKEN.")
      }),
      annotations: {
        title: "Get LinkedIn Profile",
        readOnlyHint: true,
        openWorldHint: true
      }
    },
    async ({ access_token }) => {
      try {
        const profile = (await linkedInGet("/v2/userinfo", await accessToken(access_token))) as JsonObject;
        const subject = typeof profile.sub === "string" ? profile.sub : undefined;
        const output = {
          ...profile,
          suggested_member_author_urn: subject ? `urn:li:person:${subject}` : undefined,
          note:
            "Use suggested_member_author_urn for member posts if your LinkedIn app/product accepts the OIDC subject as the person URN identifier."
        };
        return textResult(jsonText(output), output);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_create_text_post",
    {
      description:
        "Publish or draft a text-only LinkedIn post for a member or organization author URN.",
      inputSchema: z.object({
        commentary: z.string().min(1).max(3000),
        author_urn: z
          .string()
          .regex(/^urn:li:(person|organization):.+$/)
          .describe("Example: urn:li:person:{id} or urn:li:organization:{id}."),
        visibility: z.enum(["PUBLIC", "CONNECTIONS"]).default("PUBLIC"),
        lifecycle_state: z.enum(["PUBLISHED", "DRAFT"]).default("PUBLISHED"),
        reshare_parent_urn: z
          .string()
          .regex(/^urn:li:(share|ugcPost):.+$/)
          .optional()
          .describe("Optional parent post URN to reshare."),
        access_token: z.string().optional().describe("Optional token. Defaults to the stored OAuth token, then LINKEDIN_ACCESS_TOKEN.")
      }),
      annotations: {
        title: "Create LinkedIn Text Post",
        destructiveHint: true,
        readOnlyHint: false,
        openWorldHint: true
      }
    },
    async input => {
      try {
        const result = await linkedInPost(
          "/rest/posts",
          await accessToken(input.access_token),
          buildPostBody(input)
        );
        return textResult(jsonText(result), result);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_get_post",
    {
      description: "Retrieve a LinkedIn post by URN.",
      inputSchema: z.object({
        post_urn: z.string().regex(/^urn:li:(share|ugcPost):.+$/),
        view_context: z.enum(["READER", "AUTHOR"]).default("READER"),
        access_token: z.string().optional().describe("Optional token. Defaults to the stored OAuth token, then LINKEDIN_ACCESS_TOKEN.")
      }),
      annotations: {
        title: "Get LinkedIn Post",
        readOnlyHint: true,
        openWorldHint: true
      }
    },
    async ({ post_urn, view_context, access_token }) => {
      try {
        const data = await linkedInGet(
          `/rest/posts/${encodeURIComponent(post_urn)}`,
          await accessToken(access_token),
          new URLSearchParams({ viewContext: view_context })
        );
        return textResult(jsonText(data), data as JsonObject);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  server.registerTool(
    "linkedin_find_posts_by_author",
    {
      description: "Find LinkedIn posts by member or organization author URN.",
      inputSchema: z.object({
        author_urn: z.string().regex(/^urn:li:(person|organization):.+$/),
        view_context: z.enum(["READER", "AUTHOR"]).default("READER"),
        start: z.number().int().min(0).default(0),
        count: z.number().int().min(1).max(100).default(10),
        access_token: z.string().optional().describe("Optional token. Defaults to the stored OAuth token, then LINKEDIN_ACCESS_TOKEN.")
      }),
      annotations: {
        title: "Find LinkedIn Posts By Author",
        readOnlyHint: true,
        openWorldHint: true
      }
    },
    async ({ author_urn, view_context, start, count, access_token }) => {
      try {
        const params = new URLSearchParams({
          author: author_urn,
          viewContext: view_context,
          start: String(start),
          count: String(count)
        });
        const data = await linkedInGet("/rest/posts", await accessToken(access_token), params);
        return textResult(jsonText(data), data as JsonObject);
      } catch (error) {
        return errorResult(error);
      }
    }
  );

  return server;
}

serveStdio(createServer);
