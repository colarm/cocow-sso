import http from "./http.js";

/**
 * OAuth2 / OIDC API — /api/v1/oauth
 */
export const oauthApi = {
  /**
   * POST /api/v1/oauth/authorize
   * Submits the user's approval from the consent screen.
   * Backend validates, generates an authorization code, and returns the full
   * callback URI. The frontend is responsible for the final redirect.
   * @param {{ responseType?, clientId, redirectUri, scope, state?, codeChallenge?, codeChallengeMethod? }} params
   * @returns {{ redirectUri: string }}  full callback URL including code & state
   */
  approve({
    responseType,
    clientId,
    redirectUri,
    scope,
    state,
    codeChallenge,
    codeChallengeMethod,
  }) {
    return http.post("/oauth/authorize", {
      responseType: responseType ?? "code",
      clientId,
      redirectUri,
      scope,
      state,
      codeChallenge: codeChallenge ?? null,
      codeChallengeMethod: codeChallengeMethod ?? null,
    });
  },

  /**
   * POST /api/v1/oauth/token
   * Exchanges an authorization code for access/refresh tokens, or uses a
   * refresh token to obtain a new access token.
   * The backend expects application/x-www-form-urlencoded parameters.
   *
   * Authorization code flow:
   * @param {{ grantType: 'authorization_code', code, redirectUri, clientId, clientSecret, codeVerifier? }} params
   *
   * Refresh token flow:
   * @param {{ grantType: 'refresh_token', refreshToken, clientId, clientSecret }} params
   *
   * @returns {{ access_token, refresh_token, token_type, expires_in, scope }}
   */
  token({
    grantType,
    code,
    redirectUri,
    clientId,
    clientSecret,
    codeVerifier,
    refreshToken,
  }) {
    const form = new URLSearchParams();
    form.set("grant_type", grantType);
    form.set("client_id", clientId);
    form.set("client_secret", clientSecret);
    if (grantType === "authorization_code") {
      if (code) form.set("code", code);
      if (redirectUri) form.set("redirect_uri", redirectUri);
      if (codeVerifier) form.set("code_verifier", codeVerifier);
    } else if (grantType === "refresh_token") {
      if (refreshToken) form.set("refresh_token", refreshToken);
    }
    return http.post("/oauth/token", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },

  /**
   * POST /api/v1/oauth/revoke
   * Revokes an access or refresh token.
   * @param {string} token
   */
  revoke(token) {
    const form = new URLSearchParams({ token });
    return http.post("/oauth/revoke", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },

  /**
   * POST /api/v1/oauth/introspect
   * Introspects a token and returns its active status and metadata.
   * @param {string} token
   * @returns {{ active, client_id?, sub?, scope?, exp? }}
   */
  introspect(token) {
    const form = new URLSearchParams({ token });
    return http.post("/oauth/introspect", form, {
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
    });
  },

  /**
   * GET /api/v1/oauth/userinfo
   * Returns OIDC user claims for the bearer of the given access token.
   * @param {string} accessToken  Bearer token
   */
  getUserInfo(accessToken) {
    return http.get("/oauth/userinfo", {
      headers: { Authorization: `Bearer ${accessToken}` },
    });
  },

  /**
   * GET /api/v1/oauth/.well-known/openid-configuration
   * Returns the OIDC provider metadata (discovery document).
   */
  getDiscoveryDocument() {
    return http.get("/oauth/.well-known/openid-configuration");
  },

  /**
   * GET /api/v1/oauth/.well-known/jwks.json
   * Returns the JSON Web Key Set used to verify JWT signatures.
   */
  getJwks() {
    return http.get("/oauth/.well-known/jwks.json");
  },

  /**
   * Build the deny redirect URL on the client side — no backend call needed.
   * Produces: redirect_uri?error=access_denied[&state=xxx]
   * @param {string} redirectUri
   * @param {string|null} state
   * @returns {string}
   */
  denyRedirectUrl(redirectUri, state) {
    const p = new URLSearchParams({
      error: "access_denied",
      error_description: "User denied access",
    });
    if (state) p.set("state", state);
    return `${redirectUri}?${p.toString()}`;
  },
};
