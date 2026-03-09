import axios from "axios";

const http = axios.create({
  baseURL: "/api/v1",
  withCredentials: true, // carry session cookies automatically
  headers: { "Content-Type": "application/json" },
});

export const authApi = {
  /**
   * POST /api/v1/auth/register
   */
  register(payload, rememberMe = false) {
    return http.post(`/auth/register?rememberMe=${rememberMe}`, payload);
  },

  /**
   * POST /api/v1/auth/login
   */
  login(payload, rememberMe = false) {
    return http.post(`/auth/login?rememberMe=${rememberMe}`, payload);
  },

  /**
   * POST /api/v1/auth/logout
   */
  logout() {
    return http.post("/auth/logout");
  },
};

export const userApi = {
  /**
   * GET /api/v1/user/info
   */
  getInfo() {
    return http.get("/user/info");
  },
};

export const clientApi = {
  /**
   * GET /api/v1/clients/info/:clientId
   * Fetch client display name by OAuth2 string clientId.
   * Accessible to any authenticated user — used by the consent screen.
   * Returns { clientId, clientName } or 404 if the client does not exist.
   */
  getClientInfo(clientId) {
    return http.get(`/client/info/${encodeURIComponent(clientId)}`);
  },
};

export const oauthApi = {
  /**
   * POST /api/v1/oauth/authorize
   * Submit the user's approval. Backend validates, generates the auth code,
   * and returns { redirectUri: "https://client/callback?code=XXX&state=YYY" }.
   * The frontend is responsible for the final window.location.href redirect.
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
   * Build the deny redirect URL on the client side — no backend call needed.
   * Client receives: redirect_uri?error=access_denied[&state=xxx]
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

export default http;
