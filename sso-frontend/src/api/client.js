import http from "./http.js";

/**
 * Client Management API — /api/v1/client
 * Most endpoints require ADMIN or CLIENT_ADMIN role.
 * Exception: GET /info/:clientId is accessible to any authenticated user.
 */
export const clientApi = {
  /**
   * POST /api/v1/client
   * Registers a new OAuth2 client application.
   * Requires ADMIN or CLIENT_ADMIN role.
   * @param {{ clientName: string, clientType: string, redirectUris: string[], scopes: string[] }} payload
   * @returns {{ id, clientId, clientSecret, clientName, clientType, redirectUris, scopes, enabled }}
   */
  register(payload) {
    return http.post("/client", payload);
  },

  /**
   * GET /api/v1/client
   * Lists all registered OAuth2 clients.
   * Requires ADMIN role.
   */
  listAll() {
    return http.get("/client");
  },

  /**
   * GET /api/v1/client/:id
   * Retrieves a client by its numeric database ID.
   * Requires access to the specific client (owner or ADMIN).
   * @param {number} id  numeric database ID
   */
  getById(id) {
    return http.get(`/client/${id}`);
  },

  /**
   * GET /api/v1/client/info/:clientId
   * Fetches the display name for an OAuth2 string clientId.
   * Accessible to any authenticated user — used by the consent screen.
   * @param {string} clientId  OAuth2 string client identifier
   * @returns {{ clientId, clientName }}
   */
  getClientInfo(clientId) {
    return http.get(`/client/info/${encodeURIComponent(clientId)}`);
  },

  /**
   * GET /api/v1/client/allowed-scopes
   * Returns the list of scopes that clients are permitted to request,
   * along with their human-readable descriptions.
   * @returns {{ scopes: string[], description: Record<string, string> }}
   */
  getAllowedScopes() {
    return http.get("/client/allowed-scopes");
  },

  /**
   * PUT /api/v1/client/:id
   * Updates a client's name, redirect URIs, or scopes.
   * @param {number} id
   * @param {{ clientName?: string, redirectUris?: string[], scopes?: string[] }} payload
   */
  update(id, payload) {
    return http.put(`/client/${id}`, payload);
  },

  /**
   * POST /api/v1/client/:id/regenerate-secret
   * Generates a new client_secret, invalidating the previous one.
   * @param {number} id
   */
  regenerateSecret(id) {
    return http.post(`/client/${id}/regenerate-secret`);
  },

  /**
   * PATCH /api/v1/client/:id/enable
   * Enables a previously disabled client.
   * @param {number} id
   */
  enable(id) {
    return http.patch(`/client/${id}/enable`);
  },

  /**
   * PATCH /api/v1/client/:id/disable
   * Disables a client without deleting it.
   * @param {number} id
   */
  disable(id) {
    return http.patch(`/client/${id}/disable`);
  },

  /**
   * DELETE /api/v1/client/:id
   * Permanently deletes a client.
   * @param {number} id
   */
  remove(id) {
    return http.delete(`/client/${id}`);
  },
};
