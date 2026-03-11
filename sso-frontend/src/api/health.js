import http from "./http.js";

/**
 * Health Check API — /api/v1/health
 */
export const healthApi = {
  /**
   * GET /api/v1/health
   * Returns a plain-text confirmation that the SSO server is running.
   * No authentication required.
   */
  check() {
    return http.get("/health");
  },
};
