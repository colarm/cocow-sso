import http from "./http.js";

/**
 * Authentication API — /api/v1/auth
 */
export const authApi = {
  /**
   * POST /api/v1/auth/register
   * @param {{ username: string, email: string, password: string }} payload
   * @param {boolean} rememberMe  extend session to 30 days when true
   */
  register(payload, rememberMe = false) {
    return http.post(`/auth/register?rememberMe=${rememberMe}`, payload);
  },

  /**
   * POST /api/v1/auth/login
   * @param {{ username: string, password: string }} payload
   * @param {boolean} rememberMe  extend session to 30 days when true
   */
  login(payload, rememberMe = false) {
    return http.post(`/auth/login?rememberMe=${rememberMe}`, payload);
  },

  /**
   * POST /api/v1/auth/logout
   * Invalidates the server-side session.
   */
  logout() {
    return http.post("/auth/logout");
  },
};
