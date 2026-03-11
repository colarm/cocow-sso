import http from "./http.js";

/**
 * User API — /api/v1/user
 * All endpoints require an active session (authenticated user).
 */
export const userApi = {
  /**
   * GET /api/v1/user/info
   * Returns the current user's profile information.
   * @returns {{ id, username, email, role, createdAt }}
   */
  getInfo() {
    return http.get("/user/info");
  },

  /**
   * PUT /api/v1/user/info
   * Updates the current user's username and/or email.
   * @param {{ username?: string, email?: string }} payload
   */
  updateInfo(payload) {
    return http.put("/user/info", payload);
  },

  /**
   * PATCH /api/v1/user/password
   * Changes the current user's password.
   * @param {{ oldPassword: string, newPassword: string }} payload
   */
  changePassword(payload) {
    return http.patch("/user/password", payload);
  },

  /**
   * DELETE /api/v1/user/account
   * Permanently deletes the current user's account.
   * Requires the user's current password for confirmation.
   * @param {{ password: string }} payload
   */
  deleteAccount(payload) {
    return http.delete("/user/account", { data: payload });
  },
};
