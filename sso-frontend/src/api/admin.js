import http from "./http.js";

/**
 * Admin Management API — /api/v1/admin
 * All endpoints require ADMIN role.
 */
export const adminApi = {
  /**
   * GET /api/v1/admin/users?page=0&size=20
   * Paginated list of all users.
   * @param {{ page?: number, size?: number }} params
   * @returns {{ users, total, page, size, total_pages }}
   */
  listUsers({ page = 0, size = 20 } = {}) {
    return http.get("/admin/users", { params: { page, size } });
  },

  /**
   * GET /api/v1/admin/users/:id
   * Get a single user's details.
   * @param {number} id
   */
  getUser(id) {
    return http.get(`/admin/users/${id}`);
  },

  /**
   * PATCH /api/v1/admin/users/:id/role
   * Change a user's role.
   * @param {number} id
   * @param {'USER' | 'CLIENT_ADMIN' | 'ADMIN'} role
   */
  updateRole(id, role) {
    return http.patch(`/admin/users/${id}/role`, { role });
  },

  /**
   * PATCH /api/v1/admin/users/:id/enabled
   * Enable or disable a user account.
   * @param {number} id
   * @param {boolean} enabled
   */
  setEnabled(id, enabled) {
    return http.patch(`/admin/users/${id}/enabled`, { enabled });
  },

  /**
   * PATCH /api/v1/admin/users/:id/locked
   * Lock or unlock a user account.
   * @param {number} id
   * @param {boolean} locked
   */
  setLocked(id, locked) {
    return http.patch(`/admin/users/${id}/locked`, { locked });
  },

  /**
   * POST /api/v1/admin/users/:id/reset-password
   * Reset a user's password without requiring the old one.
   * @param {number} id
   * @param {string} newPassword
   */
  resetPassword(id, newPassword) {
    return http.post(`/admin/users/${id}/reset-password`, { newPassword });
  },

  /**
   * DELETE /api/v1/admin/users/:id
   * Hard-delete a user account.
   * @param {number} id
   */
  deleteUser(id) {
    return http.delete(`/admin/users/${id}`);
  },
};
