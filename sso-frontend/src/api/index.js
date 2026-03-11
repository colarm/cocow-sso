/**
 * Central re-export for all API modules.
 *
 * Usage:
 *   import { authApi, userApi, clientApi, oauthApi, healthApi } from "@/api";
 * or import individual modules:
 *   import { authApi } from "@/api/auth.js";
 */
export { authApi } from "./auth.js";
export { userApi } from "./user.js";
export { clientApi } from "./client.js";
export { oauthApi } from "./oauth.js";
export { healthApi } from "./health.js";
export { adminApi } from "./admin.js";
export { default as http } from "./http.js";
