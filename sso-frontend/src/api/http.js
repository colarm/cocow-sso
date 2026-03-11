import axios from "axios";

/**
 * Shared Axios instance for all API modules.
 * Base URL: /api/v1
 * Credentials (session cookies) are sent automatically.
 */
const http = axios.create({
  baseURL: "/api/v1",
  withCredentials: true,
  headers: { "Content-Type": "application/json" },
});

export default http;
