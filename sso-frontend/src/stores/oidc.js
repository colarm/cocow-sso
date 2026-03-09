import { defineStore } from "pinia";
import { ref, computed } from "vue";

const STORAGE_KEY = "oidc_pending";

function loadFromStorage() {
  try {
    const raw = sessionStorage.getItem(STORAGE_KEY);
    return raw ? JSON.parse(raw) : null;
  } catch {
    return null;
  }
}

/**
 * Holds the OIDC authorization-request params that came in from the client app.
 * Persisted to sessionStorage so they survive the login form redirect.
 */
export const useOidcStore = defineStore("oidc", () => {
  const params = ref(loadFromStorage());

  /**
   * Capture OIDC params from the /oauth/authorize query string.
   * Returns true if the params look valid.
   */
  function capture(query) {
    if (!query.client_id || !query.redirect_uri) return false;
    params.value = {
      responseType: query.response_type ?? "code",
      clientId: query.client_id,
      redirectUri: query.redirect_uri,
      scope: query.scope ?? "openid",
      state: query.state ?? "",
    };
    sessionStorage.setItem(STORAGE_KEY, JSON.stringify(params.value));
    return true;
  }

  function clear() {
    params.value = null;
    sessionStorage.removeItem(STORAGE_KEY);
  }

  const hasPending = computed(() => !!params.value);

  return { params, capture, clear, hasPending };
});
