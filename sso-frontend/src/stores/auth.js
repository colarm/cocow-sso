import { defineStore } from "pinia";
import { ref } from "vue";
import { authApi, userApi } from "../api/auth.js";

export const useAuthStore = defineStore("auth", () => {
  const user = ref(null); // { id, username, email, enabled, locked, createdAt }
  const loading = ref(false);
  const error = ref(null);

  function clearError() {
    error.value = null;
  }

  async function login(username, password, rememberMe) {
    loading.value = true;
    error.value = null;
    try {
      await authApi.login({ username, password }, rememberMe);
      await fetchUser();
      return true;
    } catch (e) {
      error.value =
        e.response?.data?.message || e.response?.data || "Login failed";
      return false;
    } finally {
      loading.value = false;
    }
  }

  async function register(username, email, password, rememberMe) {
    loading.value = true;
    error.value = null;
    try {
      await authApi.register({ username, email, password }, rememberMe);
      await fetchUser();
      return true;
    } catch (e) {
      error.value =
        e.response?.data?.message || e.response?.data || "Registration failed";
      return false;
    } finally {
      loading.value = false;
    }
  }

  async function logout() {
    loading.value = true;
    error.value = null;
    try {
      await authApi.logout();
    } catch (_) {
      // even if the server call fails, clear local state
    } finally {
      user.value = null;
      loading.value = false;
    }
  }

  async function fetchUser() {
    try {
      const res = await userApi.getInfo();
      user.value = res.data;
    } catch (_) {
      user.value = null;
    }
  }

  const isAuthenticated = () => !!user.value;

  return {
    user,
    loading,
    error,
    login,
    register,
    logout,
    fetchUser,
    isAuthenticated,
    clearError,
  };
});
