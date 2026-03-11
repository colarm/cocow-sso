import { defineStore } from "pinia";
import { ref } from "vue";
import { authApi } from "../api/auth.js";
import { userApi } from "../api/user.js";

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

  async function updateInfo(username, email) {
    loading.value = true;
    error.value = null;
    try {
      const res = await userApi.updateInfo({ username, email });
      user.value = { ...user.value, ...res.data };
      return { success: true };
    } catch (e) {
      error.value =
        e.response?.data?.message || e.response?.data || "Update failed";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function changePassword(oldPassword, newPassword) {
    loading.value = true;
    error.value = null;
    try {
      await userApi.changePassword({ oldPassword, newPassword });
      return { success: true };
    } catch (e) {
      error.value =
        e.response?.data?.message ||
        e.response?.data ||
        "Password change failed";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function deleteAccount(password) {
    loading.value = true;
    error.value = null;
    try {
      await userApi.deleteAccount({ password });
      user.value = null;
      return { success: true };
    } catch (e) {
      error.value =
        e.response?.data?.message ||
        e.response?.data ||
        "Account deletion failed";
      return { success: false };
    } finally {
      loading.value = false;
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
    updateInfo,
    changePassword,
    deleteAccount,
    isAuthenticated,
    clearError,
  };
});
