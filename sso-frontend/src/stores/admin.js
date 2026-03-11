import { defineStore } from "pinia";
import { ref } from "vue";
import { adminApi } from "../api/admin.js";

export const useAdminStore = defineStore("admin", () => {
  const users = ref([]);
  const total = ref(0);
  const totalPages = ref(0);
  const page = ref(0);
  const size = ref(20);
  const loading = ref(false);
  const error = ref("");

  function clearError() {
    error.value = "";
  }

  async function fetchUsers(p = page.value) {
    loading.value = true;
    error.value = "";
    try {
      const res = await adminApi.listUsers({ page: p, size: size.value });
      users.value = res.data.users;
      total.value = res.data.total;
      totalPages.value = res.data.total_pages;
      page.value = p;
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to load users";
    } finally {
      loading.value = false;
    }
  }

  async function updateRole(id, role) {
    loading.value = true;
    error.value = "";
    try {
      const res = await adminApi.updateRole(id, role);
      _replace(res.data);
      return { success: true };
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to update role";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function setEnabled(id, enabled) {
    loading.value = true;
    error.value = "";
    try {
      const res = await adminApi.setEnabled(id, enabled);
      _replace(res.data);
      return { success: true };
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to update status";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function setLocked(id, locked) {
    loading.value = true;
    error.value = "";
    try {
      const res = await adminApi.setLocked(id, locked);
      _replace(res.data);
      return { success: true };
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to update lock";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function resetPassword(id, newPassword) {
    loading.value = true;
    error.value = "";
    try {
      await adminApi.resetPassword(id, newPassword);
      return { success: true };
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to reset password";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function deleteUser(id) {
    loading.value = true;
    error.value = "";
    try {
      await adminApi.deleteUser(id);
      users.value = users.value.filter((u) => u.id !== id);
      total.value -= 1;
      return { success: true };
    } catch (e) {
      error.value = e.response?.data?.message ?? "Failed to delete user";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  function _replace(updated) {
    const idx = users.value.findIndex((u) => u.id === updated.id);
    if (idx !== -1) users.value[idx] = updated;
  }

  return {
    users,
    total,
    totalPages,
    page,
    size,
    loading,
    error,
    clearError,
    fetchUsers,
    updateRole,
    setEnabled,
    setLocked,
    resetPassword,
    deleteUser,
  };
});
