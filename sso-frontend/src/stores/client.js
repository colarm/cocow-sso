import { defineStore } from "pinia";
import { ref } from "vue";
import { clientApi } from "../api/client.js";

export const useClientStore = defineStore("client", () => {
  const clients = ref([]);
  const loading = ref(false);
  const error = ref(null);
  const allowedScopes = ref([]);
  const scopeDescriptions = ref({});

  function clearError() {
    error.value = null;
  }

  async function fetchAll() {
    loading.value = true;
    error.value = null;
    try {
      const res = await clientApi.listAll();
      clients.value = res.data;
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to load clients";
    } finally {
      loading.value = false;
    }
  }

  async function fetchAllowedScopes() {
    try {
      const res = await clientApi.getAllowedScopes();
      allowedScopes.value = res.data.scopes ?? [];
      scopeDescriptions.value = res.data.description ?? {};
    } catch (_) {}
  }

  async function create(payload) {
    loading.value = true;
    error.value = null;
    try {
      const res = await clientApi.register(payload);
      clients.value.unshift(res.data);
      return { success: true, data: res.data };
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to create client";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function update(id, payload) {
    loading.value = true;
    error.value = null;
    try {
      const res = await clientApi.update(id, payload);
      const idx = clients.value.findIndex((c) => c.id === id);
      if (idx !== -1) clients.value[idx] = res.data;
      return { success: true, data: res.data };
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to update client";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function regenerateSecret(id) {
    loading.value = true;
    error.value = null;
    try {
      const res = await clientApi.regenerateSecret(id);
      const idx = clients.value.findIndex((c) => c.id === id);
      if (idx !== -1) clients.value[idx] = res.data;
      return { success: true, data: res.data };
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to regenerate secret";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function setEnabled(id, enabled) {
    loading.value = true;
    error.value = null;
    try {
      const res = enabled
        ? await clientApi.enable(id)
        : await clientApi.disable(id);
      const idx = clients.value.findIndex((c) => c.id === id);
      if (idx !== -1) clients.value[idx] = res.data;
      return { success: true };
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to update status";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  async function remove(id) {
    loading.value = true;
    error.value = null;
    try {
      await clientApi.remove(id);
      clients.value = clients.value.filter((c) => c.id !== id);
      return { success: true };
    } catch (e) {
      error.value =
        e.response?.data?.error ||
        e.response?.data?.message ||
        "Failed to delete client";
      return { success: false };
    } finally {
      loading.value = false;
    }
  }

  return {
    clients,
    loading,
    error,
    allowedScopes,
    scopeDescriptions,
    clearError,
    fetchAll,
    fetchAllowedScopes,
    create,
    update,
    regenerateSecret,
    setEnabled,
    remove,
  };
});
