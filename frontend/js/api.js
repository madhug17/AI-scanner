/**
 * AI App Security & Quality Scanner — API Client
 */

const API_BASE = window.location.origin;

class ApiClient {
  constructor() {
    this.tokenKey = 'ai_scanner_token';
  }

  getToken() {
    return localStorage.getItem(this.tokenKey);
  }

  setToken(token) {
    if (token) {
      localStorage.setItem(this.tokenKey, token);
    } else {
      localStorage.removeItem(this.tokenKey);
    }
  }

  getHeaders(customHeaders = {}) {
    const headers = {
      'Content-Type': 'application/json',
      ...customHeaders,
    };
    const token = this.getToken();
    if (token) {
      headers['Authorization'] = `Bearer ${token}`;
    }
    return headers;
  }

  async request(endpoint, options = {}) {
    const url = `${API_BASE}${endpoint}`;
    const headers = this.getHeaders(options.headers);

    try {
      const response = await fetch(url, { ...options, headers });
      if (!response.ok) {
        let errorDetail = 'API request failed';
        try {
          const errData = await response.json();
          errorDetail = errData.detail || errData.message || JSON.stringify(errData);
        } catch {
          errorDetail = response.statusText;
        }
        throw new Error(errorDetail);
      }
      return await response.json();
    } catch (err) {
      console.error(`[API Error] ${endpoint}:`, err);
      throw err;
    }
  }

  // --- Health & Stats ---
  async getHealth() {
    return this.request('/health');
  }

  async getDashboardStats() {
    return this.request('/api/v1/stats');
  }

  // --- Scans ---
  async submitScan(repositoryUrl) {
    return this.request('/api/v1/scans', {
      method: 'POST',
      body: JSON.stringify({ repository_url: repositoryUrl }),
    });
  }

  async getScanStatus(scanId) {
    return this.request(`/api/v1/scans/${scanId}`);
  }

  async getScanReport(scanId) {
    return this.request(`/api/v1/scans/${scanId}/report`);
  }

  async getScanFindings(scanId, params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/api/v1/scans/${scanId}/findings${query ? '?' + query : ''}`);
  }

  async cancelScan(scanId) {
    return this.request(`/api/v1/scans/${scanId}/cancel`, { method: 'POST' });
  }

  async listScans(page = 1, pageSize = 20) {
    return this.request(`/api/v1/scans?page=${page}&page_size=${pageSize}`);
  }

  async compareScans(scanIdA, scanIdB) {
    return this.request(`/api/v1/scans/${scanIdA}/compare/${scanIdB}`);
  }

  // --- Rules ---
  async getRules() {
    return this.request('/api/v1/rules');
  }

  // --- Findings ---
  async listAllFindings(params = {}) {
    const query = new URLSearchParams(params).toString();
    return this.request(`/findings${query ? '?' + query : ''}`);
  }

  async updateFindingStatus(findingId, status) {
    return this.request(`/findings/${findingId}`, {
      method: 'PATCH',
      body: JSON.stringify({ status }),
    });
  }

  // --- Repositories ---
  async listRepositories(page = 1, pageSize = 20) {
    return this.request(`/repositories?page=${page}&page_size=${pageSize}`);
  }

  async getRepository(repoId) {
    return this.request(`/repositories/${repoId}`);
  }

  // --- Authentication ---
  async register(email, password, fullName = null) {
    const res = await this.request('/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password, full_name: fullName }),
    });
    if (res.access_token) {
      this.setToken(res.access_token);
    }
    return res;
  }

  async login(email, password) {
    const res = await this.request('/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (res.access_token) {
      this.setToken(res.access_token);
    }
    return res;
  }

  async getCurrentUser() {
    const token = this.getToken();
    if (!token) return null;
    try {
      return await this.request('/auth/me');
    } catch {
      this.setToken(null);
      return null;
    }
  }

  logout() {
    this.setToken(null);
  }
}

window.api = new ApiClient();
