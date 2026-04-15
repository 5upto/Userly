import axios from 'axios';

const api = axios.create({
  baseURL: import.meta.env.VITE_API_BASE_URL || '/api',
});

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('token');
  if (token) {
    config.headers.Authorization = `Bearer ${token}`;
  }
  return config;
});

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.data?.redirect) {
      // Handle session revocation (SLO or blocked)
      const reason = error.response?.data?.reason;
      const message = error.response?.data?.message;
      
      localStorage.removeItem('token');
      localStorage.removeItem('user');
      
      if (reason === 'blocked') {
        // Show blocked message
        window.location.href = '/login?error=account_blocked&message=' + encodeURIComponent(message || 'Account blocked');
      } else if (reason === 'logout') {
        // Session terminated from IdP
        window.location.href = '/login?message=' + encodeURIComponent(message || 'Session logged out');
      } else {
        window.location.href = '/login';
      }
    }
    return Promise.reject(error);
  }
);

export const userService = {
  getUsers: () => api.get('/users'),
  
  blockUsers: (userIds) => api.patch('/users/block', { userIds }),
  
  unblockUsers: (userIds) => api.patch('/users/unblock', { userIds }),
  
  deleteUsers: (userIds) => api.delete('/users', { data: { userIds } }),
  
  updateUserRole: (userId, role) => api.patch(`/users/${userId}/role`, { role })
};

export default api;