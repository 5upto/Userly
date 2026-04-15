import axios from 'axios';
import { toast } from 'react-toastify';

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
  async (error) => {
    const status = error.response?.status;
    const message = error.response?.data?.message;
    const redirect = error.response?.data?.redirect;
    const reason = error.response?.data?.reason;

    // Handle Entra block or security group removal
    if (status === 403 && (reason === 'blocked' || reason === 'security_group')) {
      // Determine the appropriate message based on reason from backend
      const toastMessage = reason === 'security_group'
        ? 'Your access has been revoked.'
        : 'Your account has been locked.';

      // Show toast immediately
      toast.error(toastMessage);

      // Wait for toast to be visible then redirect
      await new Promise(resolve => setTimeout(resolve, 3000));

      // Clear tokens and redirect
      localStorage.removeItem('token');
      localStorage.removeItem('refreshToken');
      localStorage.removeItem('user');
      window.location.href = `/login?blocked=true&reason=${reason}`;

      // Return a never-resolving promise to prevent further processing
      return new Promise(() => {});
    }

    // Handle other redirect cases (token expired, etc.)
    if (redirect) {
      localStorage.removeItem('token');
      window.location.href = '/login';
      return new Promise(() => {});
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