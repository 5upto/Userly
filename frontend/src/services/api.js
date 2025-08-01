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
      localStorage.removeItem('token');
      window.location.href = '/login';
    }
    return Promise.reject(error);
  }
);

export const userService = {
  getUsers: () => api.get('/users'),
  
  blockUsers: (userIds) => api.patch('/users/block', { userIds }),
  
  unblockUsers: (userIds) => api.patch('/users/unblock', { userIds }),
  
  deleteUsers: (userIds) => api.delete('/users', { data: { userIds } })
};

export default api;