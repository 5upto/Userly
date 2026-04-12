import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api'

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [samlConfigId, setSamlConfigId] = useState(null);
  const [token, setToken] = useState(null);

  useEffect(() => {
    // Fetch SAML config to get the ID for automatic login
    const fetchSamlConfig = async () => {
      try {
        const response = await fetch('https://userly-341i.onrender.com/api/saml/configs');
        const data = await response.json();
        if (data && data.length > 0) {
          setSamlConfigId(data[0].id);
        }
      } catch (error) {
        console.error('Failed to fetch SAML config:', error);
      }
    };

    fetchSamlConfig();

    const storedToken = localStorage.getItem('token');
    if (storedToken) {
      setToken(storedToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
      validateToken();
    } else {
      setLoading(false);
    }
  }, []);

  const validateToken = async () => {
    try {
      const response = await api.get('/users');
      setLoading(false);
      setUser(response.data);
    } catch (error) {
      if (error.response?.data?.redirect) {
        logout();
      }
      setLoading(false);
    }
  };

  // Auto-redirect to SAML login if not authenticated and SAML config exists
  useEffect(() => {
    if (!loading && !user && samlConfigId) {
      // Only redirect on initial load, not on logout or after manual login attempts
      const hasVisited = sessionStorage.getItem('samlRedirected');
      const isLoginOrRegisterPage = window.location.pathname === '/login' || window.location.pathname === '/register';
      if (!hasVisited && !isLoginOrRegisterPage && window.location.pathname !== '/auth/callback') {
        sessionStorage.setItem('samlRedirected', 'true');
        const apiBaseUrl = import.meta.env.VITE_API_BASE_URL || 'https://userly-341i.onrender.com';
        window.location.href = `${apiBaseUrl}/saml/login/${samlConfigId}`;
      }
    }
  }, [loading, user, samlConfigId]);

  const login = async (email, password) => {
    try {
      console.log('Manual login attempt for:', email);
      const response = await api.post('/auth/login', { email, password });
      const { token: newToken, user: userData } = response.data;
      
      console.log('Login successful, user data:', userData);
      setToken(newToken);
      setUser(userData);
      localStorage.setItem('token', newToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;
      sessionStorage.removeItem('samlRedirected'); // Clear SAML redirect flag
      
      return { success: true };
    } catch (error) {
      console.error('Login failed:', error);
      return { 
        success: false, 
        message: error.response?.data?.message || 'Login failed' 
      };
    }
  };

  const register = async (name, email, password) => {
    try {
      await api.post('/auth/register', { name, email, password });
      return { success: true };
    } catch (error) {
      return { 
        success: false, 
        message: error.response?.data?.message || 'Registration failed' 
      };
    }
  };

  const logout = () => {
    setToken(null);
    setUser(null);
    localStorage.removeItem('token');
    delete api.defaults.headers.common['Authorization'];
    sessionStorage.removeItem('samlRedirected');
    window.location.href = '/login';
  };

  const value = {
    user,
    loading,
    login,
    register,
    logout
  };

  return (
    <AuthContext.Provider value={value}>
      {children}
    </AuthContext.Provider>
  );
};

export const useAuth = () => {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
};