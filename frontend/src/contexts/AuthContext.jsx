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
        const response = await fetch('https://userly-341i.onrender.com/api/saml/providers');
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
    const storedUser = localStorage.getItem('user');
    
    if (storedToken) {
      setToken(storedToken);
      api.defaults.headers.common['Authorization'] = `Bearer ${storedToken}`;
      
      // Use stored user data if available
      if (storedUser) {
        try {
          const userData = JSON.parse(storedUser);
          setUser(userData);
          setLoading(false);
        } catch (e) {
          console.error('Failed to parse stored user:', e);
          validateToken();
        }
      } else {
        validateToken();
      }
    } else {
      setLoading(false);
    }
  }, []);

  const validateToken = async () => {
    try {
      // Get current user profile from token
      const response = await api.get('/users');
      setLoading(false);
      // If response is an array (all users), find the current user by matching email from token
      if (Array.isArray(response.data)) {
        const token = localStorage.getItem('token');
        if (token) {
          const base64Url = token.split('.')[1];
          const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
          const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
            return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
          }).join(''));
          const payload = JSON.parse(jsonPayload);
          const currentUser = response.data.find(u => u.email === payload.email);
          if (currentUser) {
            setUser(currentUser);
            localStorage.setItem('user', JSON.stringify(currentUser));
          }
        }
      } else {
        setUser(response.data);
      }
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
      localStorage.setItem('user', JSON.stringify(userData));
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

  const logout = async () => {
    const token = localStorage.getItem('token');
    
    // DEBUG: Check token contents
    if (token) {
      try {
        const payload = JSON.parse(atob(token.split('.')[1]));
        console.log('Logout - Token authMethod:', payload.authMethod);
        console.log('Logout - Token samlNameID:', payload.samlNameID);
        console.log('Logout - Token samlConfigId:', payload.samlConfigId);
      } catch (e) {
        console.log('Logout - Could not parse token');
      }
    }
    
    if (token) {
      try {
        // Call backend logout endpoint to initiate SLO if user is SAML-authenticated
        // Use api service which has correct baseURL configured
        const response = await api.post('/saml/logout');
        const data = response.data;
        
        console.log('Logout - Response:', data);
        
        // Clear local storage first
        localStorage.removeItem('token');
        localStorage.removeItem('user');
        setUser(null);
        setToken(null);
        delete api.defaults.headers.common['Authorization'];
        sessionStorage.removeItem('samlRedirected');
        
        // If SLO was initiated, redirect to IdP logout URL
        if (data.sloInitiated && data.redirectUrl) {
          console.log('SLO initiated, redirecting to IdP:', data.redirectUrl);
          window.location.href = data.redirectUrl;
          return;
        }
      } catch (error) {
        console.error('SLO logout error:', error);
        // Continue with local logout on error
      }
    }
    
    // Local logout (non-SAML or SLO not available)
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    setUser(null);
    setToken(null);
    delete api.defaults.headers.common['Authorization'];
    sessionStorage.removeItem('samlRedirected');
    window.location.href = '/login';
  };

  const value = {
    user,
    token,
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