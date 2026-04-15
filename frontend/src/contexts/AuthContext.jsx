import React, { createContext, useContext, useState, useEffect } from 'react';
import api from '../services/api'

const AuthContext = createContext();

export const AuthProvider = ({ children }) => {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const [samlConfigId, setSamlConfigId] = useState(null);
  const [token, setToken] = useState(null);
  const [refreshToken, setRefreshToken] = useState(null);
  const [tokenExpiry, setTokenExpiry] = useState(null);

  // Token refresh interval
  useEffect(() => {
    if (!token || !refreshToken || !tokenExpiry) return;

    // Refresh token 2 minutes before expiry
    const refreshTime = tokenExpiry - 2 * 60 * 1000;
    const now = Date.now();
    const timeUntilRefresh = Math.max(0, refreshTime - now);

    console.log('Token refresh scheduled in', Math.round(timeUntilRefresh / 1000), 'seconds');

    const refreshTimer = setTimeout(() => {
      refreshAccessToken();
    }, timeUntilRefresh);

    return () => clearTimeout(refreshTimer);
  }, [token, refreshToken, tokenExpiry]);

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

    // Check for SAML callback with tokens
    const urlParams = new URLSearchParams(window.location.search);
    const samlToken = urlParams.get('token');
    const samlRefreshToken = urlParams.get('refreshToken');
    const samlExpiresIn = urlParams.get('expiresIn');

    if (samlToken && samlRefreshToken) {
      // Handle SAML auth callback
      handleSamlCallback(samlToken, samlRefreshToken, parseInt(samlExpiresIn) || 900);
      // Clean URL
      window.history.replaceState({}, document.title, window.location.pathname);
      return;
    }

    const storedToken = localStorage.getItem('token');
    const storedRefreshToken = localStorage.getItem('refreshToken');
    const storedUser = localStorage.getItem('user');
    const storedExpiry = localStorage.getItem('tokenExpiry');

    if (storedToken) {
      setToken(storedToken);
      setRefreshToken(storedRefreshToken);
      if (storedExpiry) setTokenExpiry(parseInt(storedExpiry));
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

  const handleSamlCallback = (newToken, newRefreshToken, expiresIn) => {
    const expiryTime = Date.now() + expiresIn * 1000;

    setToken(newToken);
    setRefreshToken(newRefreshToken);
    setTokenExpiry(expiryTime);

    localStorage.setItem('token', newToken);
    localStorage.setItem('refreshToken', newRefreshToken);
    localStorage.setItem('tokenExpiry', expiryTime.toString());

    api.defaults.headers.common['Authorization'] = `Bearer ${newToken}`;

    // Decode token to get user info
    try {
      const base64Url = newToken.split('.')[1];
      const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
      const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
        return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
      }).join(''));
      const payload = JSON.parse(jsonPayload);

      const userData = {
        id: payload.userId,
        email: payload.email,
        name: payload.name,
        role: payload.role
      };

      setUser(userData);
      localStorage.setItem('user', JSON.stringify(userData));
      sessionStorage.removeItem('samlRedirected');
    } catch (e) {
      console.error('Failed to decode token:', e);
    }

    setLoading(false);
  };

  const refreshAccessToken = async () => {
    const currentRefreshToken = localStorage.getItem('refreshToken');
    if (!currentRefreshToken) {
      console.log('No refresh token available');
      logout();
      return;
    }

    try {
      console.log('Refreshing access token...');
      const response = await fetch('https://userly-341i.onrender.com/api/auth/refresh', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refreshToken: currentRefreshToken })
      });

      if (!response.ok) {
        const error = await response.json();
        console.error('Token refresh failed:', error);
        if (error.forceReauth) {
          // Session exceeded max age (30min), redirect to SAML for re-authentication
          console.log('Session requires re-authentication with Entra');
          logout();
          // After logout clears tokens, redirect to SAML login
          setTimeout(() => {
            const apiBaseUrl = 'https://userly-341i.onrender.com';
            window.location.href = `${apiBaseUrl}/saml/login/${samlConfigId || ''}`;
          }, 100);
          return;
        }
        if (error.redirect) {
          logout();
          return;
        }
        throw new Error('Refresh failed');
      }

      const data = await response.json();
      console.log('Token refreshed successfully');

      const newExpiry = Date.now() + data.expiresIn * 1000;
      setToken(data.token);
      setTokenExpiry(newExpiry);

      localStorage.setItem('token', data.token);
      localStorage.setItem('tokenExpiry', newExpiry.toString());
      localStorage.setItem('user', JSON.stringify(data.user));

      api.defaults.headers.common['Authorization'] = `Bearer ${data.token}`;
      setUser(data.user);
    } catch (error) {
      console.error('Failed to refresh token:', error);
      logout();
    }
  };

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
    const userData = localStorage.getItem('user');
    const userEmail = userData ? JSON.parse(userData).email : null;

    // Clear all tokens first
    localStorage.removeItem('token');
    localStorage.removeItem('refreshToken');
    localStorage.removeItem('tokenExpiry');
    localStorage.removeItem('user');
    setUser(null);
    setToken(null);
    setRefreshToken(null);
    setTokenExpiry(null);
    delete api.defaults.headers.common['Authorization'];

    // Check if any SAML provider has SLO configured
    try {
      const response = await fetch('https://userly-341i.onrender.com/api/saml/providers');
      const providers = await response.json();
      const sloProvider = providers.find(p => p.idp_slo_url);

      if (sloProvider) {
        // Redirect to SP-initiated SLO endpoint
        const apiBaseUrl = 'https://userly-341i.onrender.com';
        const sloUrl = `${apiBaseUrl}/api/saml/logout/${sloProvider.id}${userEmail ? `?nameID=${encodeURIComponent(userEmail)}` : ''}`;
        console.log('Initiating SLO to IdP:', sloUrl);

        sessionStorage.removeItem('samlRedirected');
        // Redirect to IdP logout
        window.location.href = sloUrl;
        return;
      }
    } catch (error) {
      console.error('Failed to check SLO configuration:', error);
    }

    // No SLO configured, redirect to login
    sessionStorage.removeItem('samlRedirected');
    window.location.href = '/login';
  };

  const value = {
    user,
    token,
    refreshToken,
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