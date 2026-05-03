import React, { useState, useEffect } from 'react';
import { Link, useNavigate, useSearchParams } from 'react-router-dom';
import { useAuth } from '../contexts/AuthContext';
import { toast } from 'react-toastify';
import api from '../services/api';

const Login = () => {
  const [formData, setFormData] = useState({
    email: '',
    password: ''
  });
  const [loading, setLoading] = useState(false);
  const [blockedMessage, setBlockedMessage] = useState('');
  const [samlProviders, setSamlProviders] = useState([]);
  const [loadingProviders, setLoadingProviders] = useState(true);
  const [showProviderModal, setShowProviderModal] = useState(false);

  const { login } = useAuth();
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();

  useEffect(() => {
    // Check if user was redirected due to being blocked/revoked in Entra
    if (searchParams.get('blocked') === 'true') {
      const reason = searchParams.get('reason');
      if (reason === 'security_group') {
        setBlockedMessage('Your access has been revoked for this application. Contact your support person to unlock it, then try again.');
      } else {
        setBlockedMessage('Your account has been locked. Contact your support person to unlock it, then try again.');
      }
    }
  }, [searchParams]);

  // Fetch enabled SAML providers
  useEffect(() => {
    const fetchSamlProviders = async () => {
      try {
        setLoadingProviders(true);
        const response = await api.get('/saml/providers');
        setSamlProviders(response.data || []);
      } catch (error) {
        console.error('Failed to fetch SAML providers:', error);
        setSamlProviders([]);
      } finally {
        setLoadingProviders(false);
      }
    };

    fetchSamlProviders();
  }, []);

  const handleChange = (e) => {
    setFormData({
      ...formData,
      [e.target.name]: e.target.value
    });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    const result = await login(formData.email, formData.password);
    
    if (result.success) {
      toast.success('Login successful!');
      navigate('/dashboard');
    } else {
      toast.error(result.message);
    }
    
    setLoading(false);
  };

  return (
    <div className="h-screen w-screen flex items-center justify-center bg-gray-50">
      <div className="w-full max-w-lg px-8">
        <div className="text-center mb-8">
          <div className="flex items-center justify-center mb-8">
            <div
              className="triangle"
              style={{
                width: 0,
                height: 0,
                borderTop: '22px solid transparent',
                borderBottom: '22px solid transparent',
                borderLeft: '18px solid #f97316'
              }}
            ></div>
            <h1 className="text-2xl font-bold text-gray-900 ml-3">Betopia ERP</h1>
          </div>
          <h2 className="text-4xl font-bold text-gray-900 mb-2">
            Sign in to your account
          </h2>
          <p className="text-gray-600">Welcome back! Please enter your details.</p>
        </div>
        <form className="space-y-6" onSubmit={handleSubmit}>
          {blockedMessage && (
            <div className="bg-red-50 border border-red-200 rounded-lg p-4 mb-4">
              <div className="flex items-center">
                <svg className="w-5 h-5 text-red-500 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 8v4m0 4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z" />
                </svg>
                <span className="text-red-700 font-medium">{blockedMessage}</span>
              </div>
            </div>
          )}
          <div className="rounded-md shadow-sm -space-y-px">
            <div>
              <label htmlFor="email" className="sr-only">
                Email address
              </label>
              <input
                id="email"
                name="email"
                type="email"
                required
                value={formData.email}
                onChange={handleChange}
                className="w-full px-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-t-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-base"
                placeholder="Email address"
              />
            </div>
            <div>
              <label htmlFor="password" className="sr-only">
                Password
              </label>
              <input
                id="password"
                name="password"
                type="password"
                required
                value={formData.password}
                onChange={handleChange}
                className="w-full px-4 py-3 border border-gray-300 placeholder-gray-500 text-gray-900 rounded-b-lg focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500 text-base"
                placeholder="Password"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className="w-full flex justify-center py-3 px-4 border border-transparent text-base font-medium rounded-lg text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 transition-colors duration-200"
            >
              {loading ? 'Signing in...' : 'Sign in'}
            </button>
          </div>

          {/* SAML SSO Section */}
          {samlProviders.length > 0 && (
            <div className="mt-6">
              <div className="relative">
                <div className="absolute inset-0 flex items-center">
                  <div className="w-full border-t border-gray-300"></div>
                </div>
                <div className="relative flex justify-center text-sm">
                  <span className="px-2 bg-gray-50 text-gray-500">Or</span>
                </div>
              </div>

              <div className="mt-6">
                {samlProviders.length === 1 ? (
                  // Single provider: direct redirect
                  <button
                    type="button"
                    onClick={() => {
                      const provider = samlProviders[0];
                      // Use Azure AD MyApps direct link if saml_app_id is configured
                      if (provider.saml_app_id && provider.tenant_id) {
                        const azureAdUrl = `https://account.activedirectory.windowsazure.com/applications/signin/${provider.saml_app_id}?tenantId=${provider.tenant_id}`;
                        window.location.href = azureAdUrl;
                      } else {
                        // Fallback to backend SAML login endpoint
                        window.location.href = `${import.meta.env.VITE_API_URL || 'https://userly-341i.onrender.com'}/api/saml/login/${provider.id}`;
                      }
                    }}
                    className="w-full flex justify-center items-center py-3 px-4 border border-gray-300 text-base font-medium rounded-lg text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors duration-200"
                  >
                    <svg className="w-5 h-5 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    Single Sign On
                  </button>
                ) : (
                  // Multiple providers: show selection modal
                  <button
                    type="button"
                    onClick={() => setShowProviderModal(true)}
                    className="w-full flex justify-center items-center py-3 px-4 border border-gray-300 text-base font-medium rounded-lg text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 transition-colors duration-200"
                  >
                    <svg className="w-5 h-5 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
                    </svg>
                    Single Sign On
                  </button>
                )}
              </div>
            </div>
          )}

          {/* SAML Provider Selection Modal */}
          {showProviderModal && (
            <div className="fixed inset-0 z-50 overflow-y-auto" aria-labelledby="modal-title" role="dialog" aria-modal="true">
              <div className="flex items-center justify-center min-h-screen px-4">
                {/* Backdrop */}
                <div
                  className="fixed inset-0 bg-gray-500 bg-opacity-75 transition-opacity"
                  onClick={() => setShowProviderModal(false)}
                ></div>

                {/* Modal panel */}
                <div className="relative bg-white rounded-lg max-w-md w-full p-6 shadow-xl">
                  <div className="text-center">
                    <h3 className="text-lg font-medium text-gray-900 mb-2" id="modal-title">
                      Choose your organization
                    </h3>
                    <p className="text-sm text-gray-500 mb-6">
                      Select your organization to continue with Single Sign On
                    </p>
                  </div>

                  <div className="space-y-3">
                    {samlProviders.map((provider) => (
                      <button
                        key={provider.id}
                        type="button"
                        onClick={() => {
                          // Use Azure AD MyApps direct link if saml_app_id is configured
                          if (provider.saml_app_id && provider.tenant_id) {
                            const azureAdUrl = `https://account.activedirectory.windowsazure.com/applications/signin/${provider.saml_app_id}?tenantId=${provider.tenant_id}`;
                            window.location.href = azureAdUrl;
                          } else {
                            // Fallback to backend SAML login endpoint
                            window.location.href = `${import.meta.env.VITE_API_URL || 'https://userly-341i.onrender.com'}/api/saml/login/${provider.id}`;
                          }
                        }}
                        className="w-full flex items-center justify-between p-4 border border-gray-300 rounded-lg hover:border-indigo-500 hover:bg-indigo-50 transition-colors"
                      >
                        <div className="flex items-center">
                          <div className="flex-shrink-0 h-10 w-10 bg-indigo-100 rounded-full flex items-center justify-center">
                            <svg className="h-6 w-6 text-indigo-600" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4" />
                            </svg>
                          </div>
                          <div className="ml-4 text-left">
                            <p className="text-sm font-medium text-gray-900">{provider.saml_name}</p>
                            <p className="text-xs text-gray-500">{provider.allowed_domains}</p>
                          </div>
                        </div>
                        <svg className="h-5 w-5 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                          <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 5l7 7-7 7" />
                        </svg>
                      </button>
                    ))}
                  </div>

                  <div className="mt-6">
                    <button
                      type="button"
                      onClick={() => setShowProviderModal(false)}
                      className="w-full px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              </div>
            </div>
          )}

          <div className="text-center">
            <span className="text-sm text-gray-600">
              Don't have an account?{' '}
              <Link to="/register" className="font-medium text-indigo-600 hover:text-indigo-500">
                Sign up
              </Link>
            </span>
          </div>
        </form>
      </div>
    </div>
  );
};

export default Login;