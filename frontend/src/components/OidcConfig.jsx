import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import api from '../services/api';

const OidcConfig = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [validating, setValidating] = useState(false);
  const [config, setConfig] = useState({
    oidcName: '',
    allowedDomains: '',
    issuerUrl: '',
    clientId: '',
    clientSecret: '',
    callbackUrl: '',
    scope: 'openid profile email',
    responseType: 'code',
    enabled: true
  });
  const [existingConfigs, setExistingConfigs] = useState([]);
  const [showNewConfig, setShowNewConfig] = useState(false);
  const [editingConfigId, setEditingConfigId] = useState(null);
  const [validationResult, setValidationResult] = useState(null);

  useEffect(() => {
    fetchConfigs();
  }, []);

  const fetchConfigs = async () => {
    try {
      console.log('Fetching OIDC configs...');
      const response = await api.get('/oidc/configs');
      console.log('Fetched configs:', response.data);
      setExistingConfigs(response.data);
    } catch (error) {
      console.error('Failed to fetch OIDC configs:', error);
      console.error('Error response:', error.response);
    }
  };

  const handleInputChange = (e) => {
    const { name, value, type, checked } = e.target;
    setConfig({ 
      ...config, 
      [name]: type === 'checkbox' ? checked : value 
    });
    // Clear validation result when form changes
    setValidationResult(null);
  };

  const handleValidate = async () => {
    if (!config.issuerUrl || !config.clientId || !config.clientSecret || !config.callbackUrl) {
      toast.error('Please fill in all required fields before validating');
      return;
    }

    setValidating(true);
    try {
      const response = await api.post('/oidc/validate', {
        issuer_url: config.issuerUrl,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        callback_url: config.callbackUrl
      });
      
      if (response.data.valid) {
        setValidationResult({ valid: true, discovery: response.data.discovery });
        toast.success('OIDC configuration is valid!');
      } else {
        setValidationResult({ valid: false, error: response.data.error });
        toast.error('Invalid OIDC configuration');
      }
    } catch (error) {
      console.error('Validation error:', error);
      const errorMsg = error.response?.data?.error || error.message || 'Validation failed';
      setValidationResult({ valid: false, error: errorMsg });
      toast.error(errorMsg);
    } finally {
      setValidating(false);
    }
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const payload = {
        oidc_name: config.oidcName,
        allowed_domains: config.allowedDomains,
        issuer_url: config.issuerUrl,
        client_id: config.clientId,
        client_secret: config.clientSecret,
        callback_url: config.callbackUrl,
        scope: config.scope,
        response_type: config.responseType,
        enabled: config.enabled
      };

      console.log(editingConfigId ? 'Updating OIDC config:' : 'Creating OIDC config:', payload);

      let response;
      if (editingConfigId) {
        response = await api.put(`/oidc/configs/${editingConfigId}`, payload);
        toast.success('OIDC configuration updated successfully');
      } else {
        response = await api.post('/oidc/configs', payload);
        toast.success('OIDC configuration saved successfully');
      }
      console.log('OIDC config saved:', response.data);

      setShowNewConfig(false);
      setEditingConfigId(null);
      setConfig({
        oidcName: '',
        allowedDomains: '',
        issuerUrl: '',
        clientId: '',
        clientSecret: '',
        callbackUrl: '',
        scope: 'openid profile email',
        responseType: 'code',
        enabled: true
      });
      setValidationResult(null);
      fetchConfigs();
    } catch (error) {
      console.error('OIDC config save error:', error);
      console.error('Error response:', error.response);
      console.error('Error data:', error.response?.data);
      toast.error(error.response?.data?.message || error.message || 'Failed to save OIDC configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleEdit = (cfg) => {
    setEditingConfigId(cfg.id);
    setConfig({
      oidcName: cfg.oidc_name || '',
      allowedDomains: cfg.allowed_domains || '',
      issuerUrl: cfg.issuer_url || '',
      clientId: cfg.client_id || '',
      clientSecret: cfg.client_secret || '',
      callbackUrl: cfg.callback_url || '',
      scope: cfg.scope || 'openid profile email',
      responseType: cfg.response_type || 'code',
      enabled: cfg.enabled !== false
    });
    setShowNewConfig(true);
    setValidationResult(null);
    window.scrollTo({ top: 0, behavior: 'smooth' });
  };

  const handleCancel = () => {
    setShowNewConfig(false);
    setEditingConfigId(null);
    setConfig({
      oidcName: '',
      allowedDomains: '',
      issuerUrl: '',
      clientId: '',
      clientSecret: '',
      callbackUrl: '',
      scope: 'openid profile email',
      responseType: 'code',
      enabled: true
    });
    setValidationResult(null);
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this OIDC configuration?')) return;

    try {
      await api.delete(`/oidc/configs/${id}`);
      toast.success('OIDC configuration deleted successfully');
      fetchConfigs();
    } catch (error) {
      console.error('Delete error:', error);
      toast.error('Failed to delete OIDC configuration');
    }
  };

  const handleToggle = async (id, currentEnabled) => {
    try {
      const newEnabled = !currentEnabled;
      console.log(`Toggling config ${id} from ${currentEnabled} to ${newEnabled}`);
      await api.put(`/oidc/configs/${id}`, { enabled: newEnabled });
      toast.success(`OIDC configuration ${newEnabled ? 'enabled' : 'disabled'}`);
      fetchConfigs();
    } catch (error) {
      console.error('Toggle error:', error);
      console.error('Error response:', error.response?.data);
      const errorMsg = error.response?.data?.message || error.message || 'Unknown error';
      toast.error(`Failed to toggle: ${errorMsg}`);
    }
  };

  return (
    <div className="h-screen w-screen bg-gray-50 flex flex-col">
      <div className="flex-1 overflow-auto">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-8">
          <div className="mb-8">
            <button
              onClick={() => navigate('/dashboard')}
              className="inline-flex items-center text-indigo-600 hover:text-indigo-800 mb-4"
            >
              <svg className="w-5 h-5 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 19l-7-7m0 0l7-7m-7 7h18" />
              </svg>
              Back to Dashboard
            </button>
            <h1 className="text-3xl font-bold text-gray-900">OIDC Configuration</h1>
            <p className="mt-2 text-gray-600">Configure OpenID Connect single sign-on for your identity provider</p>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-2 gap-8">
            {/* Existing Configurations */}
            <div className="bg-white shadow rounded-lg p-6">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-xl font-semibold text-gray-900">Existing Configurations</h2>
                <button
                  onClick={() => setShowNewConfig(!showNewConfig)}
                  className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700"
                >
                  <svg className="w-4 h-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 4v16m8-8H4" />
                  </svg>
                  New Configuration
                </button>
              </div>

              {existingConfigs.length === 0 ? (
                <div className="text-center py-12 text-gray-500">
                  <svg className="w-12 h-12 mx-auto mb-4 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                    <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z" />
                  </svg>
                  <p>No OIDC configurations found</p>
                  <p className="text-sm mt-2">Click "New Configuration" to add one</p>
                </div>
              ) : (
                <div className="space-y-4">
                  {existingConfigs.map((cfg) => (
                    <div key={cfg.id} className={`border rounded-lg p-4 hover:shadow-md transition-shadow ${cfg.enabled === false ? 'border-gray-200 bg-gray-50' : 'border-gray-200 bg-white'}`}>
                      <div className="flex justify-between items-start mb-3">
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          <div className="min-w-0">
                            <div className="flex items-center gap-2 flex-wrap">
                              <h3 className="font-semibold text-gray-900">{cfg.oidc_name}</h3>
                              {cfg.enabled === false ? (
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">
                                  Disabled
                                </span>
                              ) : (
                                <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                                  Active
                                </span>
                              )}
                            </div>
                            <p className="text-sm text-gray-600 mt-1">Domains: {cfg.allowed_domains}</p>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 flex-shrink-0 ml-2">
                          <button
                            onClick={() => handleEdit(cfg)}
                            className="inline-flex items-center justify-center p-2 border border-indigo-300 rounded text-indigo-700 bg-white hover:bg-indigo-50"
                            title="Edit"
                          >
                            <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z" />
                            </svg>
                          </button>
                          <button
                            onClick={() => handleDelete(cfg.id)}
                            className="inline-flex items-center justify-center p-2 border border-red-300 rounded text-red-700 bg-white hover:bg-red-50"
                            title="Delete"
                          >
                            <svg className="w-4 h-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                            </svg>
                          </button>
                          <div
                            onClick={(e) => {
                              e.preventDefault();
                              e.stopPropagation();
                              handleToggle(cfg.id, cfg.enabled !== false);
                            }}
                            className={`relative inline-flex h-7 w-12 items-center rounded-full cursor-pointer transition-all duration-200 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 ${cfg.enabled !== false ? 'bg-green-500 shadow-green-200' : 'bg-gray-300'}`}
                            title={cfg.enabled !== false ? 'Click to disable' : 'Click to enable'}
                            role="switch"
                            aria-checked={cfg.enabled !== false}
                          >
                            <span
                              className={`inline-block h-5 w-5 transform rounded-full bg-white shadow-md transition-transform duration-200 ease-in-out ${cfg.enabled !== false ? 'translate-x-6' : 'translate-x-1'}`}
                            />
                          </div>
                        </div>
                      </div>
                      {cfg.issuer_url && (
                        <div className="text-sm text-gray-600">
                          <p><strong>Issuer URL:</strong> {cfg.issuer_url}</p>
                          <p><strong>Callback URL:</strong> {cfg.callback_url}</p>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* New Configuration Form */}
            {showNewConfig && (
              <div className="bg-white shadow rounded-lg p-6">
                <h2 className="text-xl font-semibold text-gray-900 mb-6">
                  {editingConfigId ? 'Edit OIDC Configuration' : 'New OIDC Configuration'}
                </h2>
                <form onSubmit={handleSubmit} className="space-y-6">
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">OIDC Name</label>
                    <input
                      type="text"
                      name="oidcName"
                      value={config.oidcName}
                      onChange={handleInputChange}
                      required
                      placeholder="e.g., Google OIDC"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Allowed Domains</label>
                    <input
                      type="text"
                      name="allowedDomains"
                      value={config.allowedDomains}
                      onChange={handleInputChange}
                      required
                      placeholder="e.g., gmail.com, yourcompany.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <p className="mt-1 text-sm text-gray-500">Comma-separated list of allowed domains</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Issuer URL</label>
                    <input
                      type="url"
                      name="issuerUrl"
                      value={config.issuerUrl}
                      onChange={handleInputChange}
                      required
                      placeholder="e.g., https://accounts.google.com"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <p className="mt-1 text-sm text-gray-500">The OpenID Connect issuer URL</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Client ID</label>
                    <input
                      type="text"
                      name="clientId"
                      value={config.clientId}
                      onChange={handleInputChange}
                      required
                      placeholder="Your OAuth 2.0 Client ID"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Client Secret</label>
                    <input
                      type="password"
                      name="clientSecret"
                      value={config.clientSecret}
                      onChange={handleInputChange}
                      required
                      placeholder="Your OAuth 2.0 Client Secret"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Callback URL</label>
                    <input
                      type="url"
                      name="callbackUrl"
                      value={config.callbackUrl}
                      onChange={handleInputChange}
                      required
                      placeholder="e.g., http://localhost:3000/oidc/callback"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <p className="mt-1 text-sm text-gray-500">Must match the redirect URI configured in your IdP</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Scope</label>
                    <input
                      type="text"
                      name="scope"
                      value={config.scope}
                      onChange={handleInputChange}
                      placeholder="openid profile email"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <p className="mt-1 text-sm text-gray-500">Space-separated scopes (default: openid profile email)</p>
                  </div>

                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Response Type</label>
                    <select
                      name="responseType"
                      value={config.responseType}
                      onChange={handleInputChange}
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    >
                      <option value="code">code (Authorization Code Flow)</option>
                      <option value="id_token">id_token (Implicit Flow)</option>
                    </select>
                  </div>

                  {/* Validation Button */}
                  <div className="border-t border-gray-200 pt-6">
                    <button
                      type="button"
                      onClick={handleValidate}
                      disabled={validating}
                      className="w-full px-4 py-2 border border-blue-600 text-sm font-medium rounded-md text-blue-600 bg-white hover:bg-blue-50 disabled:opacity-50 disabled:cursor-not-allowed"
                    >
                      {validating ? 'Validating...' : 'Validate Configuration'}
                    </button>
                    {validationResult && (
                      <div className={`mt-3 p-3 rounded-md ${validationResult.valid ? 'bg-green-50 border border-green-200' : 'bg-red-50 border border-red-200'}`}>
                        <p className={`text-sm ${validationResult.valid ? 'text-green-800' : 'text-red-800'}`}>
                          {validationResult.valid ? '✓ Configuration is valid' : `✗ ${validationResult.error}`}
                        </p>
                        {validationResult.valid && validationResult.discovery && (
                          <div className="mt-2 text-xs text-green-700">
                            <p>Authorization Endpoint: {validationResult.discovery.authorization_endpoint}</p>
                            <p>Token Endpoint: {validationResult.discovery.token_endpoint}</p>
                          </div>
                        )}
                      </div>
                    )}
                  </div>

                  {/* SSO Enabled Toggle */}
                  <div className="border-t border-gray-200 pt-6">
                    <div className="flex items-center justify-between">
                      <div>
                        <h3 className="text-lg font-medium text-gray-900">SSO Status</h3>
                        <p className="text-sm text-gray-600">Enable or disable SSO for this configuration</p>
                      </div>
                      <label className="flex items-center cursor-pointer">
                        <div className="relative">
                          <input
                            type="checkbox"
                            name="enabled"
                            checked={config.enabled}
                            onChange={(e) => setConfig({ ...config, enabled: e.target.checked })}
                            className="sr-only"
                          />
                          <div className={`block w-14 h-8 rounded-full transition-colors ${config.enabled ? 'bg-green-500' : 'bg-gray-300'}`}></div>
                          <div className={`dot absolute left-1 top-1 bg-white w-6 h-6 rounded-full transition-transform ${config.enabled ? 'translate-x-6' : ''}`}></div>
                        </div>
                        <span className="ml-3 text-sm font-medium text-gray-700">
                          {config.enabled ? 'SSO Enabled' : 'SSO Disabled'}
                        </span>
                      </label>
                    </div>
                  </div>

                  <div className="flex justify-end space-x-3 pt-4">
                    <button
                      type="button"
                      onClick={handleCancel}
                      className="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                    >
                      Cancel
                    </button>
                    <button
                      type="submit"
                      disabled={loading}
                      className="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
                    >
                      {loading ? (editingConfigId ? 'Updating...' : 'Saving...') : (editingConfigId ? 'Update Configuration' : 'Save Configuration')}
                    </button>
                  </div>
                </form>
              </div>
            )}

            {/* Setup Instructions */}
            <div className="bg-white shadow rounded-lg p-6">
              <h2 className="text-xl font-semibold text-gray-900 mb-6">OIDC Setup Instructions</h2>
              <div className="space-y-4">
                <div className="bg-blue-50 border-l-4 border-blue-400 p-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-blue-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M18 10a8 8 0 11-16 0 8 8 0 0116 0zm-7-4a1 1 0 11-2 0 1 1 0 012 0zM9 9a1 1 0 000 2v3a1 1 0 001 1h1a1 1 0 100-2v-3a1 1 0 00-1-1H9z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm text-blue-700">
                        Your callback URL: <strong>https://userly-pro.vercel.app/oidc/callback</strong>
                      </p>
                    </div>
                  </div>
                </div>

                <div className="space-y-3">
                  <h3 className="font-medium text-gray-900">Step 1: Create OAuth 2.0 Application</h3>
                  <p className="text-sm text-gray-600">Create an OAuth 2.0 client application in your identity provider (e.g., Google, Okta, Auth0, Azure AD)</p>
                </div>

                <div className="space-y-3">
                  <h3 className="font-medium text-gray-900">Step 2: Configure Redirect URIs</h3>
                  <p className="text-sm text-gray-600">Add your callback URL to the allowed redirect URIs in your IdP application settings</p>
                </div>

                <div className="space-y-3">
                  <h3 className="font-medium text-gray-900">Step 3: Get Credentials</h3>
                  <p className="text-sm text-gray-600">Copy the Client ID and Client Secret from your IdP application</p>
                </div>

                <div className="space-y-3">
                  <h3 className="font-medium text-gray-900">Step 4: Configure in Userly</h3>
                  <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                    <li>Enter the Issuer URL (e.g., https://accounts.google.com for Google)</li>
                    <li>Enter the Client ID and Client Secret</li>
                    <li>Enter the Callback URL matching your IdP configuration</li>
                    <li>Click "Validate Configuration" to verify the setup</li>
                    <li>Save the configuration</li>
                  </ol>
                </div>

                <div className="bg-yellow-50 border-l-4 border-yellow-400 p-4">
                  <div className="flex">
                    <div className="flex-shrink-0">
                      <svg className="h-5 w-5 text-yellow-400" xmlns="http://www.w3.org/2000/svg" viewBox="0 0 20 20" fill="currentColor">
                        <path fillRule="evenodd" d="M8.257 3.099c.765-1.36 2.722-1.36 3.486 0l5.58 9.92c.75 1.334-.213 2.98-1.742 2.98H4.42c-1.53 0-2.493-1.646-1.743-2.98l5.58-9.92zM11 13a1 1 0 11-2 0 1 1 0 012 0zm-1-8a1 1 0 00-1 1v3a1 1 0 002 0V6a1 1 0 00-1-1z" clipRule="evenodd" />
                      </svg>
                    </div>
                    <div className="ml-3">
                      <p className="text-sm text-yellow-700">
                        Make sure to configure the allowed domains to restrict which users can authenticate via this OIDC provider.
                      </p>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};

export default OidcConfig;
