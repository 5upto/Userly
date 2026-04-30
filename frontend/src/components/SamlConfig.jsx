import React, { useState, useEffect } from 'react';
import { useNavigate } from 'react-router-dom';
import { toast } from 'react-toastify';
import api from '../services/api';

const SamlConfig = () => {
  const navigate = useNavigate();
  const [loading, setLoading] = useState(false);
  const [config, setConfig] = useState({
    samlName: '',
    allowedDomains: '',
    issuerUrl: '',
    idpSsoUrl: '',
    idpSloUrl: '',
    idpCertificate: '',
    metadataFile: null,
    enabled: true,
    tenantId: '',
    clientId: '',
    clientSecret: '',
    graphApiEnabled: false
  });
  const [existingConfigs, setExistingConfigs] = useState([]);
  const [showNewConfig, setShowNewConfig] = useState(false);

  useEffect(() => {
    fetchConfigs();
  }, []);

  const fetchConfigs = async () => {
    try {
      console.log('Fetching SAML configs...');
      const response = await api.get('/saml/configs');
      console.log('Fetched configs:', response.data);
      setExistingConfigs(response.data);
    } catch (error) {
      console.error('Failed to fetch SAML configs:', error);
      console.error('Error response:', error.response);
    }
  };

  const handleInputChange = (e) => {
    const { name, value } = e.target;
    setConfig({ ...config, [name]: value });
  };

  const handleFileChange = (e) => {
    const file = e.target.files[0];
    setConfig({ ...config, metadataFile: file });
  };

  const handleSubmit = async (e) => {
    e.preventDefault();
    setLoading(true);

    try {
      const formData = new FormData();
      formData.append('samlName', config.samlName);
      formData.append('allowedDomains', config.allowedDomains);
      formData.append('issuerUrl', config.issuerUrl);
      formData.append('idpSsoUrl', config.idpSsoUrl);
      formData.append('idpSloUrl', config.idpSloUrl);
      formData.append('idpCertificate', config.idpCertificate);
      formData.append('enabled', config.enabled);
      formData.append('tenantId', config.tenantId);
      formData.append('clientId', config.clientId);
      formData.append('clientSecret', config.clientSecret);
      formData.append('graphApiEnabled', config.graphApiEnabled);
      if (config.metadataFile) {
        formData.append('metadataFile', config.metadataFile);
      }

      console.log('Submitting SAML config:', {
        samlName: config.samlName,
        allowedDomains: config.allowedDomains,
        hasMetadata: !!config.metadataFile
      });

      const response = await api.post('/saml/config', formData);
      console.log('SAML config saved successfully:', response.data);

      toast.success('SAML configuration saved successfully');
      setShowNewConfig(false);
      setConfig({
        samlName: '',
        allowedDomains: '',
        issuerUrl: '',
        idpSsoUrl: '',
        idpSloUrl: '',
        idpCertificate: '',
        metadataFile: null,
        enabled: true,
        tenantId: '',
        clientId: '',
        clientSecret: '',
        graphApiEnabled: false
      });
      fetchConfigs();
    } catch (error) {
      console.error('SAML config save error:', error);
      console.error('Error response:', error.response);
      console.error('Error data:', error.response?.data);
      toast.error(error.response?.data?.message || error.message || 'Failed to save SAML configuration');
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    if (!window.confirm('Are you sure you want to delete this SAML configuration?')) return;

    try {
      await api.delete(`/saml/config/${id}`);
      toast.success('SAML configuration deleted successfully');
      fetchConfigs();
    } catch (error) {
      console.error('Delete error:', error);
      toast.error('Failed to delete SAML configuration');
    }
  };

  const handleToggle = async (id, currentEnabled) => {
    try {
      const newEnabled = !currentEnabled;
      await api.patch(`/saml/config/${id}/toggle`, { enabled: newEnabled });
      toast.success(`SAML configuration ${newEnabled ? 'enabled' : 'disabled'}`);
      fetchConfigs();
    } catch (error) {
      console.error('Toggle error:', error);
      toast.error('Failed to toggle configuration');
    }
  };

  const downloadMetadata = async (configId) => {
    try {
      console.log('Downloading metadata for config:', configId);
      const response = await api.get(`/saml/metadata/${configId}`, {
        responseType: 'blob'
      });
      
      console.log('Metadata response received:', response);
      const url = window.URL.createObjectURL(new Blob([response.data]));
      const link = document.createElement('a');
      link.href = url;
      link.setAttribute('download', 'saml-metadata.xml');
      document.body.appendChild(link);
      link.click();
      link.remove();
      toast.success('Metadata downloaded successfully');
    } catch (error) {
      console.error('Download metadata error:', error);
      console.error('Error response:', error.response);
      toast.error(error.response?.data?.message || 'Failed to download metadata');
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
            <h1 className="text-3xl font-bold text-gray-900">SAML 2.0 Configuration for Entra ID</h1>
            <p className="mt-2 text-gray-600">Configure SAML 2.0 single sign-on with Microsoft Entra ID (formerly Azure AD)</p>
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
                <p>No SAML configurations found</p>
                <p className="text-sm mt-2">Click "New Configuration" to add one</p>
              </div>
            ) : (
              <div className="space-y-4">
                {existingConfigs.map((cfg) => (
                  <div key={cfg.id} className={`border rounded-lg p-4 hover:shadow-md transition-shadow ${cfg.enabled === false ? 'border-gray-200 bg-gray-50' : 'border-gray-200 bg-white'}`}>
                    <div className="flex justify-between items-start mb-3">
                      <div className="flex items-center gap-3">
                        <div>
                          <div className="flex items-center gap-2">
                            <h3 className="font-semibold text-gray-900">{cfg.saml_name}</h3>
                            {cfg.enabled === false ? (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-600">
                                Disabled
                              </span>
                            ) : (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-green-100 text-green-800">
                                Active
                              </span>
                            )}
                            {cfg.graph_api_enabled && (
                              <span className="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-blue-100 text-blue-800">
                                Graph API
                              </span>
                            )}
                          </div>
                          <p className="text-sm text-gray-600 mt-1">Domains: {cfg.allowed_domains}</p>
                          {cfg.tenant_id && (
                            <p className="text-xs text-gray-500 mt-1">Tenant: {cfg.tenant_id}</p>
                          )}
                        </div>
                      </div>
                      <div className="flex items-center gap-2">
                        {/* Toggle Switch - Better styled */}
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
                        <button
                          onClick={() => downloadMetadata(cfg.id)}
                          className="inline-flex items-center px-3 py-1 border border-gray-300 text-sm font-medium rounded text-gray-700 bg-white hover:bg-gray-50"
                        >
                          <svg className="w-4 h-4 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 16v1a3 3 0 003 3h10a3 3 0 003-3v-1m-4-4l-4 4m0 0l-4-4m4 4V4" />
                          </svg>
                          Metadata
                        </button>
                        <button
                          onClick={() => handleDelete(cfg.id)}
                          className="inline-flex items-center px-3 py-1 border border-red-300 text-sm font-medium rounded text-red-700 bg-white hover:bg-red-50"
                        >
                          <svg className="w-4 h-4 mr-1" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                          </svg>
                          Delete
                        </button>
                      </div>
                    </div>
                    {cfg.issuer_url && (
                      <div className="text-sm text-gray-600">
                        <p><strong>Issuer URL:</strong> {cfg.issuer_url}</p>
                        <p><strong>SSO URL:</strong> {cfg.idp_sso_url}</p>
                        {cfg.idp_slo_url && (
                          <p><strong>SLO URL:</strong> {cfg.idp_slo_url}</p>
                        )}
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
              <h2 className="text-xl font-semibold text-gray-900 mb-6">New SAML Configuration</h2>
              <form onSubmit={handleSubmit} className="space-y-6">
                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">SAML Name</label>
                  <input
                    type="text"
                    name="samlName"
                    value={config.samlName}
                    onChange={handleInputChange}
                    required
                    placeholder="e.g., SAML Entra ID"
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
                    placeholder="e.g., yourcompany.onmicrosoft.com"
                    className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                  />
                  <p className="mt-1 text-sm text-gray-500">Comma-separated list of allowed domains</p>
                </div>

                <div>
                  <label className="block text-sm font-medium text-gray-700 mb-2">Upload Metadata (Optional)</label>
                  <div className="mt-1 flex justify-center px-6 pt-5 pb-6 border-2 border-gray-300 border-dashed rounded-md hover:border-indigo-500 transition-colors">
                    <div className="space-y-1 text-center">
                      <svg className="mx-auto h-12 w-12 text-gray-400" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                        <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
                      </svg>
                      <div className="flex text-sm text-gray-600">
                        <label className="relative cursor-pointer bg-white rounded-md font-medium text-indigo-600 hover:text-indigo-500 focus-within:outline-none">
                          <span>Upload a file</span>
                          <input type="file" accept=".xml" onChange={handleFileChange} className="sr-only" />
                        </label>
                        <p className="pl-1">or drag and drop</p>
                      </div>
                      <p className="text-xs text-gray-500">XML file up to 10MB</p>
                      {config.metadataFile && (
                        <p className="text-sm text-indigo-600 mt-2">Selected: {config.metadataFile.name}</p>
                      )}
                    </div>
                  </div>
                </div>

                <div className="border-t border-gray-200 pt-6">
                  <p className="text-sm text-gray-600 mb-4">Or enter Entra ID details manually:</p>
                  
                  <div>
                    <label className="block text-sm font-medium text-gray-700 mb-2">Issuer URL (Entity ID)</label>
                    <input
                      type="text"
                      name="issuerUrl"
                      value={config.issuerUrl}
                      onChange={handleInputChange}
                      placeholder="https://sts.windows.net/{tenant-id}/"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>

                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-2">IdP SSO URL</label>
                    <input
                      type="text"
                      name="idpSsoUrl"
                      value={config.idpSsoUrl}
                      onChange={handleInputChange}
                      placeholder="https://login.microsoftonline.com/{tenant-id}/saml2"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>

                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-2">IdP SLO URL (Logout)</label>
                    <input
                      type="text"
                      name="idpSloUrl"
                      value={config.idpSloUrl}
                      onChange={handleInputChange}
                      placeholder="https://login.microsoftonline.com/{tenant-id}/saml2/logout"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                    <p className="mt-1 text-sm text-gray-500">Single Logout URL for true SLO (auto-extracted from metadata)</p>
                  </div>

                  <div className="mt-4">
                    <label className="block text-sm font-medium text-gray-700 mb-2">IdP Certificate (X.509)</label>
                    <textarea
                      name="idpCertificate"
                      value={config.idpCertificate}
                      onChange={handleInputChange}
                      rows={4}
                      placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
                      className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-indigo-500"
                    />
                  </div>
                </div>

                {/* Graph API Configuration Section */}
                <div className="border-t border-gray-200 pt-6">
                  <div className="flex items-center justify-between mb-4">
                    <h3 className="text-lg font-medium text-gray-900">Microsoft Graph API (Optional)</h3>
                    <div className="flex items-center">
                      <label className="flex items-center cursor-pointer">
                        <div className="relative">
                          <input
                            type="checkbox"
                            name="graphApiEnabled"
                            checked={config.graphApiEnabled}
                            onChange={(e) => setConfig({ ...config, graphApiEnabled: e.target.checked })}
                            className="sr-only"
                          />
                          <div className={`block w-10 h-6 rounded-full transition-colors ${config.graphApiEnabled ? 'bg-blue-600' : 'bg-gray-300'}`}></div>
                          <div className={`dot absolute left-1 top-1 bg-white w-4 h-4 rounded-full transition-transform ${config.graphApiEnabled ? 'translate-x-4' : ''}`}></div>
                        </div>
                        <span className="ml-2 text-sm font-medium text-gray-700">
                          {config.graphApiEnabled ? 'Enabled' : 'Disabled'}
                        </span>
                      </label>
                    </div>
                  </div>
                  <p className="text-sm text-gray-600 mb-4">
                    Enable Graph API to sync user status and group memberships for this tenant. Each tenant needs its own app registration.
                  </p>

                  {config.graphApiEnabled && (
                    <div className="space-y-4 bg-blue-50 p-4 rounded-lg">
                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Tenant ID <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="text"
                          name="tenantId"
                          value={config.tenantId}
                          onChange={handleInputChange}
                          placeholder="e.g., 12345678-1234-1234-1234-123456789012"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        />
                        <p className="mt-1 text-xs text-gray-500">Azure AD Tenant ID (Directory ID)</p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Application (Client) ID <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="text"
                          name="clientId"
                          value={config.clientId}
                          onChange={handleInputChange}
                          placeholder="e.g., 87654321-4321-4321-4321-210987654321"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        />
                        <p className="mt-1 text-xs text-gray-500">App Registration Client ID</p>
                      </div>

                      <div>
                        <label className="block text-sm font-medium text-gray-700 mb-2">
                          Client Secret <span className="text-red-500">*</span>
                        </label>
                        <input
                          type="password"
                          name="clientSecret"
                          value={config.clientSecret}
                          onChange={handleInputChange}
                          placeholder="Enter client secret value"
                          className="w-full px-3 py-2 border border-gray-300 rounded-md text-gray-900 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-blue-500"
                        />
                        <p className="mt-1 text-xs text-gray-500">Client Secret from App Registration (keep secure)</p>
                      </div>
                    </div>
                  )}
                </div>

                {/* SSO Enabled Toggle */}
                <div className="border-t border-gray-200 pt-6">
                  <div className="flex items-center justify-between">
                    <div>
                      <h3 className="text-lg font-medium text-gray-900">SSO Status</h3>
                      <p className="text-sm text-gray-600">Enable or disable SSO for this tenant</p>
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
                    onClick={() => setShowNewConfig(false)}
                    className="px-4 py-2 border border-gray-300 text-sm font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50"
                  >
                    Cancel
                  </button>
                  <button
                    type="submit"
                    disabled={loading}
                    className="px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 disabled:opacity-50"
                  >
                    {loading ? 'Saving...' : 'Save Configuration'}
                  </button>
                </div>
              </form>
            </div>
          )}

          {/* Setup Instructions */}
          <div className="bg-white shadow rounded-lg p-6">
            <h2 className="text-xl font-semibold text-gray-900 mb-6">Entra ID Setup Instructions</h2>
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
                      Your application URL: <strong>https://userly-pro.vercel.app</strong>
                    </p>
                  </div>
                </div>
              </div>

              <div className="space-y-3">
                <h3 className="font-medium text-gray-900">Step 1: Create Enterprise Application in Entra ID</h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                  <li>Go to Microsoft Entra admin center</li>
                  <li>Navigate to Applications &gt; Enterprise applications</li>
                  <li>Click "New application" &gt; "Create your own application"</li>
                  <li>Enter a name (e.g., "Userly") and select "Integrate any other application you don't find in the gallery"</li>
                  <li>Click Create</li>
                </ol>
              </div>

              <div className="space-y-3">
                <h3 className="font-medium text-gray-900">Step 2: Configure SAML SSO</h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                  <li>In the new application, go to "Single sign-on"</li>
                  <li>Select "SAML" as the single sign-on method</li>
                  <li>Download the "Federation Metadata XML" file from Entra ID</li>
                  <li>Upload it in the form above, or copy the values manually</li>
                </ol>
              </div>

              <div className="space-y-3">
                <h3 className="font-medium text-gray-900">Step 3: Configure Reply URL</h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                  <li>In Basic SAML Configuration, set Reply URL (Assertion Consumer Service URL) to:</li>
                  <li className="font-mono text-xs bg-gray-100 p-2 rounded">https://userly-341i.onrender.com/api/saml/acs</li>
                </ol>
              </div>

              <div className="space-y-3">
                <h3 className="font-medium text-gray-900">Step 4: Download Service Provider Metadata</h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                  <li>After saving your configuration, click "Download Metadata"</li>
                  <li>Upload this metadata file to your Entra ID application</li>
                  <li>Or manually configure the Identifier (Entity ID) and Reply URL in Entra ID</li>
                </ol>
              </div>

              <div className="space-y-3">
                <h3 className="font-medium text-gray-900">Step 5: Assign Users</h3>
                <ol className="list-decimal list-inside space-y-2 text-sm text-gray-600 ml-4">
                  <li>Go to "Users and groups" in your Entra ID application</li>
                  <li>Add users or groups that should have access</li>
                  <li>Ensure users are assigned to the application</li>
                </ol>
              </div>
            </div>
          </div>
        </div>
        </div>
      </div>
    </div>
  );
};

export default SamlConfig;
