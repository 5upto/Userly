import React from 'react';
import { useAuth } from '../contexts/AuthContext';

const Toolbar = ({ selectedUsers, onBlock, onUnblock, onDelete, onMakeAdmin, onRemoveAdmin, users, loading }) => {
  const { user } = useAuth();
  const hasSelection = selectedUsers.length > 0;
  
  // Get role from user context or decode from token as fallback
  const getUserRole = () => {
    if (user?.role) return user.role;
    
    // Fallback: decode from token
    const token = localStorage.getItem('token');
    if (token) {
      try {
        const base64Url = token.split('.')[1];
        const base64 = base64Url.replace(/-/g, '+').replace(/_/g, '/');
        const jsonPayload = decodeURIComponent(atob(base64).split('').map(c => {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
        const payload = JSON.parse(jsonPayload);
        return payload.role;
      } catch (e) {
        return null;
      }
    }
    return null;
  };
  
  const userRole = getUserRole();
  const isSuperAdmin = userRole === 'super_admin';
  
  
  // Check if selected users include any standard users (for Make Admin button)
  const hasStandardUser = selectedUsers.some(id => {
    const u = users.find(user => user.id === id || user.id === parseInt(id));
    return u && u.role === 'standard';
  });
  
  // Check if selected users include any admins (for Remove Admin button)
  const hasAdmin = selectedUsers.some(id => {
    const u = users.find(user => user.id === id || user.id === parseInt(id));
    return u && u.role === 'admin';
  });

  return (
    <div className="bg-white border-b border-gray-200 px-4 py-3 sm:px-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center space-x-3">
          <span className="text-sm text-gray-700">
            {selectedUsers.length} user{selectedUsers.length !== 1 ? 's' : ''} selected
          </span>
        </div>
        
        <div className="flex items-center space-x-2">
          <button
            onClick={onBlock}
            disabled={!hasSelection || loading}
            title="Block"
            className="inline-flex items-center p-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z" />
            </svg>
          </button>

          <button
            onClick={onUnblock}
            disabled={!hasSelection || loading}
            title="Unblock"
            className="inline-flex items-center p-2 border border-gray-300 shadow-sm text-sm leading-4 font-medium rounded-md text-gray-700 bg-white hover:bg-gray-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed"
          >
            <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 11V7a4 4 0 118 0m-4 8v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2z" />
            </svg>
          </button>

          {isSuperAdmin && hasStandardUser && (
            <button
              onClick={onMakeAdmin}
              disabled={!hasSelection || loading}
              title="Make Admin"
              className="inline-flex items-center px-3 py-2 border border-blue-300 shadow-sm text-sm leading-4 font-medium rounded-md text-blue-700 bg-white hover:bg-blue-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-blue-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Make Admin
            </button>
          )}
          
          {isSuperAdmin && hasAdmin && (
            <button
              onClick={onRemoveAdmin}
              disabled={!hasSelection || loading}
              title="Remove Admin"
              className="inline-flex items-center px-3 py-2 border border-orange-300 shadow-sm text-sm leading-4 font-medium rounded-md text-orange-700 bg-white hover:bg-orange-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-orange-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <svg className="w-4 h-4 mr-2" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M10 14l2-2m0 0l2-2m-2 2l-2-2m2 2l2 2m7-2a9 9 0 11-18 0 9 9 0 0118 0z" />
              </svg>
              Remove Admin
            </button>
          )}

          {isSuperAdmin && (
            <button
              onClick={onDelete}
              disabled={!hasSelection || loading}
              title="Delete"
              className="inline-flex items-center p-2 border border-red-300 shadow-sm text-sm leading-4 font-medium rounded-md text-red-700 bg-white hover:bg-red-50 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500 disabled:opacity-50 disabled:cursor-not-allowed"
            >
              <svg className="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
              </svg>
            </button>
          )}
        </div>
      </div>
    </div>
  );
};

export default Toolbar;