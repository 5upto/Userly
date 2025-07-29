import React, { useState, useEffect } from 'react';
import { useAuth } from '../contexts/AuthContext';
import { userService } from '../services/api';
import { toast } from 'react-toastify';
import Toolbar from './Toolbar';
import UserTable from './UserTable';
import { Sparklines, SparklinesLine, SparklinesBars } from 'react-sparklines';
import { format } from 'date-fns';

const Dashboard = () => {
  const [users, setUsers] = useState([]);
  const [selectedUsers, setSelectedUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [actionLoading, setActionLoading] = useState(false);

  const { user, logout } = useAuth();

  useEffect(() => {
    fetchUsers();
  }, []);

  const fetchUsers = async () => {
    try {
      setLoading(true);
      const response = await userService.getUsers();
      setUsers(response.data);
    } catch (error) {
      if (error.response?.data?.redirect) {
        toast.error('Session expired. Please login again.');
        logout();
      } else {
        toast.error('Failed to fetch users');
      }
    } finally {
      setLoading(false);
    }
  };

  const handleSelectUser = (userId, isSelected) => {
    if (isSelected) {
      setSelectedUsers([...selectedUsers, userId]);
    } else {
      setSelectedUsers(selectedUsers.filter(id => id !== userId));
    }
  };

  const handleSelectAll = (isSelected) => {
    if (isSelected) {
      setSelectedUsers(users.map(user => user.id));
    } else {
      setSelectedUsers([]);
    }
  };

  const handleBlock = async () => {
    if (selectedUsers.length === 0) return;

    try {
      setActionLoading(true);
      await userService.blockUsers(selectedUsers);
      toast.success(`${selectedUsers.length} user(s) blocked successfully`);
      setSelectedUsers([]);
      await fetchUsers();
    } catch (error) {
      if (error.response?.data?.redirect) {
        toast.error('Session expired. Please login again.');
        logout();
      } else {
        toast.error('Failed to block users');
      }
    } finally {
      setActionLoading(false);
    }
  };

  const handleUnblock = async () => {
    if (selectedUsers.length === 0) return;

    try {
      setActionLoading(true);
      await userService.unblockUsers(selectedUsers);
      toast.success(`${selectedUsers.length} user(s) unblocked successfully`);
      setSelectedUsers([]);
      await fetchUsers();
    } catch (error) {
      if (error.response?.data?.redirect) {
        toast.error('Session expired. Please login again.');
        logout();
      } else {
        toast.error('Failed to unblock users');
      }
    } finally {
      setActionLoading(false);
    }
  };

  const handleDelete = async () => {
    if (selectedUsers.length === 0) return;

    if (window.confirm(`Are you sure you want to delete ${selectedUsers.length} user(s)? This action cannot be undone.`)) {
      try {
        setActionLoading(true);
        await userService.deleteUsers(selectedUsers);
        toast.success(`${selectedUsers.length} user(s) deleted successfully`);
        setSelectedUsers([]);
        await fetchUsers();
      } catch (error) {
        if (error.response?.data?.redirect) {
          toast.error('Session expired. Please login again.');
          logout();
        } else {
          toast.error('Failed to delete users');
        }
      } finally {
        setActionLoading(false);
      }
    }
  };

  return (
    <div className="h-screen w-screen bg-gray-50 flex flex-col">
      <div className="bg-white shadow">
        <div className="w-full px-6 lg:px-8">
          <div className="flex justify-between items-center py-6">
            <div className="flex items-center space-x-3">
              <svg className="w-8 h-8 text-indigo-600" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 20h5v-2a3 3 0 00-5.356-1.857M17 20H7m10 0v-2c0-.656-.126-1.283-.356-1.857M7 20H2v-2a3 3 0 015.356-1.857M7 20v-2c0-.656.126-1.283.356-1.857m0 0a5.002 5.002 0 019.288 0M15 7a3 3 0 11-6 0 3 3 0 016 0zm6 3a2 2 0 11-4 0 2 2 0 014 0zM7 10a2 2 0 11-4 0 2 2 0 014 0z" />
              </svg>
              <div>
                <h1 className="text-2xl font-bold text-gray-900">Userly</h1>
                <p1 className="text-sm text-gray-600">
                  Welcome back, {user?.name}
                </p1>
              </div>
            </div>

            <div className="flex items-center space-x-4">
              <button
                onClick={fetchUsers}
                disabled={loading}
                className="inline-flex items-center justify-center py-2 px-4 border border-transparent shadow-sm text-sm font-medium rounded-md text-white bg-indigo-600 hover:bg-indigo-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-indigo-500 disabled:opacity-50"
              >
                {loading ? (
                  <span className="flex items-center">
                    <svg className="animate-spin -ml-1 mr-2 h-4 w-4" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    Refreshing...
                  </span>
                ) : (
                  <span className="flex items-center">
                    <svg className="w-4 h-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                      <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
                    </svg>
                    Refresh
                  </span>
                )}
              </button>
              <button
                onClick={logout}
                className="inline-flex items-center px-4 py-2 border border-transparent text-sm font-medium rounded-md text-white bg-red-600 hover:bg-red-700 focus:outline-none focus:ring-2 focus:ring-offset-2 focus:ring-red-500"
              >
                <svg className="w-4 h-4 mr-2" xmlns="http://www.w3.org/2000/svg" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1" />
                </svg>
                Logout
              </button>
            </div>

          </div>
        </div>
      </div>

      <Toolbar 
        onBlock={handleBlock}
        onUnblock={handleUnblock}
        onDelete={handleDelete}
        selectedCount={selectedUsers.length}
        loading={actionLoading}
      />
      <main className="flex-1 overflow-y-auto">
        <div className="p-6 lg:px-8">
          {/* Activity Overview */}
          <div className="mb-6 bg-white shadow rounded-lg p-6">
            <h2 className="text-lg font-semibold text-gray-900 mb-4">Activity Overview</h2>
            <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500">New Users</h3>
                <div className="mt-2">
                  <Sparklines data={[0, 4, 5, 3, 7, 8, 6, 9, 10, 12]} limit={10}>
                    <SparklinesLine color="#4F46E5" style={{ strokeWidth: 2 }} />
                  </Sparklines>
                </div>
                <p className="mt-2 text-sm text-gray-600">Last 7 days</p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500">Active Users</h3>
                <div className="mt-2">
                  <Sparklines data={[20, 25, 30, 28, 35, 40, 38, 45, 50, 48]} limit={10}>
                    <SparklinesLine color="#10B981" style={{ strokeWidth: 2 }} />
                  </Sparklines>
                </div>
                <p className="mt-2 text-sm text-gray-600">Last 7 days</p>
              </div>
              <div className="bg-gray-50 p-4 rounded-lg">
                <h3 className="text-sm font-medium text-gray-500">User Actions</h3>
                <div className="mt-2">
                  <Sparklines data={[5, 8, 10, 12, 15, 18, 20, 22, 25, 28]} limit={10}>
                    <SparklinesLine color="#F59E0B" style={{ strokeWidth: 2 }} />
                  </Sparklines>
                </div>
                <p className="mt-2 text-sm text-gray-600">Last 7 days</p>
              </div>
            </div>
          </div>

          {/* User Table */}
          <div className="bg-white shadow rounded-lg">
            <UserTable
              users={users}
              selectedUsers={selectedUsers}
              onSelectUser={handleSelectUser}
              onSelectAll={handleSelectAll}
            />
          </div>
        </div>
      </main>
    </div>
  );
};

export default Dashboard;