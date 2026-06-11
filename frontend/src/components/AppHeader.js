import React from 'react';
import { useNavigate, useLocation } from 'react-router-dom';
import { useAuth } from '../context/AuthContext';
import { useTheme } from '../context/ThemeContext';
import './AppHeader.css';

const AppHeader = ({ showBack = false, onLogout }) => {
  const navigate = useNavigate();
  const location = useLocation();
  const { user, logout } = useAuth();
  const { isDarkMode, toggleTheme } = useTheme();

  const handleLogout = () => {
    const confirmed = window.confirm('Are you sure you want to logout?');
    if (confirmed) {
      if (onLogout) {
        onLogout();
      } else {
        logout();
        navigate('/login');
      }
    }
  };

  const handleBack = () => {
    if (location.pathname === '/chat') {
      navigate('/dashboard');
    } else {
      navigate(-1);
    }
  };

  return (
    <header className="app-header">
      <div className="header-left">
        <div className="logo-section">
          <div className="logo">
            <span className="logo-icon">🔐</span>
            <span className="logo-text">SecureChat</span>
          </div>
          {showBack && (
            <button className="back-button" onClick={handleBack}>
              ← Back
            </button>
          )}
        </div>
      </div>

      <div className="header-right">
        <button className="theme-toggle" onClick={toggleTheme} title={isDarkMode ? 'Switch to Light Mode' : 'Switch to Dark Mode'}>
          {isDarkMode ? '☀️' : '🌙'}
        </button>

        {user && (
          <div className="account-section">
            <div className="account-icon">
              <span>{user.username[0].toUpperCase()}</span>
            </div>
            <span className="account-name">{user.username}</span>
            <button className="logout-button" onClick={handleLogout}>
              Logout
            </button>
          </div>
        )}
      </div>
    </header>
  );
};

export default AppHeader;
