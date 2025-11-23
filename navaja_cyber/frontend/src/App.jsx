import React, { useState, useEffect } from 'react';
import Dashboard from './components/Dashboard';
import FindingsList from './components/FindingsList';
import CTFPanel from './components/CTFPanel';
import AgentsList from './components/AgentsList';
import Login from './components/Login';

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:8000';

function App() {
  const [currentView, setCurrentView] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(false);
  const [user, setUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('navaja_token'));

  useEffect(() => {
    if (token) {
      fetchUser();
    }
  }, [token]);

  const fetchUser = async () => {
    try {
      const response = await fetch(`${API_URL}/api/auth/me`, {
        headers: {
          'Authorization': `Bearer ${token}`
        }
      });
      if (response.ok) {
        const userData = await response.json();
        setUser(userData);
        setIsAuthenticated(true);
      } else {
        handleLogout();
      }
    } catch (error) {
      console.error('Auth error:', error);
    }
  };

  const handleLogin = (newToken, userData) => {
    localStorage.setItem('navaja_token', newToken);
    setToken(newToken);
    setUser(userData);
    setIsAuthenticated(true);
  };

  const handleLogout = () => {
    localStorage.removeItem('navaja_token');
    setToken(null);
    setUser(null);
    setIsAuthenticated(false);
  };

  if (!isAuthenticated) {
    return <Login onLogin={handleLogin} apiUrl={API_URL} />;
  }

  const renderView = () => {
    switch (currentView) {
      case 'dashboard':
        return <Dashboard apiUrl={API_URL} token={token} />;
      case 'findings':
        return <FindingsList apiUrl={API_URL} token={token} />;
      case 'ctf':
        return <CTFPanel apiUrl={API_URL} token={token} />;
      case 'agents':
        return <AgentsList apiUrl={API_URL} token={token} />;
      default:
        return <Dashboard apiUrl={API_URL} token={token} />;
    }
  };

  return (
    <div className="min-h-screen bg-gray-900">
      {/* Navigation */}
      <nav className="bg-gray-800 border-b border-gray-700">
        <div className="max-w-7xl mx-auto px-4">
          <div className="flex justify-between h-16">
            <div className="flex items-center">
              <span className="text-xl font-bold text-green-400">NavajaCyber</span>
              <div className="ml-10 flex space-x-4">
                <button
                  onClick={() => setCurrentView('dashboard')}
                  className={`px-3 py-2 rounded-md text-sm font-medium ${
                    currentView === 'dashboard' ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  Dashboard
                </button>
                <button
                  onClick={() => setCurrentView('agents')}
                  className={`px-3 py-2 rounded-md text-sm font-medium ${
                    currentView === 'agents' ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  Agents
                </button>
                <button
                  onClick={() => setCurrentView('findings')}
                  className={`px-3 py-2 rounded-md text-sm font-medium ${
                    currentView === 'findings' ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  Findings
                </button>
                <button
                  onClick={() => setCurrentView('ctf')}
                  className={`px-3 py-2 rounded-md text-sm font-medium ${
                    currentView === 'ctf' ? 'bg-gray-900 text-white' : 'text-gray-300 hover:bg-gray-700'
                  }`}
                >
                  CTF
                </button>
              </div>
            </div>
            <div className="flex items-center">
              <span className="text-gray-300 mr-4">{user?.username}</span>
              <button
                onClick={handleLogout}
                className="text-gray-300 hover:text-white text-sm"
              >
                Logout
              </button>
            </div>
          </div>
        </div>
      </nav>

      {/* Main Content */}
      <main className="max-w-7xl mx-auto py-6 px-4">
        {renderView()}
      </main>

      {/* Footer */}
      <footer className="bg-gray-800 border-t border-gray-700 py-4 mt-8">
        <div className="max-w-7xl mx-auto px-4 text-center text-gray-400 text-sm">
          <p>USO AUTORIZADO ÚNICAMENTE - NavajaCyber v0.1.0</p>
        </div>
      </footer>
    </div>
  );
}

export default App;
