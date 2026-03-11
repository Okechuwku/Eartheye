import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar.jsx';
import LandingPage from './pages/LandingPage.jsx';
import Dashboard from './pages/Dashboard.jsx';
import Login from './pages/Login.jsx';
import Register from './pages/Register.jsx';
import NewScan from './pages/NewScan.jsx';
import ScanResults from './pages/ScanResults.jsx';
import AdminPanel from './pages/AdminPanel.jsx';
import { useAuth } from './context/AuthContext.jsx';
import { isAdminRole } from './utils/roles.js';

function ProtectedRoute({ children, adminOnly = false }) {
  const { user, loading } = useAuth();
  
  if (loading) return <div className="min-h-screen flex items-center justify-center text-cyber-blue font-mono">Initializing Neural Link...</div>;
  if (!user) return <Navigate to="/login" />;
  if (adminOnly && !isAdminRole(user.role)) return <Navigate to="/dashboard" />;
  
  return children;
}

function App() {
  return (
    <Router>
      <div className="min-h-screen flex flex-col relative overflow-hidden bg-cyber-bg text-cyber-text">
        <div className="fixed inset-0 z-0 bg-cyber-gradient pointer-events-none opacity-40"></div>
        <div className="z-10 relative flex-grow flex flex-col">
          <Navbar />
          <main className="flex-grow p-4 md:p-8 flex flex-col relative z-20">
            <Routes>
              <Route path="/" element={<LandingPage />} />
              <Route path="/login" element={<Login />} />
              <Route path="/register" element={<Register />} />
              <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
              <Route path="/scans/new" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
              <Route path="/scans/:id" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
              <Route path="/admin" element={<ProtectedRoute adminOnly={true}><AdminPanel /></ProtectedRoute>} />
            </Routes>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
