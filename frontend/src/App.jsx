import { lazy, Suspense } from 'react';
import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import Navbar from './components/Navbar.jsx';
import { useAuth } from './context/AuthContext.jsx';
import { isAdminRole } from './utils/roles.js';

const LandingPage = lazy(() => import('./pages/LandingPage.jsx'));
const Dashboard = lazy(() => import('./pages/Dashboard.jsx'));
const Login = lazy(() => import('./pages/Login.jsx'));
const Register = lazy(() => import('./pages/Register.jsx'));
const NewScan = lazy(() => import('./pages/NewScan.jsx'));
const ScanResults = lazy(() => import('./pages/ScanResults.jsx'));
const AdminPanel = lazy(() => import('./pages/AdminPanel.jsx'));

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
            <Suspense fallback={<div className="min-h-screen flex items-center justify-center text-cyber-blue font-mono">Loading interface...</div>}>
              <Routes>
                <Route path="/" element={<LandingPage />} />
                <Route path="/login" element={<Login />} />
                <Route path="/register" element={<Register />} />
                <Route path="/dashboard" element={<ProtectedRoute><Dashboard /></ProtectedRoute>} />
                <Route path="/scans/new" element={<ProtectedRoute><NewScan /></ProtectedRoute>} />
                <Route path="/scans/:id" element={<ProtectedRoute><ScanResults /></ProtectedRoute>} />
                <Route path="/admin" element={<ProtectedRoute adminOnly={true}><AdminPanel /></ProtectedRoute>} />
              </Routes>
            </Suspense>
          </main>
        </div>
      </div>
    </Router>
  );
}

export default App;
