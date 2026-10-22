import { useEffect } from 'react';
import { BrowserRouter, Navigate, Route, Routes } from 'react-router-dom';
import Layout from './components/Layout';
import ProtectedRoute from './components/ProtectedRoute';
import LoginPage from './pages/LoginPage';
import DashboardPage from './pages/DashboardPage';
import AlertsPage from './pages/AlertsPage';
import ParsePage from './pages/ParsePage';
import UsersPage from './pages/UsersPage';
import AuditPage from './pages/AuditPage';
import { useAuthStore } from './store/authStore';

export default function App() {
  const user = useAuthStore((s) => s.user);
  const logout = useAuthStore((s) => s.logout);

  useEffect(() => {
    // Fired by the axios interceptor when refresh rotation fails.
    const onLogout = () => logout();
    window.addEventListener('actilp:logout', onLogout);
    return () => window.removeEventListener('actilp:logout', onLogout);
  }, [logout]);

  // Opt into the React Router v7 behaviours now: silences the v6 deprecation
  // warnings (v7_startTransition, v7_relativeSplatPath) and avoids a breaking
  // change when upgrading to v7.
  return (
    <BrowserRouter
      future={{
        v7_startTransition: true,
        v7_relativeSplatPath: true,
      }}
    >
      <Routes>
        <Route path="/login" element={user ? <Navigate to="/" replace /> : <LoginPage />} />

        <Route
          path="/"
          element={
            <ProtectedRoute>
              <Layout>
                <DashboardPage />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/alerts"
          element={
            <ProtectedRoute>
              <Layout>
                <AlertsPage />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/parse"
          element={
            <ProtectedRoute roles={['admin', 'analyst']}>
              <Layout>
                <ParsePage />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/users"
          element={
            <ProtectedRoute roles={['admin']}>
              <Layout>
                <UsersPage />
              </Layout>
            </ProtectedRoute>
          }
        />
        <Route
          path="/audit"
          element={
            <ProtectedRoute roles={['admin']}>
              <Layout>
                <AuditPage />
              </Layout>
            </ProtectedRoute>
          }
        />

        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}
