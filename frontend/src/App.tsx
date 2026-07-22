import { useEffect, useState } from 'react';
import { Nav } from './components/Nav';
import { Footer } from './components/Footer';
import { Landing } from './pages/Landing';
import { Dashboard } from './pages/Dashboard';

function usePath() {
  const [path, setPath] = useState(window.location.pathname);

  useEffect(() => {
    const onPop = () => setPath(window.location.pathname);
    window.addEventListener('popstate', onPop);
    return () => window.removeEventListener('popstate', onPop);
  }, []);

  const navigate = (to: string) => {
    window.history.pushState({}, '', to);
    setPath(to);
    window.scrollTo(0, 0);
  };

  return { path, navigate };
}

export default function App() {
  const { path, navigate } = usePath();
  const isDashboard = path.startsWith('/dashboard');

  return (
    <div className="min-h-screen flex flex-col">
      <Nav onNavigate={navigate} current={path} />
      <main className="flex-1">
        {isDashboard ? <Dashboard /> : <Landing onNavigate={navigate} />}
      </main>
      {!isDashboard && <Footer />}
    </div>
  );
}
