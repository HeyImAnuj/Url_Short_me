import type { Component } from "solid-js";

import NavBar from './components/NavBar';
import Home from './pages/Home';
import Login from './pages/Login';
import Register from './pages/Register';
import Info from './pages/Info';
import Admin from './pages/Admin';

import { createRenderEffect, createSignal } from 'solid-js';

const App: Component = () => {
  const [logged, setLogged] = createSignal(false);
  const [isAdmin, setIsAdmin] = createSignal(false);
  const [page, setPage] = createSignal('home');

  const preprocess = async () => {
    let token = await localStorage.getItem('token');
    let admin = await localStorage.getItem('isAdmin');
    if(token != null) {
      setLogged(true);
      if(admin == 'true') setIsAdmin(true);
    }

    if(logged()) setPage('info');
    if(isAdmin()) setPage('admin');
  }
  createRenderEffect(() => {
    preprocess();
  });

  const handleLogout = async () => {
    await localStorage.removeItem('token');
    await localStorage.removeItem('isAdmin');
    setLogged(false);
    setIsAdmin(false);
    setPage('home');
  }

  return (
    <div class="w-full min-h-screen bg-darker-800 text-white flex flex-col">
      <NavBar logged={logged} setPage={setPage} onLogout={handleLogout} page={page} />
      { page() === 'home' && <Home /> }
      { page() === 'login' && <Login setLogged={setLogged} setIsAdmin={setIsAdmin} setPage={setPage} /> }
      { page() === 'register' && <Register setPage={setPage} /> }
      { page() === 'info' && <Info /> }
      { page() === 'admin' &&  <Admin /> }
    </div>
  );
};

export default App;
