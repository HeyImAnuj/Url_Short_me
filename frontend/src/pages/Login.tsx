import type { Component } from 'solid-js';

import { createSignal } from 'solid-js';
import { API_BASE_URL } from '../constants';

import LoginSvg from '../assets/login.svg'

const Login: Component = ({ setLogged, setPage, setIsAdmin }) => {
  const [email, setEmail] = createSignal('');
  const [password, setPassword] = createSignal('');

  const handleLogin = async () => {
    const resp = await fetch(`${API_BASE_URL}/login`, {
      method: 'POST',
      body: JSON.stringify({ email: email(), password: password() }),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    const json = await resp.json();
    if(json.token != undefined) {
      await localStorage.setItem('token', json.token);
      setLogged(true);
      setPage('info');
      if(email() === 'admin@short.me') {
        await localStorage.setItem('isAdmin', 'true');
        setIsAdmin(true); 
        setPage('admin');
      }
    }
  }
  return (
    <div class="flex flex-grow justify-center items-center font-press-start">
      <div class="z-10">
        <div class="mb-3">
          <label for="email" class="text-xs text-cyan">Email</label>
          <input type="email" autocomplete="off" onchange={(evt)=> setEmail(evt.target.value)} name="email" placeholder="example@short.me" class="block text-yellow bg-darker-800 px-6 py-2 border border-dashed rounded focus:text-yellow" />
        </div>
        <div class="mb-6">
          <label for="password" class="text-xs text-cyan">Password</label>
          <input type="password" autocomplete="off" onchange={(evt)=> setPassword(evt.target.value)} name="password" placeholder="******" class="block text-yellow bg-darker-800 px-6 py-2 border border-dashed rounded focus:text-yellow" />
        </div>
        <div class="flex justify-center">
          <button class="px-6 py-2 border border-dashed rounded hover:bg-yellow hover:text-darker" onclick={handleLogin}>Login</button>
        </div>
      </div>
      <div class="absolute z-0 opacity-10">
        <img src={LoginSvg} class="w-100"/>
      </div>
    </div>
  );
}

export default Login;
