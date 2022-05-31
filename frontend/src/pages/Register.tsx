import type { Component } from 'solid-js';

import { createSignal } from 'solid-js';
import { API_BASE_URL } from '../constants';

import RegisterSvg from '../assets/register.svg'

const Register: Component = ({ setPage }) => {
  const [email, setEmail] = createSignal('');
  const [password, setPassword] = createSignal('');

  const handleRegister = async () => {
    const resp = await fetch(`${API_BASE_URL}/register`, {
      method: 'POST',
      body: JSON.stringify({ email: email(), password: password() }),
      headers: {
        "Content-type": "application/json; charset=UTF-8"
      }
    });
    const status = await resp.status;
    if(status === 201) {
      setPage('home');
    }
  }

  return (
    <div class="flex flex-grow justify-center items-center font-press-start">
      <div class="z-10">
        <div class="mb-3">
          <label for="email" class="text-xs text-cyan">Email</label>
          <input type="email" name="email" autocomplete="off" onchange={(event) => setEmail(event.target.value)} placeholder="example@short.me" class="block text-green bg-darker-800 px-6 py-2 border border-dashed rounded focus:text-green" />
        </div>
        <div class="mb-6">
          <label for="password" class="text-xs text-cyan">Password</label>
          <input type="password" name="password" autocomplete="off" onchange={(event) => setPassword(event.target.value)} placeholder="******" class="block text-green bg-darker-800 px-6 py-2 border border-dashed rounded focus:text-green" />
        </div>
        <div class="flex justify-center">
          <button class="px-6 py-2 border border-dashed rounded hover:bg-green hover:text-darker" onclick={handleRegister}>Register</button>
        </div>
      </div>
      <div class="absolute z-0 opacity-10">
        <img src={RegisterSvg} class="w-100"/>
      </div>
    </div>
  );
}

export default Register;
