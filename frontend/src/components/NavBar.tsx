import type { Component } from 'solid-js';
import { createSignal, createRenderEffect } from 'solid-js';

const NavBar: Component = ({ logged, setPage, onLogout, page }) => { 
  const [head, setHead] = createSignal('');
  createRenderEffect(() => {
    if(page() == 'info') setHead('Info Dashboard');
    else if(page() == 'admin') setHead('Admin Panel');
    else setHead('Short.Me');
  });
  return (
    <nav class="flex w-full px-6 h-16 items-center justify-between bg-darker-800 border-b-2 font-press-start">
      <h1 class="text-lg text-orange font-bold">{head}</h1>
      <ul class="flex text-pink text-xs items-center justify-center">
        {
          logged() && <li class="mx-4 px-5 py-2 border border-dashed rounded-lg cursor-pointer hover:bg-red hover:text-darker" onclick={onLogout}>Logout</li>
        }
        { 
          !logged() && <>
            <li class="mx-4 px-5 py-2 border border-dashed rounded-lg cursor-pointer hover:bg-yellow hover:text-darker" onclick={() => setPage('login')}>Login</li>
            <li class="px-5 py-2 border border-dashed rounded-lg cursor-pointer hover:bg-green hover:text-darker" onclick={() => setPage('register')}>Register</li>
          </>
        }
      </ul>
    </nav>
  );
};

export default NavBar;
