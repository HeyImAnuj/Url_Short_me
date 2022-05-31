import type { Component } from 'solid-js';

import svg from '../assets/url-shortener.svg';

const Home: Component = () => (
  <div class="flex justify-center items-center flex-col flex-grow font-press-start">
    <img src={svg} class="h-72"/>
    <div class="text-center my-12">
      <p class="text-darker-300 my-4 font-bold">One stop destination for shortening your URLs<span></span></p>
      <p class="text-xs font-thin text-green underline"> Login / Register to Get Started </p>
    </div>
  </div>
)

export default Home;
