import type { Component } from 'solid-js';

import { createRenderEffect, createSignal, For } from 'solid-js';
import { API_BASE_URL } from '../constants';

const Info: Component = () => {
  const [url, setUrl] = createSignal('');
  const [data, setData] = createSignal([]);

  const fetchData = async () => {
    const token = await localStorage.getItem('token');
    const resp = await fetch(`${API_BASE_URL}/info`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    const json = await resp.json();
    setData(json);
  }

  const handleShort = async () => {
    const token = await localStorage.getItem('token');
    const resp = await fetch(`${API_BASE_URL}/shorten`, {
      method: 'POST',
      body: JSON.stringify({ uri: url() }),
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-type': 'application/json; charset=UTF-8'
      }
    })
    fetchData();
  }

  const handleClick = () => {
    setTimeout(() => {
      fetchData();
    }, 1000);
  }

  createRenderEffect(() => {
    fetchData();
  });
  return ( 
    <div class="flex flex-grow flex-col items-center p-4">
      <div class="flex w-4/5 max-w-4xl mt-12">
          <input type="text" name="url" autocomplete="off" onchange={(event) => setUrl(event.target.value)} placeholder="Your lengthy URL here." class="block w-full text-cyan bg-darker-800 px-6 py-2 border border-dashed rounded focus:text-cyan mr-4 font-poppins" />
          <button class="px-6 py-2 border border-dashed rounded hover:bg-cyan hover:text-darker font-press-start font-bold text-xs" onclick={handleShort}>SHORT</button>
      </div>
      <table class="w-4/5 max-w-4xl border border-dashed mt-12">
        <thead class="border-b border-dashed">
          <tr class="font-press-start text-sm font-bold">
            <th class="border-r border-dashed py-2"> YOUR URL</th>
            <th class="border-r border-dashed py-2">SHORT.ME URL</th>
            <th class="py-2">CLICKED</th>
          </tr>
        </thead>
        <tbody class="font-poppins text-center">
          <For each={data()}>
            {element => 
              <tr class="border-b border-dashed">
                <td class="border-r border-dashed py-2 text-orange">{element.value}</td>
                <td class="border-r border-dashed py-2 text-green" onclick={handleClick}>
                  <a href={`${API_BASE_URL}/${element.link}`} target="blank">short.me/{element.link}</a>
                </td>
                <td class="text-purple-200">{element.clicked}</td>
              </tr>
            }
          </For>
        </tbody>
      </table>
    </div>
  );
}

export default Info;
