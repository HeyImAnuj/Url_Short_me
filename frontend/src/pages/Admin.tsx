import type { Component } from 'solid-js';

import { For, createSignal, createRenderEffect } from 'solid-js';

import { API_BASE_URL } from '../constants';

const Admin: Component = () => {
  const [data, setData] = createSignal([]);

  const fetchData = async () => {
    const token = await localStorage.getItem('token');
    const resp = await fetch(`${API_BASE_URL}/admin`, {
      method: 'GET',
      headers: {
        'Authorization': `Bearer ${token}`
      }
    })
    const json = await resp.json();
    setData(json.slice(1));
  }

  createRenderEffect(() => {
    fetchData();
  });

  return (
    <div class="flex flex-grow flex-col items-center p-4">
      <table class="w-4/5 max-w-4xl border border-dashed mt-12">
        <thead class="border-b border-dashed">
          <tr class="font-press-start text-sm font-bold">
            <th class="border-r border-dashed py-2"> S.No</th>
            <th class="border-r border-dashed py-2">USER</th>
          </tr>
        </thead>
        <tbody class="font-poppins text-center">
          <For each={data()}>
            { (element, i) => 
              <tr class="border-b border-dashed">
                <td class="border-r border-dashed py-2 text-orange">{i() + 1}.</td>
                <td class="py-2 text-green">{element}</td>
              </tr>
            }
          </For>
        </tbody>
      </table>
    </div>
  );
};

export default Admin;
