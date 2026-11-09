import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';
import { fileURLToPath } from 'node:url';
export default defineConfig({
  root:fileURLToPath(new URL('.',import.meta.url)),plugins:[vue(),{
    name:'watch-source-components',
    configureServer(server){server.watcher.add(fileURLToPath(new URL('../../src',import.meta.url)));},
  }],
  resolve:{alias:[{find:/^(?:\.\/|(?:\.\.\/)+)api$/,replacement:fileURLToPath(new URL('api.ts',import.meta.url))}]},
  server:{host:'127.0.0.1',port:1435,strictPort:true,fs:{allow:[fileURLToPath(new URL('../..',import.meta.url))]}},
});
