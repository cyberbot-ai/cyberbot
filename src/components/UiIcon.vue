<script setup lang="ts">
withDefaults(defineProps<{name:string;size?:number}>(),{size:18});
const paths:Record<string,string>={
 console:'m4 6 6 6-6 6 M12 18h8',
 monitoring:'M3 4h18v13H3z M8 21h8 M12 17v4 M6 11h3l2-4 3 7 2-3h2',
 undo:'M9 14 4 9l5-5 M4 9h9a6 6 0 0 1 0 12h-1',
 resolve:'M9 12l2 2 4-4 M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0',
 servers:'M4 3h16v7H4z M4 14h16v7H4z M7 6.5h.01 M7 17.5h.01 M11 6.5h6 M11 17.5h6',
 incident:'M12 3 2 21h20L12 3Z M12 9v5 M12 17h.01',
 gear:'M9.5 2h5l.5 2.5 2 1.2 2.4-.8 2.5 4.3-1.9 1.7v2.2l1.9 1.7-2.5 4.3-2.4-.8-2 1.2-.5 2.5h-5l-.5-2.5-2-1.2-2.4.8-2.5-4.3L4 13.1v-2.2L2.1 9.2l2.5-4.3 2.4.8 2-1.2.5-2.5Z M15.5 12a3.5 3.5 0 1 1-7 0 3.5 3.5 0 0 1 7 0',
 sources:'M3 7h18 M17 3l4 4-4 4 M21 17H3 M7 13l-4 4 4 4',
 refresh:'M3 12a9 9 0 0 1 9-9 9.75 9.75 0 0 1 6.74 2.74L21 8 M21 3v5h-5 M21 12a9 9 0 0 1-9 9 9.75 9.75 0 0 1-6.74-2.74L3 16 M8 16H3v5',
 auto:'m13 2-9 12h7l-1 8 10-13h-7l1-7Z',
 settings:'M4 6h16 M4 12h16 M4 18h16 M8 3v6 M16 9v6 M10 15v6',
 search:'M21 21l-5-5 M18 10a8 8 0 1 1-16 0 8 8 0 0 1 16 0',
 plus:'M12 5v14 M5 12h14',close:'m6 6 12 12 M18 6 6 18',
 pause:'M6 4h4v16H6z M14 4h4v16h-4z',play:'m7 4 13 8-13 8V4Z',
 arrow:'M5 12h14 m-6-6 6 6-6 6',external:'M14 3h7v7 M21 3 11 13 M10 3H3v18h18v-7',
 sun:'M12 8a4 4 0 1 0 0 8 4 4 0 0 0 0-8 M12 2v2 M12 20v2 M2 12h2 M20 12h2 M5 5l1 1 M18 18l1 1 M5 19l1-1 M18 6l1-1',
 moon:'M20 15.5A9 9 0 0 1 8.5 4 9 9 0 1 0 20 15.5Z',
 clock:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 7v5l3 2',
 info:'M12 3a9 9 0 1 0 0 18 9 9 0 0 0 0-18 M12 11v5 M12 8h.01',
 history:'M3 12a9 9 0 1 0 3-6.7 M3 3v5h5 M12 7v5l3 2',
 folder:'M3 6h7l2 3h9v12H3V6Z',chevron:'m9 5 7 7-7 7',check:'m5 12 4 4L19 6',
 copy:'M9 9h11v11H9z M5 15H4V4h11v1'
};
</script>
<template><svg :width="size" :height="size" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" focusable="false"><path :d="paths[name]??paths.servers"/></svg></template>
<style scoped>svg{display:block;flex-shrink:0}</style>
