import {onBeforeUnmount,ref,type Ref} from 'vue';
import {call,preview} from './api';

// Each queued value owns its scope. Navigation cannot redirect a pending save.
export function useConfigAutosave<T extends object>(options:{command:string;scope:()=>Record<string,string>;value:()=>T|undefined;dirty:Ref<boolean>;error:Ref<string>;saved:()=>Promise<void>|void}){
 const saving=ref(false),pending=ref(false);
 type Job={scope:Record<string,string>;key:string;config:T;json:string};
 const queue=new Map<string,Job>();let timer:ReturnType<typeof setTimeout>|undefined,disposed=false;
 const key=()=>JSON.stringify(options.scope());
 async function flush(){
  clearTimeout(timer);if(saving.value||preview)return;
  saving.value=true;
  try{while(queue.size){
   const [k,job]=queue.entries().next().value!;queue.delete(k);
   try{await call(options.command,{...job.scope,config:job.config});
    if(!disposed&&key()===job.key&&JSON.stringify(options.value())===job.json&&!queue.has(k)){options.dirty.value=false;options.error.value='';await options.saved();}
   }catch(e){if(!disposed&&key()===job.key)options.error.value=String(e).replace(/^Error: /,'');}
  }}finally{saving.value=false;pending.value=queue.size>0;}
 }
 function edited(event?:Event){
  if(preview)return;
  const config=options.value();if(!config)return;
  options.dirty.value=true;options.error.value='';const k=key();
  const form=event?.currentTarget as HTMLFormElement|undefined;
  if(form?.tagName==='FORM'&&!form.checkValidity()){queue.delete(k);pending.value=queue.size>0;options.error.value='Check the format and range of values.';return;}
  const json=JSON.stringify(config);queue.set(k,{scope:{...options.scope()},key:k,config:JSON.parse(json) as T,json});pending.value=true;clearTimeout(timer);timer=setTimeout(()=>void flush(),350);
 }
 function submit(){edited();return flush();}
 onBeforeUnmount(()=>{void flush();disposed=true;clearTimeout(timer);});
 return {saving,pending,edited,flush,submit};
}
