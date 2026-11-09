// @vitest-environment happy-dom
import { mount } from '@vue/test-utils';
import { describe,it,expect,vi,afterEach } from 'vitest';
import { nextTick } from 'vue';
import FleetGrid from './FleetGrid.vue';
import type { Server } from '../types';
const servers:Server[]=Array.from({length:500},(_,i)=>({id:String(i),sourceId:'fixture',name:`host-${i}`,endpoint:{host:'localhost',user:'ops',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0}));
describe('500-server fleet',()=>{
  afterEach(()=>vi.unstubAllGlobals());
  it.each([false,true])('bounds the DOM and keeps scroll on metric updates (ribbon=%s)',async compact=>{
    vi.stubGlobal('ResizeObserver',class { observe(){} unobserve(){} disconnect(){} });
    const wrapper=mount(FleetGrid,{props:{servers,now:1000,interval:180,compact}});
    expect(wrapper.findAll('button').length).toBeLessThan(40);
    const viewport=wrapper.get('.viewport');
    (viewport.element as HTMLElement).scrollTop=3000;
    await viewport.trigger('scroll');
    expect(wrapper.text()).not.toContain('host-0');
    await wrapper.setProps({servers:servers.map(s=>({...s,lastAttempt:1200}))});
    expect((viewport.element as HTMLElement).scrollTop).toBe(3000);
    await wrapper.setProps({servers:servers.filter(s=>s.id==='2')});
    expect((viewport.element as HTMLElement).scrollTop).toBe(0);
    expect(wrapper.findAll('button')).toHaveLength(1);
    wrapper.unmount();
  });
  it('measures wrapped rows, preserves the visible anchor and remeasures on resize',async()=>{
    const observers:MockObserver[]=[];
    class MockObserver {
      observed=new Set<Element>();disconnected=false;
      constructor(readonly callback:ResizeObserverCallback){observers.push(this);}
      observe(element:Element){this.observed.add(element);}
      unobserve(element:Element){this.observed.delete(element);}
      disconnect(){this.disconnected=true;this.observed.clear();}
      deliver(element:Element,height:number,width=1000){this.callback([{target:element,contentRect:{height,width}} as ResizeObserverEntry],this as unknown as ResizeObserver);}
    }
    vi.stubGlobal('ResizeObserver',MockObserver);
    const wrapper=mount(FleetGrid,{props:{servers,now:1000,interval:180,compact:true}});
    const viewport=wrapper.get('.viewport');
    (viewport.element as HTMLElement).scrollTop=320;
    await viewport.trigger('scroll');
    const [viewportObserver,rowObserver]=observers;
    rowObserver.deliver(wrapper.get('[data-id="8"]').element,96);
    await nextTick();
    expect((viewport.element as HTMLElement).scrollTop).toBe(384);
    expect(wrapper.get('[data-id="10"]').attributes('aria-posinset')).toBe('11');
    expect(wrapper.findAll('.ribbon-slot').length).toBeLessThan(30);
    viewportObserver.deliver(viewport.element,600,700);
    await nextTick();
    rowObserver.deliver(wrapper.get('[data-id="8"]').element,64);
    await nextTick();
    expect((viewport.element as HTMLElement).scrollTop).toBe(352);
    await wrapper.setProps({servers:servers.map(s=>({...s,lastAttempt:1200}))});
    expect((viewport.element as HTMLElement).scrollTop).toBe(352);
    expect(rowObserver.observed.size).toBeLessThan(30);
    wrapper.unmount();
    expect(observers.every(o=>o.disconnected)).toBe(true);
  });
});
