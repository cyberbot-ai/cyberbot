// @vitest-environment happy-dom
import { mount } from '@vue/test-utils';
import { describe,it,expect,vi,afterEach } from 'vitest';
import { nextTick } from 'vue';
import FleetList from './FleetList.vue';
import type { Server } from '../types';
const servers:Server[]=Array.from({length:500},(_,i)=>({id:String(i),sourceId:'fixture',name:`host-${i}`,endpoint:{host:'localhost',user:'ops',port:22,identityFile:null,jumpHost:null},observation:null,lastError:null,lastAttempt:null,nextCheck:0,failures:0}));
describe('500-server fleet',()=>{
  afterEach(()=>vi.unstubAllGlobals());
  it('bounds the DOM and keeps scroll on metric updates',async()=>{
    vi.stubGlobal('ResizeObserver',class { observe(){} unobserve(){} disconnect(){} });
    const wrapper=mount(FleetList,{props:{servers,now:1000,interval:180}});
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
  it('anchors the focused server after reordering and resets on manual sorting', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const wrapper = mount(FleetList, { attachTo: document.body, props: { servers, now: 1000, interval: 180, scrollResetKey: 'host' } });
    try {
      const viewport = wrapper.get<HTMLElement>('.viewport');
      const oldIndex = 12, newIndex = 320, rowHeight = 32;
      const rowButton = () => wrapper.get<HTMLButtonElement>(`[data-id="${oldIndex}"] button`);
      const offset = (index: number) => index * rowHeight;
      viewport.element.scrollTop = offset(oldIndex - 1) + 3;
      await viewport.trigger('scroll');
      rowButton().element.focus();
      expect(document.activeElement).toBe(rowButton().element);

      const reordered = servers.filter((_, index) => index !== oldIndex);
      reordered.splice(newIndex, 0, servers[oldIndex]);
      await wrapper.setProps({ servers: reordered });
      await nextTick();
      expect(viewport.element.scrollTop).toBe(offset(newIndex - 1) + 3);
      expect(document.activeElement).toBe(rowButton().element);
      expect(wrapper.findAll('button').length).toBeLessThan(40);

      await wrapper.setProps({ scrollResetKey: 'disk' });
      await nextTick();
      expect(viewport.element.scrollTop).toBe(0);
    } finally {
      wrapper.unmount();
    }
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
    const wrapper=mount(FleetList,{props:{servers,now:1000,interval:180}});
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
    const reordered = servers.filter(server => server.id !== '10');
    reordered.splice(20, 0, servers[10]);
    await wrapper.setProps({ servers: reordered });
    await nextTick();
    expect((viewport.element as HTMLElement).scrollTop).toBe(672);
    expect(wrapper.get('[data-id="10"]').attributes('aria-posinset')).toBe('21');
    expect(rowObserver.observed.size).toBeLessThan(30);
    wrapper.unmount();
    expect(observers.every(o=>o.disconnected)).toBe(true);
  });
  it('preserves the visible server when an offscreen project heading is removed', async () => {
    vi.stubGlobal('ResizeObserver', class { observe() {} unobserve() {} disconnect() {} });
    const projectStarts = new Map([['0', 'example.com'], ['40', 'example.net']]);
    const wrapper = mount(FleetList, { props: { servers, projectStarts, now: 1000, interval: 180 } });
    try {
      const viewport = wrapper.get<HTMLElement>('.viewport');
      viewport.element.scrollTop = 1656; // Fifty 32px rows, a 24px first heading and a 32px project break.
      await viewport.trigger('scroll');
      expect(wrapper.find('[data-id="40"]').exists()).toBe(false);
      expect(wrapper.findAll('[data-id]')[0].attributes('data-id')).toBe('48');

      await wrapper.setProps({ projectStarts: new Map([['0', 'example.com']]) });
      await nextTick();
      expect(viewport.element.scrollTop).toBe(1624);
      expect(wrapper.findAll('[data-id]')[0].attributes('data-id')).toBe('48');
    } finally {
      wrapper.unmount();
    }
  });
});
