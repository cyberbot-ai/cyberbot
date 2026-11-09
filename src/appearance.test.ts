// @vitest-environment happy-dom
import {beforeEach,expect,it} from 'vitest';
import {defaultAppearance,effectiveTheme,readAppearance,saveAppearance,appearanceKey} from './appearance';
beforeEach(()=>localStorage.clear());
const at=(hour:number,minute=0)=>new Date(2026,10,4,hour,minute);
it('switches across midnight at the exact configured boundaries',()=>{
 for(const [hour,minute,theme] of [[19,59,'light'],[20,0,'dark'],[0,0,'dark'],[6,59,'dark'],[7,0,'light']] as const)expect(effectiveTheme(defaultAppearance,at(hour,minute))).toBe(theme);
});
it('honours explicit themes and same-day schedules',()=>{
 expect(effectiveTheme({...defaultAppearance,mode:'light'},at(1))).toBe('light');
 expect(effectiveTheme({...defaultAppearance,mode:'dark'},at(12))).toBe('dark');
 const p={...defaultAppearance,nightStart:'10:00',nightEnd:'18:00'};
 expect(effectiveTheme(p,at(10))).toBe('dark');expect(effectiveTheme(p,at(18))).toBe('light');
});
it('persists preferences and recovers from corrupt or unavailable data',()=>{
 expect(readAppearance()).toEqual(defaultAppearance);
 expect(saveAppearance({...defaultAppearance,mode:'dark'})).toBe(true);
 expect(readAppearance().mode).toBe('dark');
 expect(saveAppearance({...defaultAppearance,nightEnd:'20:00'})).toBe(false);
 expect(readAppearance().mode).toBe('dark');
 localStorage.setItem(appearanceKey,'invalid');expect(readAppearance()).toEqual(defaultAppearance);
 localStorage.setItem(appearanceKey,JSON.stringify({...defaultAppearance,nightStart:'25:00'}));expect(readAppearance()).toEqual(defaultAppearance);
});
