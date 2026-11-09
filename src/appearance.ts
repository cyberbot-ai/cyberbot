export type ThemeMode = 'light' | 'dark' | 'auto';
export interface Appearance { mode: ThemeMode; nightStart: string; nightEnd: string }
export const appearanceKey = 'cyberbot.appearance.v1';
export const defaultAppearance: Appearance = {mode:'auto',nightStart:'20:00',nightEnd:'07:00'};
const validTime = (v: unknown): v is string => typeof v==='string' && /^([01]\d|2[0-3]):[0-5]\d$/.test(v);
export function readAppearance(): Appearance {
  try {
    const v=JSON.parse(localStorage.getItem(appearanceKey)??'null');
    if(v && ['light','dark','auto'].includes(v.mode) && validTime(v.nightStart) && validTime(v.nightEnd) && v.nightStart!==v.nightEnd) return {mode:v.mode,nightStart:v.nightStart,nightEnd:v.nightEnd};
  } catch { /* Unavailable or corrupted local preferences use the default. */ }
  return {...defaultAppearance};
}
export function effectiveTheme(p: Appearance, date: Date): 'dark' | 'light' {
  if(p.mode!=='auto') return p.mode;
  const minutes=(s:string)=>Number(s.slice(0,2))*60+Number(s.slice(3));
  const start=minutes(p.nightStart),end=minutes(p.nightEnd),now=date.getHours()*60+date.getMinutes();
  const night=start>end ? now>=start||now<end : now>=start&&now<end;
  return night?'dark':'light';
}
export function saveAppearance(p: Appearance): boolean {
  if(!validTime(p.nightStart)||!validTime(p.nightEnd)||p.nightStart===p.nightEnd) return false;
  try {localStorage.setItem(appearanceKey,JSON.stringify(p));return true;} catch {return false;}
}
