"""Read-only timeline of actual center/observer evidence from the owned demo."""
from __future__ import annotations

import json


def render(report: dict) -> str:
    data = json.dumps(report, ensure_ascii=False, allow_nan=False).replace("<", "\\u003c")
    return _PAGE.replace("__REPORT__", data)


_PAGE = '''<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Центр во времени · кольцо наблюдателей</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101923;color:#e5edf3}*{box-sizing:border-box}
body{margin:0}main{max-width:1160px;margin:auto;padding:36px 24px}header{max-width:900px}
h1{font-size:clamp(28px,4vw,44px);line-height:1.12;margin:14px 0}h2{font-size:18px;margin:0 0 16px}
p{color:#b2c4d2;line-height:1.65}.eyebrow{color:#73ddd0;letter-spacing:.12em;font-size:12px;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px;margin-top:22px}.wide{grid-column:1/-1}
.card{min-width:0;background:#162330;border:1px solid #2c4152;border-radius:14px;padding:22px}
.controls{display:flex;gap:12px;align-items:center}input{flex:1;min-width:60px;accent-color:#73ddd0}
button{border:1px solid #587182;background:#233746;color:#eef6fb;padding:10px 15px;border-radius:8px;cursor:pointer}
button:disabled{opacity:.35;cursor:default}button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #f4cd73;outline-offset:4px}
.muted{font-size:13px;color:#a2b7c7}.value{font-size:23px;font-weight:650;margin:7px 0;overflow-wrap:anywhere}
.label{font-size:13px;color:#b2c4d2}.windows{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px;margin-top:18px}
.window{padding:14px;background:#213344;border:1px solid #435d70;border-radius:9px;overflow-wrap:anywhere}
.current{border-color:#73ddd0;background:#143a3e}.facts{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
#frameLabel{font-size:18px;line-height:1.5;margin:15px 0 5px}#orbit{width:100%;height:auto;display:block}
.line{border-top:1px solid #304552;padding:13px 0;overflow-wrap:anywhere}.line:first-child{border-top:0}
.warning{color:#f4cd73}.digest{font-family:ui-monospace,monospace;font-size:12px;overflow-wrap:anywhere}
.tablewrap{overflow:auto}table{width:100%;border-collapse:collapse;font-size:13px}td,th{text-align:left;padding:10px 8px;border-bottom:1px solid #304552;white-space:nowrap}th{color:#a2b7c7;font-weight:500}
summary{cursor:pointer;color:#73ddd0}.check{padding:6px 0;overflow-wrap:anywhere}.check:before{content:'✓ ';color:#73ddd0}.failed:before{content:'× ';color:#f19b98}
footer{margin-top:22px;font-size:12px;color:#91a9bb;overflow-wrap:anywhere}
@media(max-width:760px){main{padding:24px 14px}.grid{grid-template-columns:1fr}.card{padding:16px}.facts{grid-template-columns:1fr}.controls{gap:8px}}
</style>
<main><header><div class="eyebrow">LIMINAL · ЦЕНТР И НЕПРЕРЫВНОСТЬ</div>
<h1>Сохранить связь<br>между прошлым и следующим шагом</h1>
<p>Центр имеет собственную траекторию во времени. Наблюдатели проверяют факты, историю и прогноз.
Идея остаётся идеей, пока получатель не подтвердит результат действия.</p></header>
<section class="grid"><div class="card wide"><h2>Временная шкала</h2>
<div class="controls"><button id="prev" aria-label="Предыдущий момент">←</button><input id="step" type="range" min="0" value="0" aria-label="Момент истории"><button id="next" aria-label="Следующий момент">→</button><span id="counter"></span></div>
<div id="frameLabel"></div><div id="time" class="muted"></div><div id="windows" class="windows"></div></div>
<div class="card"><h2>Кольцо наблюдателей</h2><svg id="orbit" viewBox="0 0 440 400" role="img" aria-label="Три роли наблюдателей вокруг текущего центра"></svg>
<div id="ringVerdict" class="digest warning"></div><p class="muted">Согласие относится к выбранному точному прогнозу. Оно не выдаёт разрешение на действие.
Кольцо изображает роли проверки, а не физическую орбиту или сознание.</p></div>
<div class="card"><h2>Реальное положение и ориентир</h2>
<div class="line"><div class="label">Действующий центр</div><div id="activeCenter" class="value"></div></div>
<div class="line"><div class="label">Подтверждённое положение агента</div><div id="actualPosition" class="value"></div><div id="revision" class="muted"></div></div>
<div class="line"><div class="label">Проверка отклонения и застоя</div><div id="diagnosis" class="digest warning"></div></div>
<div class="line"><div class="label">Связь с прошлым</div><div id="head" class="digest"></div></div></div>
<div class="card wide"><div class="facts"><div><div class="label">Полномочия</div><div id="authority" class="value"></div></div><div><div class="label">Подтверждённых записей</div><div id="effects" class="value"></div></div><div><div class="label">Действий из общего лимита</div><div id="budget" class="value"></div></div></div></div>
<div class="card"><h2>Прошлое и настоящее</h2><div id="past"></div><p class="muted">История растёт. Смена центра не переносит агента и не удаляет старые отклонения.</p></div>
<div class="card"><h2>Идеи и возможное будущее</h2><div id="future"></div><p class="muted">У прогноза есть предшественник, центр и срок. Истёкший прогноз не становится фактом.</p></div>
<div class="card wide"><h2>Цепочка наблюдаемых событий</h2><div class="tablewrap"><table><thead><tr><th>№</th><th>Событие</th><th>Время записи</th><th>Центр</th><th>Предшественник</th></tr></thead><tbody id="events"></tbody></table></div></div>
<div class="card wide"><details><summary id="checkSummary"></summary><div id="checks"></div></details><p class="muted">Пример выполняет настоящие записи в собственную SQLite-базу с управляемыми часами.
Наблюдатели здесь — тестовые роли доверенного приложения. Независимость реальных служб требует отдельной проверки.</p></div></section><footer id="source"></footer></main>
<script id="report" type="application/json">__REPORT__</script><script>
'use strict';const report=JSON.parse(document.getElementById('report').textContent),$=id=>document.getElementById(id),slider=$('step');slider.max=report.frames.length-1;
const ns='http://www.w3.org/2000/svg',roleNames={reality:'Факты',continuity:'История',projection:'Прогноз'};
function row(parent,text,cls='line'){const el=document.createElement('div');el.className=cls;el.textContent=text;parent.append(el);return el;}
function shape(tag,attrs,text){const el=document.createElementNS(ns,tag);for(const[k,v]of Object.entries(attrs))el.setAttribute(k,v);if(text!==undefined)el.textContent=text;return el;}
function draw(){const f=report.frames[+slider.value],c=f.continuity,g=f.graph,r=f.ring,s=c.states[0],a=g.executions[0];
const active=(c.centers||[]).find(w=>w.starts_at<=f.now&&f.now<w.ends_at),projections=[...c.projections].sort((x,y)=>x.created_at-y.created_at||x.action_id.localeCompare(y.action_id));
const p=projections.find(x=>x.action_id===f.focus_action_id)||projections.at(-1),coverage=(r.coverage||[]).find(x=>x.action_id===p?.action_id),supported=new Set(coverage?.supported_roles||[]);
$('counter').textContent=(+slider.value+1)+' / '+report.frames.length;$('frameLabel').textContent=f.label;$('time').textContent='t = '+f.now+' с · управляемое время сценария';
$('windows').replaceChildren();for(const w of c.centers||[]){const box=row($('windows'),w.center_id+' · '+w.starts_at+' ≤ t < '+w.ends_at,'window'+(w===active?' current':''));row(box,w.center_nodes.join(', '),'muted');}
$('activeCenter').textContent=active?.center_id||'Нет действующего окна';$('actualPosition').textContent=a?.node_id||'Нет наблюдения';$('revision').textContent='Версия '+(a?.revision??'—')+' · наблюдение t = '+(s?.last_observed_at??'—');
$('diagnosis').textContent=s?.diagnosis||'HOLD';$('head').textContent=s?.head_hash||'Цепочка не начата';$('authority').textContent=f.authority.status;$('effects').textContent=f.record_count;$('budget').textContent=f.authority.action_count+' / '+f.authority.max_actions;
const orbit=$('orbit');orbit.replaceChildren();orbit.append(shape('ellipse',{cx:220,cy:200,rx:162,ry:145,fill:'none',stroke:'#435d70','stroke-width':2,'stroke-dasharray':'5 6'}));
orbit.append(shape('circle',{cx:220,cy:200,r:57,fill:'#143a3e',stroke:'#73ddd0','stroke-width':2}));orbit.append(shape('text',{x:220,y:195,'text-anchor':'middle',fill:'#e5edf3','font-size':15},'Центр'));orbit.append(shape('text',{x:220,y:218,'text-anchor':'middle',fill:'#73ddd0','font-size':14},active?.center_id||'закрыт'));
['reality','continuity','projection'].forEach((role,i)=>{const[x,y]=[[220,55],[72,300],[365,300]][i],ok=supported.has(role);orbit.append(shape('circle',{cx:x,cy:y,r:47,fill:'#213344',stroke:ok?'#73ddd0':'#6d7e8a','stroke-width':2}));orbit.append(shape('text',{x,y:y+5,'text-anchor':'middle',fill:'#e5edf3','font-size':17},roleNames[role]));orbit.append(shape('text',{x,y:y+67,'text-anchor':'middle',fill:ok?'#73ddd0':'#b2c4d2','font-size':14},ok?'есть проверка':'нет опоры'));});
$('ringVerdict').textContent=coverage?.reason||(p?'Роли согласованы; остальные проверки обязательны':'Ожидается точный прогноз');
$('past').replaceChildren();row($('past'),'Событий в цепочке: '+c.events.length);row($('past'),'Последний подтверждённый прогресс: t = '+(s?.last_progress_at??'—'));row($('past'),'Начало отклонения: '+(s?.away_since??'не зафиксировано'));
$('future').replaceChildren();row($('future'),'Идей: '+c.ideas.length+' · прогнозов: '+c.projections.length);if(p){row($('future'),p.action_id+' · центр '+p.center_id);row($('future'),'Окно: '+p.not_before+' ≤ t < '+p.deadline);row($('future'),'Прогноз: '+p.status+' · полномочия: не выдаются');}
$('events').replaceChildren();for(const e of c.events){const tr=document.createElement('tr');for(const v of[e.sequence,e.kind,e.recorded_at,e.center_id,e.parent_hash.slice(0,12)]){const td=document.createElement('td');td.textContent=String(v);tr.append(td);}$('events').append(tr);}
$('prev').disabled=+slider.value===0;$('next').disabled=+slider.value===report.frames.length-1;}
slider.addEventListener('input',draw);$('prev').onclick=()=>{slider.value=+slider.value-1;draw()};$('next').onclick=()=>{slider.value=+slider.value+1;draw()};
for(const[k,v]of Object.entries(report.checks))row($('checks'),k.replaceAll('_',' '),'check'+(v?'':' failed'));
$('checkSummary').textContent='Проверки примера: '+Object.values(report.checks).filter(Boolean).length+' / '+Object.keys(report.checks).length;
$('source').textContent='Source '+report.source.commit+' · tree '+report.source.tree+' · dirty='+report.source.dirty;draw();
</script></html>'''
