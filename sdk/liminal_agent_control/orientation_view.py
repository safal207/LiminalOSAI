"""Self-contained, read-only graph viewer for the owned orientation example."""
from __future__ import annotations

import json


def render(report: dict) -> str:
    payload = json.dumps(report, ensure_ascii=False, allow_nan=False).replace("<", "\\u003c")
    return _PAGE.replace("__REPORT_JSON__", payload)


_PAGE = '''<!doctype html>
<html lang="ru"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Центр ориентации · траектории агентов</title>
<style>
:root{color-scheme:dark;font-family:system-ui,sans-serif;background:#101923;color:#e5edf3}
*{box-sizing:border-box}body{margin:0}main{max-width:1180px;margin:auto;padding:36px 24px}
header{max-width:850px}h1{font-size:clamp(28px,4vw,44px);line-height:1.1;margin:12px 0}h2{font-size:18px;margin:0 0 16px}
p{color:#b2c4d2;line-height:1.65}.eyebrow{color:#73ddd0;letter-spacing:.13em;font-size:12px;font-weight:700}
.grid{display:grid;grid-template-columns:minmax(0,1.5fr) minmax(280px,1fr);gap:18px;margin-top:24px}
.card{background:#162330;border:1px solid #2c4152;border-radius:14px;padding:22px;min-width:0}
.wide{grid-column:1/-1}.controls{display:flex;gap:14px;align-items:center}input{flex:1;min-width:80px;accent-color:#73ddd0}
button{border:1px solid #587182;background:#233746;color:#eef6fb;padding:10px 15px;border-radius:8px;cursor:pointer}
button:focus-visible,input:focus-visible{outline:3px solid #f4cd73;outline-offset:4px}button:disabled{opacity:.35;cursor:default}
#graph{width:100%;height:auto}svg text{font-family:system-ui,sans-serif}.muted{font-size:13px;color:#a2b7c7}.position{border-top:1px solid #304552;padding:14px 0}
.position strong{display:block;margin-bottom:7px}.pill{display:inline-block;padding:4px 8px;border-radius:5px;background:#233746;font-size:12px;margin:4px 5px 4px 0}
.hold{color:#f4cd73}.ok{color:#73ddd0}#frameLabel{font-size:18px;line-height:1.5;margin:16px 0 4px}#time{font-variant-numeric:tabular-nums}
.tablewrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:13px}th,td{text-align:left;padding:10px 8px;border-bottom:1px solid #304552;white-space:nowrap}
th{color:#a2b7c7;font-weight:500}.facts{display:grid;grid-template-columns:repeat(3,1fr);gap:14px}.facts b{display:block;font-size:22px;margin-bottom:7px}
.check{padding:7px 0;color:#b2c4d2}.check:before{content:'✓ ';color:#73ddd0}.failed:before{content:'× ';color:#f19b98}
footer{margin-top:22px;font-size:12px;word-break:break-word;color:#91a9bb}@media(max-width:760px){main{padding:24px 14px}.grid{grid-template-columns:1fr}.card{padding:16px}.facts{grid-template-columns:1fr 1fr}.controls{gap:8px}}
</style>
<main><header><div class="eyebrow">LIMINAL · НАБЛЮДАЕМЫЙ КОНТРОЛЬ</div>
<h1>Куда движется агент —<br>и чем это подтверждено</h1>
<p>Центр ориентации — заданная оператором область подтверждённых состояний.
Общая цель не объединяет полномочия агентов. Прогресс не отменяет границы.</p></header>
<section class="grid"><div class="card wide"><h2>Траектория во времени</h2>
<div class="controls"><button id="prev" aria-label="Предыдущий момент">←</button>
<input id="step" type="range" min="0" value="0" aria-label="Момент истории">
<button id="next" aria-label="Следующий момент">→</button><span id="counter"></span></div>
<div id="frameLabel"></div><div id="time" class="muted"></div></div>
<div class="card"><h2>Пространство допустимых переходов</h2>
<svg id="graph" viewBox="0 0 640 340" role="img" aria-label="Граф допустимых состояний и текущие позиции агентов"></svg>
<p class="muted">Зоны обозначают ресурсы и этапы работы. Расстояние на рисунке условное.
Пунктир — ожидающий подтверждения переход; цветная точка — последняя наблюдаемая позиция.</p></div>
<div class="card"><h2>Отдельная позиция каждого агента</h2><div id="positions"></div></div>
<div class="card wide"><div class="facts"><div><b id="session"></b><span class="muted">Состояние полномочий</span></div>
<div><b id="budget"></b><span class="muted">Действий из общего лимита</span></div>
<div><b id="pending"></b><span class="muted">Переходов ждут наблюдения</span></div></div></div>
<div class="card wide"><h2>История переходов к выбранному моменту</h2><div class="tablewrap"><table>
<thead><tr><th>Агент</th><th>Версия</th><th>Откуда → куда</th><th>Наблюдение</th><th>Действие</th></tr></thead>
<tbody id="history"></tbody></table></div></div>
<div class="card wide"><h2>Проверки выполненного примера</h2><div id="checks"></div>
<p class="muted">Это собственный сценарий с SQLite и локальным получателем, без вызовов модели и внешней сети.
Ответ транспорта не доказывает внешний эффект. Граф не выдаёт разрешения и не измеряет сознание или внутренние намерения.</p></div></section>
<footer id="source"></footer></main><script id="report" type="application/json">__REPORT_JSON__</script>
<script>
'use strict';
const report=JSON.parse(document.getElementById('report').textContent);
const $=id=>document.getElementById(id), slider=$('step'); slider.max=report.frames.length-1;
const ns='http://www.w3.org/2000/svg', colors=['#73ddd0','#f4cd73','#adbbfa'];
const labels={center:'Центр ориентации',record:'Запись наблюдалась',network:'Получатель подтверждён'};
const coordinates={}; const nodes=report.profile.nodes;
nodes.forEach((n,i)=>coordinates[n.node_id]=i===0?[180,170]:[480,80+(i-1)*180]);
function svg(tag,attrs,text){const el=document.createElementNS(ns,tag); for(const[k,v]of Object.entries(attrs))el.setAttribute(k,v);if(text!==undefined)el.textContent=text;return el;}
function row(parent,tag,text,cls){const el=document.createElement(tag);el.textContent=text;if(cls)el.className=cls;parent.append(el);return el;}
function draw(){const frame=report.frames[+slider.value], state=frame.graph, graph=$('graph');graph.replaceChildren();
const defs=svg('defs',{}), marker=svg('marker',{id:'arrow',viewBox:'0 0 10 10',refX:9,refY:5,markerWidth:5,markerHeight:5,orient:'auto-start-reverse'});marker.append(svg('path',{d:'M0 0 L10 5 L0 10 Z',fill:'#617b8e'}));defs.append(marker);graph.append(defs);
for(const edge of report.profile.edges){const a=coordinates[edge.source],b=coordinates[edge.destination],dx=b[0]-a[0],dy=b[1]-a[1],len=Math.hypot(dx,dy)||1;graph.append(svg('line',{x1:a[0]+dx/len*58,y1:a[1]+dy/len*58,x2:b[0]-dx/len*62,y2:b[1]-dy/len*62,stroke:'#435d70','stroke-width':1.5,'marker-end':'url(#arrow)'}));}
for(const n of nodes){const[x,y]=coordinates[n.node_id],center=report.profile.center_nodes.includes(n.node_id);graph.append(svg('circle',{cx:x,cy:y,r:55,fill:center?'#143a3e':'#213344',stroke:center?'#73ddd0':'#617b8e','stroke-width':center?2:1}));graph.append(svg('text',{x,y:y+4,'text-anchor':'middle',fill:'#e5edf3','font-size':12},labels[n.node_id]||n.node_id));graph.append(svg('text',{x,y:y+76,'text-anchor':'middle',fill:'#a2b7c7','font-size':11},n.space_id));}
$('positions').replaceChildren();
state.executions.forEach((agent,i)=>{const color=colors[i%colors.length],[x,y]=coordinates[agent.node_id];graph.append(svg('circle',{cx:x-16+i*32,cy:y-43,r:8,fill:color,stroke:'#101923','stroke-width':2}));
const box=document.createElement('div');box.className='position';row(box,'strong',agent.execution_id).style.color=color;row(box,'div',(labels[agent.node_id]||agent.node_id)+' · версия '+agent.revision,'muted');row(box,'span','шаги '+agent.steps,'pill');row(box,'span','шаги удаления '+agent.away_steps,'pill');
if(agent.pending_action_id){row(box,'div','Ожидается наблюдение: '+agent.pending_action_id,'hold muted');const edge=state.occurrences.find(e=>e.action_id===agent.pending_action_id);if(edge){const a=coordinates[edge.source],b=coordinates[edge.destination];graph.append(svg('path',{d:`M${a[0]} ${a[1]-60} Q320 0 ${b[0]} ${b[1]-60}`,fill:'none',stroke:color,'stroke-width':2,'stroke-dasharray':'6 5'}));}}
if(agent.hold_reason)row(box,'div',agent.hold_reason,'hold muted');const hint=frame.guidance[agent.execution_id];row(box,'div',({HOLD:'Пауза: требуется проверка',RETURN_CANDIDATE:'Следующий ориентир: вернуться к центру',TRANSITION_CANDIDATE:'Есть кандидат на следующий переход'})[hint.disposition],'muted');$('positions').append(box);});
$('history').replaceChildren();for(const e of state.occurrences){const tr=document.createElement('tr');for(const value of[e.execution_id,e.revision,e.source+' → '+e.destination,e.status,e.action_id])row(tr,'td',String(value));$('history').append(tr);}
if(!state.occurrences.length){const tr=document.createElement('tr');const td=row(tr,'td','Переходов пока нет. Начальные состояния установлены оператором.');td.colSpan=5;$('history').append(tr);}
$('counter').textContent=(+slider.value+1)+' / '+report.frames.length;$('frameLabel').textContent=frame.label;$('time').textContent='t + '+frame.elapsed_seconds.toFixed(3)+' с · время этого запуска, не SLA';
$('session').textContent=frame.authority.status;$('budget').textContent=frame.authority.action_count+' / '+frame.authority.max_actions;$('pending').textContent=state.executions.filter(e=>e.pending_action_id).length;
$('prev').disabled=+slider.value===0;$('next').disabled=+slider.value===report.frames.length-1;}
slider.addEventListener('input',draw);$('prev').onclick=()=>{slider.value=+slider.value-1;draw()};$('next').onclick=()=>{slider.value=+slider.value+1;draw()};
for(const[k,v]of Object.entries(report.checks))row($('checks'),'div',k,'check'+(v?'':' failed'));
$('source').textContent='Source '+report.source.commit+' · tree '+report.source.tree+' · dirty='+report.source.dirty+' · graph '+report.profile_digest;draw();
</script></html>'''
