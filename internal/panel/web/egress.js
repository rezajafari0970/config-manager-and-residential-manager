import {$,api,esc,fa,toast} from './core.js';
import {countryFilter} from './egress-countries.js';
import {egressEvidence} from './egress-evidence.js';
import {renderAccounting} from './egress-accounting.js';
import {profileSummary,profileDetails,networkDetails} from './egress-profiles.js';
import {healthSettings} from './egress-health.js';
import {rescanSummary} from './egress-rescan.js';
function sourceCoverage(){
 const panel=$('#egress-source-coverage'), status=$('#egress-source-coverage-status'), rows=$('#egress-source-coverage-rows');
 const prev=$('#egress-source-prev'), next=$('#egress-source-next');
 let offset=0, pageSize=50, busy=false, nextRefresh=0;
 function row(label,c){
  return '<tr><th scope="row">'+esc(label)+'</th>'+[c.residential,c.published,c.current_unique,c.registered,c.current_tested,c.awaiting,c.excluded,c.missing_job,c.withdrawn_awaiting_first].map(v=>'<td>'+fa.format(v)+'</td>').join('')+'</tr>';
 }
 async function refresh(force=false){
  if(!panel.open || busy || (!force && performance.now()<nextRefresh))return;
  busy=true;
  prev.disabled=true;next.disabled=true;
  try{
   const data=await api('/api/egress/source-coverage?offset='+offset);
   pageSize=data.page_size;
   if(offset>0 && !data.sources.length && offset>=data.enabled_sources){
    offset=Math.max(0,Math.floor((data.enabled_sources-1)/pageSize)*pageSize);
    nextRefresh=0;
    return;
   }
   rows.innerHTML=row('مجموع یکتای همهٔ منابع فعال',data.global)+data.sources.map(s=>row((s.name||'منبع')+' · '+s.id.slice(0,8),s)).join('');
   status.textContent=fa.format(data.enabled_sources)+' منبع فعال · '+new Date(data.as_of_ms).toLocaleTimeString('fa-IR')+(data.sources.length?' · ردیف '+fa.format(offset+1)+' تا '+fa.format(offset+data.sources.length):'');
   const outside=data.outside_active_sources;
   if(outside.residential)status.textContent+=' · خارج از ورودی فعلی منابع فعال، '+fa.format(outside.residential)+' رزیدنتال نگهداری می‌شود که '+fa.format(outside.published)+' مورد آن منتشر شده است.';
   prev.disabled=offset===0;
   next.disabled=offset+data.sources.length>=data.enabled_sources;
   nextRefresh=performance.now()+30000;
  }catch{
   status.textContent='دریافت پوشش منابع ناموفق بود. تلاش مجدد خودکار انجام می‌شود.';
   nextRefresh=performance.now()+10000;
  }finally{busy=false}
 }
 panel.addEventListener('toggle',()=>{if(panel.open)refresh(true)});
 if(location.hash==='#egress-source-coverage')panel.open=true;
 prev.onclick=()=>{offset=Math.max(0,offset-pageSize);refresh(true)};
 next.onclick=()=>{offset+=pageSize;refresh(true)};
 return refresh;
}
export default function Egress(){
 const evidence=egressEvidence($('#egress-list'));
 const refreshSources=sourceCoverage();
 const health=healthSettings(()=>refresh());
 const countries=countryFilter(()=>{offset=0;refresh()});
 let offset=0,busy=false,state=null;
 const names={'ADS_SPLIT':'جدایی مسیر Ads در آخرین آزمون','NO_SPLIT':'خروجی مشترک Ads و کنترل','PENDING':'در صف','RESIDENTIAL':'رزیدنتال با مسیر جداگانهٔ Ads','NON_RESIDENTIAL':'غیررزیدنتال','UNKNOWN':'نامشخص','QUARANTINED':'در انتظار تأیید دوباره','UNSUPPORTED':'درایور سازگار در دسترس نیست'};
 const reasons={'ambiguous_vmess_transport_security':'در لینک VMess به‌جای وضعیت TLS نامِ رمز ثبت شده است. بررسی ورودی کامل شد؛ مسیر شبکه قابل‌آزمون نیست.','probe_socks_contract_missing':'در پیکربندی Xray ورودی محلی SOCKS موردنیاز درایور پیدا نشد. آزمون شبکه اجرا نشد.','native_probe_listener_missing':'در پیکربندی sing-box ورودی محلی SOCKS موردنیاز درایور پیدا نشد. آزمون شبکه اجرا نشد.','nonloopback_listener_not_qualified':'پیکربندی ورودی خارج از آدرس محلی مجاز دارد. آزمون شبکه اجرا نشد.','listener_port_conflict':'درگاه‌های ورودی پیکربندی برای آزمون معتبر و یکتا نیستند. آزمون شبکه اجرا نشد.','initial_lease_recovery':'کارگر پیش از ثبت نتیجه متوقف شد. بررسی خودکار پس از مهلت بازیابی ادامه می‌یابد.','ads_hosting_route_unresolved':'مبدأ دیتاسنتری دیده شد. برای تعیین مسیر آن شواهد مقایسه کافی نیست.','ads_route_ineligible':'شرایط فعلی انتشار مسیر برقرار نیست','ads_hosting_exit':'خروج دیتاسنتری مشاهده شد','ads_mixed_exit':'خروج دیتاسنتری در کنار شبکهٔ دسترسی مشاهده شد','ads_proof_expired':'اعتبار شواهد مسیر پایان یافته است','ads_network_evidence_incomplete':'انتساب شبکهٔ برخی مبدأها ناقص است','ads_network_coverage_incomplete':'شواهد انتساب شبکه برای پروفایل آزموده‌شده کامل نیست','ads_network_route_unqualified':'شرط جدایی مسیر و تحویل محقق نشده است','ads_delivery_unproven':'مسیر جدا مشاهده شده اما دریافت فایل پایه تبلیغات در خام و قالب کامل تأیید نشده','ads_delivery_unhealthy':'فایل‌های پایه تبلیغات در هر دو نسخه دریافت نشدند؛ شاهد مستقل سالم است؛ تأیید حذف در حال انجام','unified_epoch':'دور تازهٔ بررسی با سیاست واحد مسیر و سلامت Ads','verified_ads_profile':'جداسازی یک پروفایل کامل Ads در نسخهٔ خام و قالب تأیید شد','all_tested_ads_share_control':'تمام مقصدهای Ads آزمایش‌شده در خام و قالب خروجی مشترک داشتند','ads_profile_evidence_incomplete':'شواهد برای تأیید یک پروفایل کامل Ads کافی نیست؛ نتیجه منفی قطعی نیست','variant_binding_invalid':'درایور نسخه‌های مستقل خام و قالب را درست مشخص نکرده است','repeated_ads_split_observation':'شش مقصد Ads با کنترل‌های پایدار و هم‌خانواده در دو نوبت متفاوت بودند؛ محدودیت مسیر تلگرام/اینستاگرام را در شواهد ببینید','paired_control_coverage_incomplete':'برای بعضی مقصدهای Ads دو مقایسهٔ هم‌نوبت و هم‌خانواده با گوگل و یک کنترل مستقل کامل نیست','unique_epoch':'اولین بررسی در دورهٔ جدید کانفیگ‌های یکتا','full_rescan':'دور تازهٔ بازآزمایی؛ شواهد قبلی معتبر نیست','implementation_changed':'معیار تشخیص تغییر کرده؛ شواهد قبلی آرشیوی است و بررسی تازه لازم است','non_ads_uses_ads_egress':'یکی از سرویس‌های دیگر از خروجی مشاهده‌شدهٔ Ads استفاده می‌کند','repeated_ads_exclusive_observation':'همهٔ مقصدهای الزامی در خام و قالب بررسی شدند؛ Ads جداست','payload_health_unknown':'تبادل کامل درخواست و پاسخ Ads هنوز تأیید نشده','ads_iran_quarantined':'ایران مشاهده شده؛ قرنطینهٔ همه خروجی‌ها و بررسی دوباره','confirmed_ads_iran':'ایران در دو نوبت مستقل تأیید شد؛ حذف و مسدودی دریافت دوباره','input_unavailable':'دادهٔ ورودی موقتاً قابل خواندن نیست؛ حفظ شده برای بازیابی','local_resource_pressure':'فشار منابع آزمایشگر؛ نیازمند آزمون دوباره','manual_recheck':'آزمون مجدد در اولویت','direct_route_not_qualified':'قانون خروج مستقیم خارج از محدودهٔ آزمون','direct_default_not_qualified':'مسیر پیش‌فرض مستقیم است','core_evidence_missing':'درایور پیش از تکمیل آزمون متوقف شد؛ جزئیات تلاش‌ها را ببینید','core_rejected':'هسته ساختار خام را نپذیرفت','core_schema_mismatch':'ساختار خام با هسته سازگار نیست','removed_allow_insecure':'خام حاوی گزینهٔ TLS حذف‌شده است','missing_runtime_asset':'فایل مورد نیاز هسته در محیط آزمون موجود نیست','endpoint_dns_failed':'نام سرور ورودی resolve نشد','route_not_distinct':'خروجی اختصاصی Ads تأیید نشد','network_retry_pending':'آزمون سریع بی‌پاسخ؛ در صف بررسی عمیق','new_input':'ورودی تازه','controls_incomplete':'پاسخ کنترل کافی نیست','ads_peer_echo_incomplete':'مقایسهٔ تکرارشوندهٔ Ads هنوز کافی نیست','multiple_or_unresolved_paths':'مسیرهای داخلی متعدد یا نامشخص','core_or_variant_failed':'یکی از نسخه‌های خام یا قالب در آزمون هسته موفق نبود','repeated_ads_split_project_definition':'خروجی Ads در آزمون‌های تکراری از کنترل جدا بود؛ طبق معیار سابق جدایی مسیر','mixed_route_observations':'رفتار ترکیبی؛ خروجی Ads گاهی مشترک و گاهی متفاوت بود'};
 const titles={'configs.json':'همه با قالب · اشتراک JSON','configs.jsonl':'همه با قالب · JSONL','next.json':'تک‌کانفیگ چرخشی','raw.txt':'همه به‌صورت خام'};
 async function refresh(){if(busy)return;busy=true;try{
  state=await api('/api/egress?brief=1&offset='+offset+($('#egress-diagnostics').checked?'&view=diagnostics':''));
  countries.update(state.country);health.update(state);
  const run=state.rescan;
  $('#egress-rescan-status').textContent=rescanSummary(run);
  const guard=state.iran_guard; $('#egress-iran-guard').textContent='محافظ ایران: '+fa.format(guard.quarantined_identities)+' هویت قرنطینه · '+fa.format(guard.blocked_identities)+' هویت مسدود پایدار · '+fa.format(guard.overdue_retained)+' کانفیگ نگهداری‌شده با بررسی عقب‌افتاده از ۱۰ دقیقه';
  renderAccounting(state.accounting);
  $('#egress-network-counts').textContent+=profileSummary(state.profile_stats);
  const t=state.throughput,n=v=>fa.format(v);
  $('#egress-worker').textContent=(state.now-state.worker.heartbeat<20000?'پردازشگر فعال':'پردازشگر در دسترس نیست')+' · '+n(state.now-state.worker.heartbeat<20000?state.worker.active:0)+' بررسی هم‌زمان · در ۵ دقیقهٔ اخیر '+n(t.unique_definitive_5m)+' کانفیگ یکتا با نتیجهٔ قطعی از هدف '+n(t.target_5m)+' · '+n(t.first_settled_5m)+' اولین نتیجهٔ قطعی، '+n(t.previously_settled_5m)+' دارای نتیجهٔ قطعی قبلی'+(t.settlement_unknown_5m?'، '+n(t.settlement_unknown_5m)+' با سابقهٔ نامعلوم':'')+' · '+n(t.completed_5m)+' آزمون تکمیل‌شده. در ۱۰ دقیقهٔ اخیر '+n(t.unique_definitive_10m)+' کانفیگ یکتا نتیجهٔ قطعی داشته‌اند.';
  $('#egress-metrics').textContent='آمار دورهٔ جدید از '+new Date(state.metrics.since).toLocaleString('fa-IR')+': '+fa.format(state.metrics.completed)+' بررسی ثبت‌شده · '+fa.format(state.metrics.first_assessments)+' اولین بررسی · '+fa.format(state.metrics.lease_recoveries)+' بازیابی کار نیمه‌تمام · '+fa.format(state.metrics.registered)+' ورودی تازه';
  $('#egress-links').innerHTML=Object.entries(state.links).map(([f,u])=>`<div class="subscription-box"><label>${esc(titles[f])}</label><div class="sub-link"><a dir="ltr" href="${esc(u)}">${esc(u)}</a><button class="secondary" data-copy="${esc(f)}">کپی لینک</button></div></div>`).join('');
  const rejected=state.datacenter_rejections, link=$('#egress-dc-rejected-link');
  $('#egress-dc-rejected-count').textContent=n(rejected.count)+' کانفیگ با خروج دیتاسنتری تأییدشده';
  const review=[];
  if(rejected.review_pending)review.push(n(rejected.review_pending)+' مورد در انتظار بازبینی شواهد');
  if(rejected.review_inconclusive)review.push(n(rejected.review_inconclusive)+' مورد با شواهد ناکافی پس از بازبینی');
  $('#egress-dc-review').textContent=review.join(' · ');
  link.href=rejected.raw_url;link.textContent=rejected.raw_url;
  $('#egress-dc-rejected-copy').disabled=false;
  const open=evidence.capture();
  $('#egress-list').innerHTML=state.entries.map(x=>`<article class="config-card"><strong>${esc(names[x.state]||x.state)}</strong>${networkDetails(x)}${profileDetails(x.decision)}<p>${esc((x.sources||[]).join(" · "))}</p><p>${esc(reasons[x.reason]||x.reason)}</p><p>کشورهای مسیر پروفایل تأییدشده: ${esc((x.countries||[]).map(countries.label).join("، ")||"نامشخص")}</p><p class="hint">${esc(x.kind)} · ${esc(x.format)} · ${(!x.tested?'شواهد قبلی؛ منتظر نتیجهٔ دور تازه':x.decision?.route==='DIFFERENT'?'خروجی Ads متفاوت مشاهده شد':x.decision?.route==='PARTIAL_DIFFERENCE'?'تفاوت در بخشی از نمونه‌ها؛ نیازمند بررسی عمیق':'مقایسه مسیر: '+esc(x.decision?.route||'نامشخص'))}</p><p class="hint">تبادل درخواست و پاسخ روی مسیر Ads: ${esc((x.health?.status==='healthy'&&!x.health?.fresh?'تأیید سلامت منقضی شده':({healthy:"تأییدشده",unhealthy:"خرابی مشاهده‌شده؛ تأیید دوباره",unknown:"نامشخص"})[x.health?.status]||"در انتظار آزمون"))}</p><p class="hint">دریافت فایل پایه تبلیغات: ${esc(({available:"تأییدشده",unavailable:"ناموفق با کنترل مستقل سالم",unknown:"تأییدنشده"})[x.decision?.delivery?.status]||"در انتظار آزمون")} · نمایش واقعی تبلیغ روی دستگاه: اندازه‌گیری نشده</p><details data-evidence="${esc(x.hash)}" data-tested="${x.tested}" data-revision="${x.revision}"><summary>شواهد مقایسهٔ مسیر</summary><pre dir="ltr">در حال دریافت شواهد…</pre></details></article>`).join('')||'<p class="empty">در این نمای نتایج، کانفیگی موجود نیست. نتایج ناقص در بخش نمایش همه ورودی‌ها دیده می‌شوند.</p>';
  evidence.restore(open);
 }catch(e){toast(e.message||'دریافت وضعیت ناموفق بود')}finally{busy=false}}
 $('#egress-diagnostics').onchange=()=>{offset=0;refresh()};$('#egress-prev').onclick=()=>{offset=Math.max(0,offset-50);refresh()};$('#egress-next').onclick=()=>{if(state?.entries.length===50){offset+=50;refresh()}};
 async function copyLink(url){try{await navigator.clipboard.writeText(url);toast('لینک کپی شد')}catch{toast('لینک را انتخاب و کپی کنید')}}
 $('#egress-links').onclick=e=>{const b=e.target.closest('[data-copy]');if(b&&state)copyLink(state.links[b.dataset.copy])};
 $('#egress-dc-rejected-copy').onclick=()=>{if(state)copyLink(state.datacenter_rejections.raw_url)};
 return {filters:()=>({}),render:()=>{},tasks:[refresh,refreshSources]};
}
