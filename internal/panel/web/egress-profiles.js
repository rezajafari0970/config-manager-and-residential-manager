import {esc,fa} from './core.js';
const names={'doubleclick.v1':'DoubleClick','ads-serving.v1':'Google Ads Serving'};
export function profileSummary(x){
 if(!x)return '';
 return ' در آزمون مسیر، '+fa.format(x.complete_tested_ads||0)+' کانفیگ همهٔ مقصدهای آزموده‌شده و '+fa.format(x.partial_tested_ads||0)+' کانفیگ بخشی از آن‌ها را در یک پروفایل کامل جدا کردند.';
}
export function profileDetails(d){
 if(!d?.qualified_profiles?.length)return '';
 const coverage=d.ads_coverage==='ALL_TESTED'?'همهٔ مقصدهای Ads آزمایش‌شده جدا بودند':'پوشش جزئی Ads؛ مقصدهای دیگر ممکن است مشترک یا نامشخص باشند';
 const profiles=d.qualified_profiles.map(x=>names[x]||x).join('، ');
 const scope=d.ads_coverage==='PARTIAL' && d.qualified_profiles.length===1 ? 'فقط '+profiles : profiles;
 return `<p>پروفایل دارای مسیر جداگانهٔ تأییدشده · ${esc(scope)}</p><p class="hint">${esc(coverage)}</p><p class="hint">مقصدهای تأییدشده: <span dir="ltr">${esc((d.qualified_domains||[]).join(' · '))}</span></p>`;
}

const networkReasons = {
 ads_hosting_route_unresolved: 'مالک شبکهٔ یکی از مبدأها مشخص است. شواهد برای انتساب آن به مسیر جداگانهٔ Ads کافی نیست.',
 ads_network_evidence_incomplete: 'نوع شبکهٔ بعضی مبدأهای مشاهده‌شدهٔ Ads نامعلوم است.',
 ads_network_coverage_incomplete: 'شواهد انتساب شبکه برای پروفایل آزموده‌شده کامل نیست.',
 ads_network_route_unqualified: 'جدایی مسیر یا دریافت فایل آزمایشی برای پروفایل آزموده‌شده تأیید نشده است.',
 ads_network_receipt_unbound: 'شاهد شبکه به این نسخهٔ آزموده متصل نیست.',
 network_snapshot_unavailable: 'فهرست شبکه‌ها در دسترس آزمون‌گر نیست.',
 network_snapshot_invalid: 'نسخهٔ فهرست شبکه‌ها قابل اعتبارسنجی نیست.',
 network_origin_expired: 'دادهٔ مبدأ مسیریابی منقضی شده است.',
 network_origin_unavailable: 'مبدأ مسیریابی بازه احراز نشد.',
 network_origin_conflict: 'داده‌های مبدأ مسیریابی با انتساب بازه سازگار نیستند.',
 network_usage_unverified: 'کاربری این بازه به‌عنوان میزبانی یا شبکهٔ مشترکین احراز نشد.',
 network_usage_conflict: 'داده‌های کاربری این بازه با هم تعارض دارند.',
 network_usage_expired: 'دادهٔ کاربری بازه منقضی شده است.',
 network_source_invalid: 'مبدأ قابل‌استناد برای این اتصال موجود نیست.',
};
export function networkDetails(entry) {
 const latest = entry.network || {};
 const blocked = entry.network_held;
 const observation = blocked ? entry.last_adverse || {} : latest;
 let summary;
 if (entry.network_review === 'pending') {
  summary = 'نتیجهٔ قدیمی دیتاسنتری در انتظار بازبینی مسیر است.';
 } else if (entry.network_review === 'inconclusive') {
  summary = 'بازبینی انجام شد. شواهد کافی برای انتساب دیتاسنتر به مسیر جدا ثبت نشد.';
 } else if (blocked) {
  summary = observation.state === 'mixed' ? 'خروج ترکیبی دیتاسنتر و شبکهٔ دسترسی در مسیر تبلیغات' : 'خروج دیتاسنتری در مسیر تبلیغات';
 } else if (latest.state === 'access') {
  summary = 'در آخرین آزمون، مبدأ اتصال‌های پروفایل دارای مسیر جدا به شبکهٔ دسترسی منتسب شد.';
 } else {
  summary = networkReasons[latest.detail] || networkReasons[latest.reason] || 'نوع شبکهٔ خروجی Ads مشخص نشده است.';
 }
 const variant = {raw:'خام',template:'قالب'}[observation.variant];
 const families = observation.family ? [observation.family] : observation.families || [];
 const provider = observation.provider || (observation.providers || []).join('، ');
 const observed = [observation.domain, variant, families.map(f=>'IPv'+f).join('، '), provider, observation.asn && 'AS'+observation.asn].filter(Boolean).map(v=>`<bdi>${esc(v)}</bdi>`).join(' · ');
 let publication = 'در خروجی رزیدنتال نیست';
 if (entry.published) publication = 'منتشرشده در خروجی رزیدنتال';
 else if (entry.residential_eligible) publication = 'منتظر احراز کشور یا خارج از انتخاب کشور';
 if (blocked && entry.network_clean_rounds === 1) publication += ' · یک بررسی کامل از دو بررسی لازم برای رفع توقف ثبت شد';
 function flowDetails(flows,label) {
  const groups=new Map();
  for (const flow of flows || []) {
   const variant={raw:'خام',template:'قالب'}[flow.variant] || flow.variant;
   const key=[flow.provider,flow.asn && 'AS'+flow.asn,variant,'IPv'+flow.family].filter(Boolean).join(' · ');
   if (!groups.has(key)) groups.set(key,new Set());
   groups.get(key).add(flow.domain);
  }
  return [...groups].map(([key,domains])=>
   `<p class="hint">${esc(label)} · <bdi>${esc(key)}</bdi> · ${[...domains].sort().map(d=>`<bdi>${esc(d)}</bdi>`).join('، ')}</p>`
  ).join('');
 }
 const ordinary = flowDetails(latest.shared_hosting,'خروج دیتاسنتری مشترک با ترافیک عادی');
 const unresolved = flowDetails(latest.unresolved_hosting,'مبدأ دیتاسنتری با مسیر تأییدنشده');
 return `<p>${esc(summary)}${observed ? ' · '+observed : ''}</p>${ordinary}${unresolved}<p class="hint">${esc(publication)}</p>`;
}
