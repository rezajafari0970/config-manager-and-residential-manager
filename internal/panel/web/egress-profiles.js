import {esc,fa} from './core.js';
const names={'doubleclick.v1':'DoubleClick','ads-serving.v1':'Google Ads Serving'};
export function profileSummary(x){
 if(!x)return '';
 return ' · '+fa.format(x.complete_tested_ads||0)+' با جداسازی تمام مقصدهای Ads آزمایش‌شده · '+fa.format(x.partial_tested_ads||0)+' با جداسازی پروفایل مشخص';
}
export function profileDetails(d){
 if(!d?.qualified_profiles?.length)return '';
 const coverage=d.ads_coverage==='ALL_TESTED'?'همهٔ مقصدهای Ads آزمایش‌شده جدا بودند':'پوشش جزئی Ads؛ مقصدهای دیگر ممکن است مشترک یا نامشخص باشند';
 return `<p>جدایی مسیر تأییدشده برای ${esc(d.qualified_profiles.map(x=>names[x]||x).join('، '))}</p><p class="hint">${esc(coverage)}</p><p class="hint">مقصدهای تأییدشده: <span dir="ltr">${esc((d.qualified_domains||[]).join(' · '))}</span></p>`;
}

const networkReasons = {
 ads_network_evidence_incomplete: 'انتساب نوع شبکهٔ بعضی مبدأهای Ads ناقص یا منقضی است.',
 ads_network_coverage_incomplete: 'پوشش هر شش مقصد در خام و قالب کامل نشده است.',
 ads_network_route_unqualified: 'جدایی مسیر یا دریافت فایل آزمایشی هر دو گروه تأیید نشده است.',
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
 if (blocked) {
  summary = observation.state === 'mixed' ? 'خروج ترکیبی دیتاسنتر و شبکهٔ دسترسی در آزمون Ads' : 'خروج دیتاسنتری در آزمون Ads';
 } else if (entry.residential_eligible) {
  summary = 'شبکهٔ دسترسی ثابت یا همراه و مسیر جداگانهٔ Ads تأیید شده‌اند.';
 } else {
  summary = networkReasons[latest.detail] || networkReasons[latest.reason] || (latest.state === 'access' ? 'اعتبار جاری مسیر یا شبکه برای انتشار باید تمدید شود.' : 'نوع شبکهٔ خروجی Ads هنوز تأیید نشده است.');
 }
 const variant = {raw:'خام',template:'قالب'}[observation.variant];
 const families = observation.family ? [observation.family] : observation.families || [];
 const provider = observation.provider || (observation.providers || []).join('، ');
 const observed = [observation.domain, variant, families.map(f=>'IPv'+f).join('، '), provider, observation.asn && 'AS'+observation.asn].filter(Boolean).map(v=>`<bdi>${esc(v)}</bdi>`).join(' · ');
 let publication = 'در خروجی رزیدنتال نیست';
 if (entry.published) publication = 'منتشرشده در خروجی رزیدنتال';
 else if (entry.residential_eligible) publication = 'منتظر احراز کشور یا خارج از انتخاب کشور';
 if (blocked && entry.network_clean_rounds === 1) publication += ' · یک بررسی کامل از دو بررسی لازم برای رفع توقف ثبت شد';
 return `<p>${esc(summary)}${observed ? ' · '+observed : ''}</p><p class="hint">${esc(publication)}</p>`;
}
