import {$,fa} from './core.js';
export function renderAccounting(a){
 if(!a)return;
 const p=a.publication,q=a.queue,n=v=>fa.format(v);
 $('#egress-progress').textContent=n(p.eligible)+' رزیدنتال با مسیر و شبکهٔ دسترسی تأییدشده · '+n(p.published)+' کانفیگ یکتا در خروجی · '+n(p.awaiting_proof)+' در انتظار تمدید تأیید مسیر';
 if(p.awaiting_proof>0&&a.renewal){const r=a.renewal;$('#egress-progress').textContent+=' — '+n(r.due)+' آمادهٔ تمدید، '+n(r.running)+' در حال آزمون، '+n(r.scheduled)+' با زمان تلاش بعدی، '+n(r.paused)+' متوقف و '+n(r.cached)+' خارج از صف فعال. تأیید قبلی این موارد منقضی یا آزمون تازه ناقص شده است؛ انتشار به تأیید شبکهٔ دسترسی و کشور نیز وابسته است.';}
 $('#egress-inventory').textContent=n(a.current_identities)+' کانفیگ یکتای منابع فعلی · '+n(a.retained_outside_current)+' کانفیگ دارای سابقهٔ مسیر جدا، خارج از منابع فعلی؛ هر هویت فقط یک نمایندهٔ آزمون دارد.';
 $('#egress-queue').textContent=n(a.assessed_versions)+' کانفیگ یکتا با نتیجهٔ بررسی جاری · '+n(a.awaiting_first)+' در انتظار بررسی با معیار فعلی · '+n(q.running)+' در حال بررسی · '+n(q.due)+' آماده · '+n(q.scheduled)+' پیگیری زمان‌بندی‌شده · '+n(q.cached)+' نتیجهٔ ذخیره‌شده بدون تکرار · '+n(q.paused)+' متوقف';
 $('#egress-network-counts').textContent='از '+n(p.route_verified)+' کانفیگ با مسیر جدا و سلامت معتبر، '+n(p.hosting)+' مورد به دلیل خروج دیتاسنتری و '+n(p.mixed)+' مورد به دلیل خروج ترکیبی از رزیدنتال کنار گذاشته شده‌اند. برای '+n(p.network_unverified)+' مورد دیگر، شواهد شبکه یا پوشش دامنه‌ها کامل نیست.';
 $('#egress-output-counts').textContent=n(p.published)+' خام سالم = '+n(p.template_count??p.published)+' قالب آزموده = '+n(p.identities)+' هویت ورودی یکتا · '+n(p.country_filtered)+' خارج از انتخاب کشور · '+n(p.country_unknown)+' در انتظار تعیین معتبر کشور';
}
