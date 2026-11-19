import {$,fa} from './core.js';
export function renderAccounting(a){
 if(!a)return;
 const p=a.publication,q=a.queue,n=v=>fa.format(v);
 $('#egress-progress').textContent=n(p.eligible)+' رزیدنتال واجد شرایط پیش از فیلتر کشور · '+n(p.published)+' کانفیگ یکتا در خروجی · '+n(p.awaiting_proof)+' در انتظار تمدید تأیید مسیر';
 if(p.awaiting_proof>0&&a.renewal){const r=a.renewal;$('#egress-progress').textContent+=' — '+n(r.due)+' آمادهٔ تمدید، '+n(r.running)+' در حال آزمون، '+n(r.scheduled)+' با زمان تلاش بعدی، '+n(r.paused)+' متوقف و '+n(r.cached)+' خارج از صف فعال. این موارد برای انتشار دوباره به تأیید معتبر مسیر و سلامت نیاز دارند.';}
 $('#egress-inventory').textContent=n(a.current_identities)+' کانفیگ یکتای منابع فعلی · '+n(a.retained_outside_current)+' کانفیگ دارای سابقهٔ مسیر جدا، خارج از منابع فعلی؛ هر هویت فقط یک نمایندهٔ آزمون دارد.';
 $('#egress-queue').textContent=n(a.assessed_versions)+' کانفیگ یکتا با نتیجهٔ بررسی جاری · '+n(a.awaiting_first)+' در انتظار بررسی با معیار فعلی · '+n(q.running)+' در حال بررسی · '+n(q.due)+' آماده · '+n(q.scheduled)+' پیگیری زمان‌بندی‌شده · '+n(q.cached)+' نتیجهٔ ذخیره‌شده بدون تکرار · '+n(q.paused)+' متوقف';
 $('#egress-network-counts').textContent='از '+n(p.route_verified)+' کانفیگ با مسیر جدا و سلامت معتبر، '+n(p.hosting)+' مورد به دلیل خروج دیتاسنتری و '+n(p.mixed)+' مورد به دلیل خروج ترکیبی از رزیدنتال کنار گذاشته شده‌اند. از موارد واجد شرایط، برای '+n(p.eligible_network_unattributed)+' مورد نوع شبکهٔ مسیر جدا مشخص نشده است.';
 if (p.eligible_with_shared_hosting) $('#egress-network-counts').textContent+=' در '+n(p.eligible_with_shared_hosting)+' کانفیگ واجد شرایط، مقصدی خارج از پروفایل تأییدشده از مسیر عادی و دیتاسنتری گذشته است.';
 $('#egress-output-counts').textContent=n(p.published)+' خام سالم = '+n(p.template_count??p.published)+' قالب آزموده = '+n(p.identities)+' هویت ورودی یکتا · '+n(p.country_filtered)+' خارج از انتخاب کشور · '+n(p.country_unknown)+' در انتظار تعیین معتبر کشور';
}
