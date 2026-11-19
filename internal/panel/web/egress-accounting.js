import {$,fa} from './core.js';
export function renderAccounting(a){
 if(!a)return;
 const p=a.publication,q=a.queue,n=v=>fa.format(v);
 $('#egress-progress').textContent=n(p.eligible)+' رزیدنتال واجد شرایط پیش از فیلتر کشور · '+n(p.published)+' کانفیگ یکتا در خروجی · '+n(p.awaiting_proof)+' در انتظار تمدید تأیید مسیر';
 if(p.awaiting_proof>0&&a.renewal){const r=a.renewal;$('#egress-progress').textContent+=' — '+n(r.due)+' آمادهٔ تمدید، '+n(r.running)+' در حال آزمون، '+n(r.scheduled)+' با زمان تلاش بعدی، '+n(r.paused)+' متوقف و '+n(r.cached)+' خارج از صف فعال. این موارد برای انتشار دوباره به تأیید معتبر مسیر و سلامت نیاز دارند.';}
 const c=a.current_assessment;
 $('#egress-inventory').textContent='از '+n(a.current_identities)+' کانفیگ یکتای لینک‌های فعلی، '+n(c.tested)+' بررسی شده، '+n(c.awaiting)+' در انتظار نتیجه، '+n(c.excluded)+' مشمول حذف و '+n(c.missing)+' بدون رکورد بررسی است.';
 if(c.interrupted) $('#egress-inventory').textContent+=' از موارد منتظر، '+n(c.interrupted)+' مورد پس از بازیابی پردازشگر قابل ادامه است.';
 if(c.exhausted) $('#egress-inventory').textContent+=' برای '+n(c.exhausted)+' مورد، فرصت بازیابی خودکار تمام شده است. با فعال‌سازی دوبارهٔ همان ورودی می‌توانید بررسی نیمه‌تمام را از سر بگیرید.';
 $('#egress-queue').textContent='صف بررسی اولیه و نگهداری · '+n(q.running)+' در حال بررسی · '+n(q.due)+' آماده · '+n(q.scheduled)+' زمان‌بندی‌شده · '+n(q.cached)+' خارج از صف · '+n(q.paused)+' متوقف';
 $('#egress-network-counts').textContent='از '+n(p.route_verified)+' کانفیگ با مسیر جدا و سلامت معتبر، '+n(p.hosting)+' مورد به دلیل خروج دیتاسنتری و '+n(p.mixed)+' مورد به دلیل خروج ترکیبی از رزیدنتال کنار گذاشته شده‌اند. از موارد واجد شرایط، برای '+n(p.eligible_network_unattributed)+' مورد نوع شبکهٔ مسیر جدا مشخص نشده است.';
 if (p.network_unverified) $('#egress-network-counts').textContent+=' برای '+n(p.network_unverified)+' مورد با مسیر و سلامت معتبر، انتساب شبکه هنوز تعیین تکلیف نشده است.';
 const review=a.safety_review;
 if(review && (review.iran || review.country_conflict || review.network || review.network_review || review.route_or_health_loss)) {
  $('#egress-network-counts').textContent+=' از موارد بدون تأیید مسیر جاری، '+n(review.iran)+' مورد در قرنطینهٔ ایران، '+n(review.country_conflict)+' مورد دارای شواهد متناقض دربارهٔ خروجی ایران، '+n(review.network)+' مورد دارای منع شبکهٔ دیتاسنتری یا ترکیبی، '+n(review.network_review||0)+' مورد با انتساب شبکهٔ تأییدنشده و '+n(review.route_or_health_loss)+' مورد در انتظار بررسی مجددِ از دست رفتن مسیر یا سلامت‌اند. هر مورد یک‌بار و جدا از صف تمدید رزیدنتال شمرده می‌شود.';
 }
 if (p.eligible_with_shared_hosting) $('#egress-network-counts').textContent+=' در '+n(p.eligible_with_shared_hosting)+' کانفیگ واجد شرایط، مبدأ یکی از اتصال‌های Ads با خروج دیتاسنتری مسیر عادی مشترک بوده است.';
 $('#egress-output-counts').textContent=n(p.published)+' خام سالم = '+n(p.template_count??p.published)+' قالب آزموده = '+n(p.identities)+' هویت ورودی یکتا · '+n(p.country_filtered)+' خارج از انتخاب کشور · '+n(p.country_unknown)+' در انتظار تعیین معتبر کشور';
}
