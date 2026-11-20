import {$, api, esc, fa, toast} from './core.js';

const links = {'side-all': 'configs.json', 'side-next': 'next.json', 'side-raw': 'raw.txt'};

const services = {google:'گوگل',facebook:'فیسبوک',instagram:'اینستاگرام',twitter:'توییتر (X)',telegram:'تلگرام',
 cloudflare:'کلودفلر',warp:'WARP',upload:'آپلود',download:'دانلود',stability:'پایداری'};
const outcomes = {
 passed:'موفق', not_run:'اجرا نشد', unrecorded:'بدون اندازه‌گیری ثبت‌شده', warp_not_active:'WARP خاموش بود',
 provider_unavailable:'سرویس موقتاً در دسترس نبود', side_provider_unavailable:'سرویس موقتاً در دسترس نبود',
 side_driver_unavailable:'درایور آزمون در دسترس نبود', timeout:'مهلت آزمون تمام شد', connection_timeout:'مهلت اتصال تمام شد',
 transport_failed:'اتصال برقرار نشد', unverified_connection:'اتصال قابل تأیید نبود', unexpected_http_status:'کد پاسخ غیرمنتظره',
 unexpected_content:'محتوای مورد انتظار دریافت نشد', incomplete_response:'پاسخ ناقص بود', incomplete_upload:'آپلود ناقص بود',
 side_checks_failed:'یک یا چند شرط برقرار نبود', side_raw_unverified:'اجرای نسخهٔ خام قابل تأیید نبود', probe_infrastructure_error:'آزمون به‌دلیل خطای زیرساخت نتیجه نداد',
 worker_lease_exhausted:'عامل آزمون پیش از ثبت نتیجه متوقف شد', probe_job_timeout:'مهلت اجرا به پایان رسید',
 no_verified_profile:'قالب یا اتصال قابل تأیید نبود', unsupported_protocol:'پروتکل پشتیبانی نشد',
 original_blob_unavailable:'ورودی ذخیره‌شده در دسترس نبود', input_unavailable:'ورودی در دسترس نبود',
 client_core_incompatible:'ناسازگاری هسته', client_core_validation_timeout:'مهلت بررسی هسته تمام شد',
 endpoint_dns_failed:'حل نام مقصد انجام نشد', sandbox_preflight_failed:'محیط آزمون آماده نشد',
 reality_authentication_rejected:'احراز هویت REALITY رد شد'
};
const reviewForms = {raw:'نسخهٔ خام',template:'قالب',both:'خام و قالب'};
const reviewStates = {accepted:'تأییدشده',rejected:'ردشده',inconclusive:'نامشخص'};
const reviewedAt = new Intl.DateTimeFormat('fa-IR', {month:'2-digit',day:'2-digit',hour:'2-digit',minute:'2-digit'});

function reviewHistory() {
 const details = $('#side-reviews'), host = $('#side-review-list');
 let updated = 0, busy = false, signature = '';
 async function refresh() {
  if (!details.open || busy || Date.now() - updated < 15000) return;
  busy = true;
  try {
   const reviews = await api('/api/side/reviews');
   const next = JSON.stringify(reviews);
   if (next !== signature) {
    const open = new Set([...host.querySelectorAll('details[open]')].map(row => row.dataset.review));
    host.innerHTML = reviews.length ? reviews.map(v => {
     const results = Object.entries(services).map(([key, name]) =>
      '<div><span>'+name+'</span><strong>'+esc(outcomes[v.checks[key]] || outcomes.unrecorded)+'</strong></div>').join('');
     return '<details data-review="'+esc(v.id)+'"'+(open.has(v.id)?' open':'')+'><summary><bdi>'+esc(v.id)+'</bdi> · '+
      esc(reviewStates[v.state])+' · '+esc(reviewForms[v.form] || 'قالب')+' · '+esc(reviewedAt.format(v.finished))+'</summary><p class="hint">'+
      esc(outcomes[v.reason] || outcomes.no_verified_profile)+'</p><div class="source-data">'+results+'</div></details>';
    }).join('') : '<p class="hint">هنوز نتیجه‌ای ثبت نشده است.</p>';
    signature = next;
   }
   updated = Date.now();
  } catch {
   host.textContent = 'دریافت نتایج ممکن نشد. تلاش بعدی خودکار است.';
   signature = '';
  } finally { busy = false; }
 }
 details.addEventListener('toggle',refresh);
 return refresh;
}

export function sideOutput() {
 const host = $('#side-output');
 const status = $('#side-counts');
 host.hidden = false;
 status.textContent = 'در حال دریافت وضعیت آزمون‌های Side…';
 host.addEventListener('click', async event => {
  const button = event.target.closest('[data-side-copy]');
  if (!button) return;
  const anchor = document.getElementById(button.dataset.sideCopy);
  try {
   await navigator.clipboard.writeText(anchor.href);
   toast('لینک Side کپی شد.');
  } catch {
   toast('برای کپی، لینک را انتخاب کنید.');
  }
 });

 // This summary changes independently of the paginated ordinary output.
 const refreshReviews = reviewHistory();
 let lastUpdate = 0;
 return async function refreshSide() {
  void refreshReviews();
  if (Date.now() - lastUpdate < 10000) return;
  try {
   const result = await api('/api/side');
   const c = result.counts;
   const summary = [
    [c.accepted, 'در خروجی خام'], [c.template, 'دارای قالب Xray'], [c.pending, 'در صف'], [c.running, 'در حال آزمون'],
    [c.rejected, 'ردشده'], [c.inconclusive, 'با نتیجهٔ نامشخص'], [c.expired, 'منقضی']
   ].map(([count, label]) => fa.format(count) + ' ' + label).join(' · ');
   const wait = c.oldest_pending > 0 ? ' · بیشترین انتظار ' + fa.format(Math.max(0, Math.floor((Date.now() - c.oldest_pending) / 60000))) + ' دقیقه' : '';
   if (status.textContent !== summary + wait) status.textContent = summary + wait;
   for (const [id, file] of Object.entries(links)) {
    const anchor = document.getElementById(id);
    if (anchor.textContent === result.links[file]) continue;
    anchor.href = result.links[file];
    anchor.textContent = result.links[file];
    host.querySelector('[data-side-copy="' + id + '"]').disabled = false;
   }
   lastUpdate = Date.now();
  } catch {
   status.textContent = 'دریافت وضعیت Side ممکن نشد. تلاش بعدی خودکار است.';
   return false;
  }
 };
}
