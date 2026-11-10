// PatchLabs API helper, shared by every page that calls the API.
//   api('/checks', { method: 'POST', body: {...} })        -> parsed JSON, or throws Error(friendly sentence)
//   api('/me', { auth: true })                               -> sends Authorization: Bearer <session> (also sent by default when a session exists)
//   session.get() / session.set(token) / session.clear()     -> the "pl_session" token in localStorage
// Errors from the API are {"detail": "human sentence"}; that sentence becomes err.message. err.status holds the HTTP status.
var API = (location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:8001' : 'https://api.patchlabs.dev';

var session = {
  key: 'pl_session',
  get: function () { try { return localStorage.getItem(this.key) || ''; } catch (e) { return ''; } },
  set: function (t) { try { localStorage.setItem(this.key, t); } catch (e) {} },
  clear: function () { try { localStorage.removeItem(this.key); } catch (e) {} }
};

async function api(path, opts) {
  opts = opts || {};
  var headers = {};
  if (opts.body !== undefined) headers['Content-Type'] = 'application/json';
  var tok = session.get();
  if (tok && opts.auth !== false) headers['Authorization'] = 'Bearer ' + tok;
  if (opts.auth === true && !tok) {
    var na = new Error('Please sign in to continue.'); na.status = 401; throw na;
  }
  if (opts.headers) for (var h in opts.headers) headers[h] = opts.headers[h];
  var r;
  try {
    r = await fetch(API + path, {
      method: opts.method || 'GET',
      headers: headers,
      body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined
    });
  } catch (e) {
    var ne = new Error('We couldn’t reach PatchLabs. Check your connection and try again.'); ne.status = 0; throw ne;
  }
  if (opts.raw) return r;
  var data = r.status === 204 ? {} : await r.json().catch(function () { return {}; });
  if (!r.ok) {
    var d = data.detail;
    // FastAPI answers a route the deployed API doesn't have yet with a bare "Not Found" / "Method Not Allowed".
    // Our own 404s carry a sentence ("Check not found."), so only the bare framework text is replaced.
    var missing = (r.status === 404 && (d === 'Not Found' || d === undefined)) || (r.status === 405 && d === 'Method Not Allowed');
    var msg = missing ? 'This feature isn’t available yet. Try again shortly.'
      : d === 'not found' ? 'We couldn’t find that. Check the link is complete and try again.'  // e.g. an unknown check id
      : typeof d === 'string' ? d
      : Array.isArray(d) ? 'Check the repo and email, then try again.'
      : r.status === 401 ? 'Your session has ended. Please sign in again.'
      : r.status === 429 ? 'Too many requests. Wait a minute and try again.'
      : 'Something went wrong. Try again.';
    if (r.status === 401 && tok) session.clear();
    var err = new Error(msg); err.status = r.status; err.data = data; throw err;
  }
  return data;
}
