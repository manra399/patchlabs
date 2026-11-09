// Shared by every PatchLabs page: where the API lives and how to call it.
var API = (location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:8001' : 'https://api.patchlabs.dev';

async function api(path, opts) {
  opts = opts || {};
  var r;
  try {
    r = await fetch(API + path, {
      method: opts.method || 'GET',
      headers: opts.body ? { 'Content-Type': 'application/json' } : {},
      body: opts.body ? JSON.stringify(opts.body) : undefined
    });
  } catch (e) {
    throw new Error('We couldn’t reach PatchLabs. Check your connection and try again.');
  }
  var data = await r.json().catch(function () { return {}; });
  if (!r.ok) {
    var d = data.detail;
    throw new Error(typeof d === 'string' ? d : (Array.isArray(d) ? 'Check the repo and email, then try again.' : 'Something went wrong. Try again.'));
  }
  return data;
}
