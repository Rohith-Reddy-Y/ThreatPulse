'use strict';
// Test-only shim: a Router that just records route definitions.
function Router() {
  const routes = [];
  const r = { routes };
  for (const m of ['get', 'post', 'put', 'delete', 'patch', 'use']) {
    r[m] = (path, ...handlers) => { routes.push({ method: m.toUpperCase(), path, handlers }); return r; };
  }
  return r;
}
function express() { return { use() {}, get() {}, set() {}, listen() {} }; }
express.Router = Router;
express.json = () => (req, res, next) => next();
express.static = () => (req, res, next) => next();
module.exports = express;
