/*
 * ThreatPulse — 3D threat globe (pure WebGL, no libraries).
 *
 * Purely visual: it reads no app data and calls no API. Every
 * <canvas data-globe="auth|card"> on the page gets a dotted 3D Earth with an
 * atmosphere, glowing great-circle attack arcs, impact rings and (on the
 * sign-in screen) a starfield. Rendering pauses when the canvas is off-screen
 * or the tab is hidden, and is a single still frame with prefers-reduced-motion.
 */
(function () {
  'use strict';

  const DEG = Math.PI / 180;

  // ───────────────────────── Land mask (lon, lat) ─────────────────────────
  // Simplified coastlines — plenty for a dot globe.
  const LAND = [
    // North & Central America
    [[-168,66],[-162,70],[-156,71.3],[-141,69.6],[-128,70],[-115,68.5],[-95,72],[-85,69.5],[-80,63],[-94,59],[-92,57],[-82,55],[-78,52],[-79,58],[-77,62],[-70,60],[-64,60],[-61,56],[-56,52],[-60,48],[-66,45],[-70,43.5],[-70.5,41.5],[-74,40.5],[-76,38],[-75.5,35.5],[-78,33.8],[-81,31],[-80,27],[-80.5,25.2],[-82,26.5],[-83,29.5],[-85.5,30],[-89,30.2],[-94,29.5],[-97.5,27.5],[-97.5,22],[-96,19],[-94.5,18.2],[-91,18.8],[-90.5,21],[-87,21.5],[-88,16],[-84,15.5],[-83.5,11],[-81.5,9],[-79,9.5],[-77.5,8.5],[-80,7.3],[-82.5,8.2],[-85.8,10.5],[-87.5,13],[-91.5,14],[-94.5,16],[-97,15.8],[-101,17.5],[-105.5,20],[-105.8,22.5],[-109,25.5],[-112.5,29.5],[-114.8,31.5],[-112.5,27.5],[-110,23.2],[-112,24.5],[-114.5,28],[-117,32.5],[-120.5,34.5],[-122.5,37.5],[-124.2,40.5],[-124,46],[-124.7,48.4],[-123,49],[-128,51],[-130.5,54.5],[-135,57.5],[-140,59.7],[-147,60.8],[-152,59],[-157,57],[-162,55],[-158,58.5],[-162,59.8],[-165,61.5],[-166,64],[-168,66]],
    // Greenland & Arctic islands
    [[-73,78],[-60,82],[-35,83.5],[-20,82],[-18,76],[-22,70],[-30,68],[-40,65],[-43,60],[-48,61],[-52,65],[-54,69],[-58,75],[-68,76.5],[-73,78]],
    [[-80,73],[-68,70],[-62,66.5],[-66,62],[-73,64],[-78,70]],
    [[-95,76],[-80,76],[-62,82],[-90,83]],
    [[-118,72.5],[-102,73],[-100,69],[-115,68.5]],
    // South America
    [[-80,-1],[-81,-5],[-79,-8],[-76,-14],[-70.5,-18.5],[-70.3,-23],[-71.5,-30],[-71.6,-37],[-73.5,-42],[-74.5,-47],[-75.5,-52],[-72,-54],[-68.5,-55.2],[-66,-55],[-68.5,-52.5],[-69,-50.5],[-67.5,-47],[-65.5,-45],[-63.5,-42],[-62.2,-39],[-57.5,-38.2],[-56.8,-36.5],[-58.5,-34.3],[-53.5,-34],[-48.7,-28],[-48.5,-25.5],[-44.5,-23.2],[-41,-22],[-39,-17.5],[-38.7,-13],[-35,-9],[-34.8,-7],[-37,-4.7],[-41,-2.9],[-44,-2.4],[-48.5,-1],[-50,1.7],[-51.5,4.5],[-54,5.8],[-57,6],[-60.5,8.5],[-62,10.7],[-64.5,10.2],[-68,10.5],[-71.5,12.4],[-72,11.2],[-75.5,10.5],[-77,8.6],[-77.5,7],[-77.3,4],[-78.8,1.5],[-80,-1]],
    // Eurasia
    [[-9.5,43.2],[-8.9,38.5],[-8.8,37],[-6.2,36.4],[-5.4,36.1],[-2.2,36.7],[-0.5,38.3],[0.2,39.8],[3.2,41.9],[3.1,43.1],[4.8,43.4],[7.5,43.8],[8.8,44.4],[10.3,43.5],[11.2,42.4],[12.5,41.5],[14.2,40.8],[15.7,40],[15.9,38.6],[17.1,39],[17.1,40.5],[18.5,40.2],[16,41.6],[13.6,43.6],[12.3,45.3],[13.7,45.6],[14.5,45.2],[15.6,43.5],[17.5,42.9],[19.4,41.8],[19.4,40.3],[20.2,39.5],[21.1,38.3],[21.7,36.8],[22.6,36.4],[23.2,37.9],[24,38.2],[22.9,40.5],[24.4,40.9],[26.1,40.7],[26.4,40.2],[26.8,39],[27.3,37.9],[27.4,37],[28.3,36.7],[30.5,36.3],[32.5,36.1],[34.6,36.8],[36.1,36.7],[35.8,35.4],[35.9,34.4],[35.1,33],[34.5,31.5],[34.2,31.3],[34.9,29.5],[35.5,28],[36.6,25.9],[38.5,23.5],[39.2,21.5],[40.7,19],[42.6,16],[43.3,13],[45,12.8],[48.7,14],[52.2,15.6],[55.5,17.5],[57.8,19],[58.6,20.5],[59.8,22.5],[58.8,23.5],[56.4,24.9],[56.3,26.3],[55.5,25.5],[54,24.1],[51.6,24.2],[51.6,25.9],[50.8,24.8],[50,26.5],[48.5,28.5],[47.9,30],[49,30.3],[50.2,30],[51.4,27.9],[54.7,26.5],[57.3,25.8],[59.5,25.4],[61.6,25.2],[66.5,25.4],[67.5,23.9],[68.8,22.4],[70.5,21],[72.8,21.4],[72.8,19],[73.4,16],[74.6,12.8],[76,9.5],[77.5,8.1],[78.4,9],[79.3,10.3],[79.9,12.9],[80.3,15.9],[82.3,16.6],[84.8,19.2],[86.9,21.2],[88.7,21.6],[90.5,22.5],[91.8,22.3],[92.4,20.7],[94.3,18.2],[94.4,16],[97.5,16.7],[98.2,13.2],[98.7,10.4],[98.3,8],[100.3,5.7],[101.4,2.8],[103.5,1.3],[104.2,1.4],[103.5,4.2],[102.1,6.3],[100.4,7.4],[99.4,9.3],[99.2,10.9],[100,13.2],[100.9,12.7],[102.5,12.2],[103.3,10.6],[104.5,10.4],[105,8.6],[106.7,10.4],[109.2,11.6],[109.3,13.5],[108.3,16],[106.7,17.4],[105.8,19],[106.6,20.4],[108,21.5],[109.8,21.5],[110.5,20.4],[111,21.4],[113.5,22.2],[116.5,22.9],[118.5,24.6],[119.6,25.9],[120.5,27.3],[121.9,29.9],[121.3,31],[121.9,31.8],[120.3,34.4],[119.2,35],[120.7,36.4],[122.5,36.9],[121.2,37.8],[119,37.2],[118.5,38.4],[117.6,39],[119.5,39.9],[121.6,40.9],[121.3,39.4],[122.5,40.4],[124.3,39.9],[125.3,37.7],[126.6,37.2],[126.3,34.5],[127.5,34.6],[129.4,35.4],[129.5,36.8],[128.4,38.6],[127.5,39.8],[129.7,40.9],[129.7,42.4],[131,42.9],[133,42.8],[135.5,43.9],[138.2,46.4],[140.4,48.6],[141.4,52.2],[140.6,53.5],[137,54],[135.2,54.7],[137.7,56.4],[140.5,57.8],[143,59.3],[148,59.3],[152.3,59],[155,59.3],[156.7,61.5],[160.3,61.8],[159.6,60.6],[163.3,62.2],[164.5,62.5],[163,61],[161,59.8],[160.6,58.4],[156.5,56.8],[155.7,54.5],[156.7,51],[158.3,51.9],[160.1,54.3],[162,54.8],[162.1,56.1],[163.3,58],[165.8,59.8],[170.4,60],[172.4,61],[177.4,62.5],[179.2,62.3],[179.9,64.5],[177.4,64.6],[179.5,65.5],[180,68.9],[175.5,69.8],[170.6,70.1],[167.6,69.6],[161,69.4],[159.7,70.8],[152.5,70.8],[150,71.5],[141,72.7],[139,71.5],[131,71],[128.5,72.8],[129.7,73.3],[124,73.7],[113.5,73.5],[112,76.5],[107,77.4],[104,77.7],[98.5,76.4],[94,75.9],[88,75],[86.8,74],[80.5,73.6],[80.6,72.2],[78.4,72.4],[75.8,72.3],[75.5,68.5],[73,68.4],[72.8,72.2],[69.2,72.9],[66.9,71.3],[68.5,68.1],[64.5,69.5],[60.5,69.9],[60,68.5],[55,68.4],[53.5,68.1],[46.3,67.8],[44.2,66.3],[43.7,67.7],[41,66.3],[38.4,64.8],[36.5,64.8],[37.2,65.9],[33,66.7],[34.8,64.6],[36.2,66.9],[41,67.5],[41,68.9],[33.3,69.3],[29.4,69.7],[23.7,70.7],[18.2,69.8],[15.2,68.5],[12.6,65.9],[10.5,64.5],[8.5,63.4],[5.8,62.4],[5,61],[5.3,59.5],[6,58.1],[7.5,58],[8.4,58.3],[10.4,59.4],[11.1,58.9],[12.4,56.1],[12.9,55.4],[14.4,55.6],[14.3,56.2],[16.4,56.6],[16.5,58.5],[18.7,60],[17.3,61.6],[19,63.5],[21.4,64.4],[21.2,65],[22.2,65.8],[25.4,65.1],[24.7,64.2],[21.4,62.5],[21.3,60.9],[23,59.8],[26.6,60.4],[28.3,59.7],[30.3,59.9],[28,59.4],[24.1,58.6],[23.4,58.3],[24.3,57.2],[21.3,57],[21,56],[21.1,55.2],[19.6,54.4],[18.6,54.8],[16.3,54.4],[14.3,53.9],[11.4,54.2],[10.9,54.5],[10.4,55.5],[10.6,57.7],[8.6,57.1],[8.1,56],[8.6,55],[8.8,54],[8.3,53.4],[6.9,53.5],[5,53.3],[4.2,52],[3.1,51.3],[1.6,50.9],[1.3,50],[0.2,49.7],[-1.1,49.4],[-1.4,48.6],[-3,48.8],[-4.7,48.4],[-4.1,47.7],[-2.4,47.2],[-1.2,46],[-1.4,44.3],[-1.9,43.4],[-4,43.4],[-7.5,43.7],[-9.5,43.2]],
    // Africa
    [[-17,21],[-16.5,24],[-14.5,26.2],[-13,27.8],[-10,29.5],[-9.7,31],[-8.5,33.3],[-6.8,34],[-5.9,35.8],[-2.2,35.1],[1,36.5],[3.5,36.8],[8.6,36.9],[10.3,37.2],[11,36.8],[10.3,35.6],[11.1,35.2],[10.1,34],[11.5,33.1],[15.2,32.3],[15.7,31.4],[19,30.3],[20.1,31.2],[20,32.1],[21.7,32.9],[25,31.9],[29,30.9],[31,31.6],[32.6,31.1],[32.6,29.9],[33.9,27.4],[35,24.9],[36.9,22],[37.4,18.6],[38.6,17.7],[39.5,15.5],[41.2,14.4],[43.3,12.5],[44.5,10.4],[47.5,11.2],[51.2,11.8],[51,10.6],[50.6,9],[48.5,5],[46.5,2.5],[43.5,-0.8],[41.5,-1.8],[39.6,-4.4],[38.8,-6.5],[39.5,-8],[40.5,-10.5],[40.5,-15],[37,-17.5],[35,-20],[35.5,-22.5],[33,-25.5],[32.8,-28.6],[30.9,-30.4],[28,-33],[25.6,-34],[22.5,-34],[20,-34.8],[18.4,-34],[18,-32],[16.5,-28.6],[15.2,-27],[14.4,-22.9],[13.2,-20],[11.8,-17],[12.2,-14],[13.8,-10.8],[13,-8.5],[12.2,-6],[11.8,-4],[9.4,-0.9],[9.6,1.5],[9.8,3.2],[8.5,4.5],[5.9,4.3],[4.5,6.3],[1.5,6.1],[-2,4.8],[-4.6,5.2],[-7.5,4.3],[-9.3,5.4],[-11.5,6.9],[-13.2,8.7],[-15,10.9],[-16.7,12.3],[-17.1,14.4],[-16.5,16.2],[-16.1,18.5],[-17,21]],
    [[49.2,-12],[50.5,-15.5],[49.8,-17],[48.6,-20.5],[47.2,-25],[45.2,-25.5],[43.6,-23.5],[43.3,-21.5],[44.4,-19.5],[44,-17],[46.3,-15.7],[48,-13.5],[49.2,-12]],
    // Islands of Europe
    [[-5.7,50],[-3,50.6],[1.4,51.2],[1.7,52.7],[0.2,53.6],[-1.6,55.6],[-2,57],[-1.8,57.6],[-3.1,58.6],[-5.1,58.6],[-6.2,57.3],[-5.6,55.4],[-4.9,54.7],[-3.2,54],[-3,53.3],[-4.7,52.8],[-4,51.6],[-5.7,50]],
    [[-6,52.2],[-6.2,53.9],[-5.6,54.7],[-7.3,55.4],[-8.5,54.5],[-10,54.2],[-9.6,53],[-10.4,52],[-9.5,51.6],[-8,51.8],[-6,52.2]],
    [[-22.5,64],[-24,65.5],[-22,66.4],[-18,66.2],[-14.5,66.2],[-13.6,65],[-15,64.3],[-18.7,63.4],[-22.5,64]],
    [[11,78.5],[16,80],[27,80.2],[22,78],[16,76.5],[11,78.5]],
    [[52,71.5],[56,73.5],[60,76.2],[68,76.8],[64,74.5],[57,71],[52,71.5]],
    // East & South-East Asia islands
    [[130,31.2],[131.5,31.4],[132,33.5],[134.5,33.6],[135.5,33.5],[136.9,34.3],[138.8,34.6],[140,35],[140.9,36.9],[141,38.3],[142,39.5],[141.4,41.4],[140,40.7],[139.8,39],[138.6,37.8],[137.2,36.8],[136,35.7],[133,35.5],[131,34.4],[129.7,33.2],[130,31.2]],
    [[140,41.5],[141.2,41.8],[143.3,42],[145.6,43.3],[144.8,44.1],[141.9,45.5],[141.3,43.4],[140,42.6],[140,41.5]],
    [[142,46],[143.5,46.5],[143,49.3],[144.3,49],[143.2,52.5],[142.8,54.3],[142.3,53.6],[141.8,51.6],[142.1,48.6],[142,46]],
    [[120.1,23],[121,21.9],[121.9,24.6],[121.5,25.3],[120.7,24.6],[120.1,23]],
    [[120,16],[120.6,18.5],[122.2,18.5],[122.5,17],[121.6,15.6],[124,13],[122.6,13.3],[120.6,14.2],[120,16]],
    [[122,7.5],[123.5,8.6],[125.5,9.8],[126.5,8],[126.2,6.3],[125.4,5.6],[124,6.5],[122,7.5]],
    [[109,1.5],[109.6,-0.8],[110.3,-3],[114.5,-4],[116.2,-3.9],[116.5,-1.5],[118.9,0.9],[117.8,1.8],[119,5],[117.2,6.9],[115.5,5],[113,3.1],[111.4,2.5],[109.6,2],[109,1.5]],
    [[95.3,5.6],[97.5,5.2],[100.3,2.3],[103.7,-1],[106,-3.1],[105.8,-5.8],[104.5,-5.9],[102.3,-4],[100.9,-2.2],[98.7,1.6],[95.3,5.6]],
    [[105.2,-6.8],[106,-5.9],[108.5,-6.6],[111,-6.4],[112.6,-6.9],[114.6,-7.7],[114.4,-8.7],[111,-8.2],[108,-7.8],[106.4,-7.4],[105.2,-6.8]],
    [[119.4,-5.5],[120.5,-5.6],[120.9,-3.5],[121.5,-4.8],[123.2,-5.4],[122,-3],[121,-1.4],[123.3,-0.9],[125,1.5],[124.4,0.4],[120.9,1.3],[120,0.5],[119.5,-1],[118.8,-3],[119.4,-5.5]],
    [[131,-1.4],[133.8,-0.7],[135,-3.3],[137.8,-1.5],[141,-2.6],[145.7,-4.8],[147.5,-6.1],[147.2,-7.4],[150.8,-10.2],[148,-10.1],[146,-8.1],[144,-7.8],[143.3,-9],[141,-9.1],[139,-8.1],[137.9,-5.4],[135.2,-4.4],[132.7,-4],[131.8,-2.8],[131,-1.4]],
    [[79.8,9.8],[81.9,7.5],[81.2,6.2],[80,6],[79.7,8],[79.8,9.8]],
    // Australia & New Zealand
    [[113.4,-22],[114.2,-26.3],[115,-29.5],[115.7,-33.6],[115,-34.3],[117.9,-35.1],[120,-33.9],[123.6,-33.9],[126,-32.3],[129.5,-31.6],[131.3,-31.5],[134.2,-32.6],[135.6,-34.9],[137.7,-32.9],[137.5,-35.6],[139.6,-36.2],[140.6,-38],[143.5,-38.8],[146.3,-39.1],[148,-37.8],[150,-37.4],[150.3,-35.6],[152.5,-32.5],[153.6,-28.5],[153,-25.3],[151,-23.5],[149.5,-22.3],[148,-20],[146.3,-18.8],[145.4,-16],[145.3,-14.9],[143.6,-14],[142.5,-10.7],[141.7,-12.8],[141.6,-15.5],[140.6,-17.5],[139,-17],[136.7,-15.9],[135.4,-14.8],[136.9,-12.2],[135,-12.2],[132.6,-11.5],[131,-12.2],[129.6,-14.9],[128.2,-15],[126.2,-14.2],[124.4,-16.3],[122.2,-17.8],[121,-19.6],[118.8,-20.3],[116.7,-20.6],[114.6,-21.8],[113.4,-22]],
    [[144.6,-40.7],[148.3,-40.9],[148,-43.2],[146,-43.6],[144.6,-40.7]],
    [[172.7,-34.4],[174.4,-35.6],[175.9,-37.5],[178.5,-37.7],[177,-39.3],[175.2,-41.6],[174.6,-41.2],[174.9,-39.9],[173.8,-39.2],[174.6,-37.3],[172.7,-34.4]],
    [[172.7,-40.5],[174.3,-41.3],[173.5,-42.8],[171.3,-44.5],[169.3,-46.6],[166.5,-46],[168,-44.1],[170.8,-42.6],[172.7,-40.5]],
    // Caribbean
    [[-85,21.9],[-82,23.2],[-77.5,21.8],[-74.2,20.2],[-77.5,19.9],[-80,21.8],[-85,21.9]],
    [[-74.4,18.4],[-72.5,19.9],[-69.9,19.6],[-68.4,18.6],[-71,18],[-74.4,18.4]],
  ];
  const WATER = [
    [[27.8,42],[28,41.2],[29.5,41.2],[31.5,41.2],[34,42],[36,41.6],[38.5,40.9],[41.5,41.5],[41.7,42.7],[39.5,44],[37.5,44.7],[36.5,45.3],[35,45],[33.5,44.5],[32.5,45.4],[33.6,46],[31.5,46.6],[30,45.6],[29.6,45],[28.7,44.3],[27.8,42]],
    [[47,44.5],[49.2,46.4],[51.2,47.1],[53.1,46.8],[53,45.3],[51.3,44.5],[50.3,44.4],[52.7,42],[53.9,40.8],[53.2,39.2],[54,37.4],[51,36.8],[49,37.6],[49,38.9],[49.6,40.4],[48.6,41.8],[47.2,43.2],[47,44.5]],
  ];

  // Cities used as illustrative attack endpoints (lon, lat)
  const CITIES = [
    [-77,38.9],[-74,40.7],[-122.4,37.8],[-79.4,43.7],[-99.1,19.4],[-46.6,-23.5],[-58.4,-34.6],[-0.1,51.5],[2.35,48.85],[8.7,50.1],
    [4.9,52.4],[18,59.3],[37.6,55.8],[30.5,50.5],[34.8,32.1],[55.3,25.2],[51.4,35.7],[72.9,19.1],[77.6,13],[78.5,17.4],
    [103.8,1.35],[106.8,-6.2],[114.2,22.3],[116.4,39.9],[121.5,31.2],[127,37.6],[125.8,39],[139.7,35.7],[151.2,-33.9],[28,-26.2],
    [3.4,6.5],[36.8,-1.3],[-43.2,-22.9],[-87.6,41.9],[-118.2,34],[174.8,-36.8],
  ];

  const SEV_COLOR = { critical: [1.0, 0.30, 0.43], high: [1.0, 0.69, 0.13], medium: [0.13, 0.83, 0.93], low: [0.55, 0.42, 1.0] };
  const SEV_CSS = { critical: '#ff4d6d', high: '#ffb020', medium: '#22d3ee', low: '#8c6bff' };
  const MAX_MARKERS = 170;

  // ───────────────── Threat geography feed (one request for all globes) ─────────────────
  // GET /api/geo returns countries named in the signed-in user's OWN articles
  // (guests: built-in feeds), attributed actor origins and origin -> target arcs.
  const GeoFeed = (() => {
    const subs = new Set();
    let days = 7, data, inflight = null, timer = 0, retries = 0;
    function load() {
      if (inflight) return inflight;
      inflight = fetch(`/api/geo?days=${days}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } })
        .then((r) => (r.ok ? r.json() : null))
        .catch(() => null)
        .then((d) => {
          data = d && Array.isArray(d.countries) ? d : null;
          subs.forEach((fn) => { try { fn(data); } catch (_) { /* keep others alive */ } });
          // The guest/session cookie may not exist yet on first paint: retry a few times
          if (!data && retries < 3) { retries++; setTimeout(load, 2500 * retries); }
          if (data) retries = 0;
          return data;
        })
        .finally(() => { inflight = null; });
      return inflight;
    }
    function start() {
      if (timer) return;
      load();
      timer = setInterval(() => { if (!document.hidden) load(); }, 120000);
      // Sign-in / sign-out / guest switch changes whose data we may show
      let pending = 0;
      const again = () => { clearTimeout(pending); pending = setTimeout(load, 900); };
      const mo = new MutationObserver(again);
      mo.observe(document.body, { attributes: true, attributeFilter: ['class'] });
      const overlay = document.getElementById('auth-overlay');
      if (overlay) mo.observe(overlay, { attributes: true, attributeFilter: ['class'] });
    }
    return {
      subscribe(fn) { subs.add(fn); if (data !== undefined) fn(data); start(); },
      setDays(d) { days = d; load(); },
      get days() { return days; },
    };
  })();

  const SEVERITY = [
    { w: 0.17, c: [1.0, 0.30, 0.43] },  // critical
    { w: 0.30, c: [1.0, 0.69, 0.13] },  // high
    { w: 0.40, c: [0.13, 0.83, 0.93] }, // medium
    { w: 0.13, c: [0.55, 0.42, 1.0] },  // low
  ];

  const boxes = LAND.concat(WATER).map(boundsOf);
  function boundsOf(poly) {
    let a = 180, b = -180, c = 90, d = -90;
    for (const [x, y] of poly) { a = Math.min(a, x); b = Math.max(b, x); c = Math.min(c, y); d = Math.max(d, y); }
    return [a, b, c, d];
  }
  function inPoly(lon, lat, poly, box) {
    if (lon < box[0] || lon > box[1] || lat < box[2] || lat > box[3]) return false;
    let inside = false;
    for (let i = 0, j = poly.length - 1; i < poly.length; j = i++) {
      const xi = poly[i][0], yi = poly[i][1], xj = poly[j][0], yj = poly[j][1];
      if ((yi > lat) !== (yj > lat) && lon < ((xj - xi) * (lat - yi)) / (yj - yi) + xi) inside = !inside;
    }
    return inside;
  }
  function isLand(lon, lat) {
    if (lat < -68 + 3 * Math.sin(lon * DEG * 3)) return true; // Antarctica
    for (let k = 0; k < WATER.length; k++) if (inPoly(lon, lat, WATER[k], boxes[LAND.length + k])) return false;
    for (let k = 0; k < LAND.length; k++) if (inPoly(lon, lat, LAND[k], boxes[k])) return true;
    return false;
  }

  function toVec(lon, lat, r) {
    const la = lat * DEG, lo = lon * DEG;
    return [r * Math.cos(la) * Math.cos(lo), r * Math.sin(la), -r * Math.cos(la) * Math.sin(lo)];
  }

  // Fibonacci-sphere samples kept where there is land. Cached per sample count.
  const landCache = new Map();
  function landDots(n) {
    if (landCache.has(n)) return landCache.get(n);
    const out = [];
    const ga = Math.PI * (3 - Math.sqrt(5));
    let seed = 1337;
    const rnd = () => ((seed = (seed * 16807) % 2147483647) / 2147483647);
    for (let i = 0; i < n; i++) {
      const y = 1 - (2 * (i + 0.5)) / n;
      const r = Math.sqrt(1 - y * y);
      const phi = i * ga;
      const x = Math.cos(phi) * r, z = Math.sin(phi) * r;
      const lat = Math.asin(y) / DEG, lon = Math.atan2(-z, x) / DEG;
      if (isLand(lon, lat)) out.push(x * 1.004, y * 1.004, z * 1.004, rnd());
    }
    const arr = new Float32Array(out);
    landCache.set(n, arr);
    return arr;
  }

  // ───────────────────────── Matrices (column-major) ─────────────────────────
  function perspective(fovy, aspect, near, far) {
    const f = 1 / Math.tan(fovy / 2), nf = 1 / (near - far);
    return new Float32Array([f / aspect, 0, 0, 0, 0, f, 0, 0, 0, 0, (far + near) * nf, -1, 0, 0, 2 * far * near * nf, 0]);
  }
  function mul(a, b) {
    const o = new Float32Array(16);
    for (let c = 0; c < 4; c++) for (let r = 0; r < 4; r++) {
      let s = 0;
      for (let k = 0; k < 4; k++) s += a[k * 4 + r] * b[c * 4 + k];
      o[c * 4 + r] = s;
    }
    return o;
  }
  function rotX(t) { const c = Math.cos(t), s = Math.sin(t); return new Float32Array([1, 0, 0, 0, 0, c, s, 0, 0, -s, c, 0, 0, 0, 0, 1]); }
  function rotY(t) { const c = Math.cos(t), s = Math.sin(t); return new Float32Array([c, 0, -s, 0, 0, 1, 0, 0, s, 0, c, 0, 0, 0, 0, 1]); }
  function translate(x, y, z) { return new Float32Array([1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, x, y, z, 1]); }

  // ───────────────────────── Shaders ─────────────────────────
  const COMMON_VS = 'uniform mat4 uMVP; uniform mat4 uModel; uniform vec2 uOffset; uniform vec3 uCam; uniform float uTime; uniform float uPx; uniform float uMaxPt;\n';

  const SPHERE_VS = COMMON_VS + `
    attribute vec3 aPos; varying vec3 vW; varying vec3 vV;
    void main() {
      vW = (uModel * vec4(aPos, 1.0)).xyz;
      vV = uCam - vW;
      gl_Position = uMVP * vec4(aPos, 1.0);
      gl_Position.xy += uOffset * gl_Position.w;
    }`;
  const SPHERE_FS = `precision mediump float;
    varying vec3 vW; varying vec3 vV;
    void main() {
      vec3 n = normalize(vW);
      vec3 v = normalize(vV);
      float fr = pow(1.0 - max(dot(n, v), 0.0), 2.6);
      float dif = max(dot(n, normalize(vec3(-0.55, 0.6, 0.75))), 0.0);
      vec3 base = vec3(0.012, 0.022, 0.055) + vec3(0.025, 0.045, 0.11) * dif;
      vec3 rim = mix(vec3(0.13, 0.83, 0.93), vec3(0.49, 0.36, 1.0), clamp(n.y * 0.5 + 0.5, 0.0, 1.0));
      gl_FragColor = vec4(base + rim * fr * 0.6, 1.0);
    }`;

  const DOT_VS = COMMON_VS + `
    attribute vec3 aPos; attribute float aRnd; uniform float uSize;
    varying float vA; varying vec3 vC;
    void main() {
      vec4 w = uModel * vec4(aPos, 1.0);
      float facing = dot(normalize(w.xyz), normalize(uCam - w.xyz));
      gl_Position = uMVP * vec4(aPos, 1.0);
      gl_Position.xy += uOffset * gl_Position.w;
      float tw = 0.62 + 0.38 * sin(uTime * (0.5 + aRnd * 1.7) + aRnd * 40.0);
      float spark = step(0.992, aRnd);
      vA = smoothstep(-0.02, 0.4, facing) * (tw + spark * 0.9);
      vec3 c = mix(vec3(0.13, 0.83, 0.93), vec3(0.49, 0.36, 1.0), clamp(aPos.y * 0.45 + 0.5 + (aRnd - 0.5) * 0.5, 0.0, 1.0));
      vC = mix(c, vec3(0.9, 0.97, 1.0), spark * 0.7);
      gl_PointSize = min(uSize * (0.8 + 0.45 * aRnd + spark) * (3.4 / gl_Position.w), uMaxPt);
    }`;
  const SPRITE_FS = `precision mediump float;
    varying float vA; varying vec3 vC;
    void main() {
      float d = length(gl_PointCoord - 0.5);
      if (d > 0.5) discard;
      float a = smoothstep(0.5, 0.1, d) * vA;
      gl_FragColor = vec4(vC * a, a);
    }`;

  const ARC_VS = COMMON_VS + `
    attribute vec3 aPos; attribute float aT; attribute float aStart; attribute float aDur; attribute vec3 aCol;
    varying float vA; varying vec3 vC;
    void main() {
      float p = (uTime - aStart) / aDur;
      float head = p * 1.35;
      float trail = (aT <= head) ? smoothstep(head - 0.34, head, aT) : 0.0;
      float path = (p > 0.0 && p < 1.0) ? 0.10 * smoothstep(0.0, 0.08, p) * (1.0 - smoothstep(0.8, 1.0, p)) : 0.0;
      float a = max(trail, path);
      vA = a;
      vC = mix(aCol, vec3(1.0), pow(trail, 10.0) * 0.75);
      gl_Position = uMVP * vec4(aPos, 1.0);
      gl_Position.xy += uOffset * gl_Position.w;
      gl_PointSize = a > 0.003 ? min(uPx * (1.7 + 3.8 * pow(trail, 5.0)) * (3.4 / gl_Position.w), uMaxPt) : 0.0;
    }`;

  const RING_VS = COMMON_VS + `
    attribute vec3 aPos; attribute float aStart; attribute float aLife; attribute vec3 aCol; attribute float aMax; attribute float aRep;
    varying float vK; varying float vA; varying vec3 vC;
    void main() {
      float age = aRep > 0.5 ? mod(uTime - aStart, aLife) : (uTime - aStart);
      float k = age / aLife;
      vec4 w = uModel * vec4(aPos, 1.0);
      float facing = dot(normalize(w.xyz), normalize(uCam - w.xyz));
      vK = k; vC = aCol; vA = smoothstep(0.0, 0.35, facing);
      gl_Position = uMVP * vec4(aPos, 1.0);
      gl_Position.xy += uOffset * gl_Position.w;
      gl_PointSize = (k >= 0.0 && k <= 1.0) ? min(aMax * uPx * (0.18 + 0.82 * k), uMaxPt) : 0.0;
    }`;
  const RING_FS = `precision mediump float;
    varying float vK; varying float vA; varying vec3 vC;
    void main() {
      if (vK < 0.0 || vK > 1.0) discard;
      float d = length(gl_PointCoord - 0.5) * 2.0;
      if (d > 1.0) discard;
      float ring = smoothstep(0.68, 0.86, d) * (1.0 - smoothstep(0.86, 1.0, d));
      float core = 1.0 - smoothstep(0.0, 0.22, d);
      float fade = 1.0 - vK;
      float a = (ring * fade * 0.9 + core * 0.55 * fade * fade) * vA;
      gl_FragColor = vec4(vC * a, a);
    }`;

  const HALO_VS = `attribute vec2 aPos; varying vec2 vP; void main() { vP = aPos; gl_Position = vec4(aPos, 0.0, 1.0); }`;
  const HALO_FS = `precision mediump float;
    varying vec2 vP; uniform vec2 uCenter; uniform float uAspect; uniform float uR; uniform float uStrength;
    void main() {
      vec2 p = vP - uCenter; p.x *= uAspect;
      float d = length(p) / uR;
      float outer = d > 1.0 ? exp(-(d - 1.0) * 6.5) : 0.0;
      float inner = d <= 1.0 ? pow(d, 12.0) * 0.55 : 0.0;
      vec3 col = mix(vec3(0.13, 0.83, 0.93), vec3(0.49, 0.36, 1.0), clamp(0.5 - p.y / uR * 0.6, 0.0, 1.0));
      float a = (outer * 0.5 + inner) * uStrength;
      gl_FragColor = vec4(col * a, a);
    }`;

  const STAR_VS = `attribute vec3 aPos; attribute float aRnd; uniform mat4 uMVP; uniform float uTime; uniform float uPx;
    varying float vA; varying vec3 vC;
    void main() {
      gl_Position = uMVP * vec4(aPos * 40.0, 1.0);
      vA = (0.25 + 0.75 * aRnd) * (0.55 + 0.45 * sin(uTime * (0.3 + aRnd) + aRnd * 60.0));
      vC = mix(vec3(0.65, 0.75, 1.0), vec3(0.75, 0.6, 1.0), aRnd);
      gl_PointSize = uPx * (0.8 + 1.8 * aRnd * aRnd);
    }`;

  function compile(gl, vs, fs) {
    const p = gl.createProgram();
    for (const [type, src] of [[gl.VERTEX_SHADER, vs], [gl.FRAGMENT_SHADER, fs]]) {
      const s = gl.createShader(type);
      gl.shaderSource(s, src);
      gl.compileShader(s);
      if (!gl.getShaderParameter(s, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(s) || 'shader compile failed');
      gl.attachShader(p, s);
    }
    gl.linkProgram(p);
    if (!gl.getProgramParameter(p, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(p) || 'program link failed');
    const info = { p, a: {}, u: {} };
    const na = gl.getProgramParameter(p, gl.ACTIVE_ATTRIBUTES);
    for (let i = 0; i < na; i++) { const n = gl.getActiveAttrib(p, i).name; info.a[n] = gl.getAttribLocation(p, n); }
    const nu = gl.getProgramParameter(p, gl.ACTIVE_UNIFORMS);
    for (let i = 0; i < nu; i++) { const n = gl.getActiveUniform(p, i).name; info.u[n] = gl.getUniformLocation(p, n); }
    return info;
  }

  // Bind interleaved float attributes: layout = [[name, size], ...]
  function bindLayout(gl, prog, buf, layout) {
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    const stride = layout.reduce((s, [, n]) => s + n, 0) * 4;
    let off = 0;
    for (const [name, size] of layout) {
      const loc = prog.a[name];
      if (loc !== undefined && loc >= 0) {
        gl.enableVertexAttribArray(loc);
        gl.vertexAttribPointer(loc, size, gl.FLOAT, false, stride, off);
      }
      off += size * 4;
    }
    return () => { for (const [name] of layout) { const loc = prog.a[name]; if (loc !== undefined && loc >= 0) gl.disableVertexAttribArray(loc); } };
  }

  // ───────────────────────── Globe instance ─────────────────────────
  const PRESETS = {
    auth: { samples: 30000, arcs: 18, arcPts: 240, dist: 3.55, stars: 1400, halo: 1.0, ringMax: 46, autoSpin: 0.07, offset: true, parallax: true, panel: false },
    card: { samples: 16000, arcs: 11, arcPts: 150, dist: 3.25, stars: 0, halo: 0.9, ringMax: 30, autoSpin: 0.11, offset: false, parallax: false, panel: true },
  };
  const ARC_STRIDE = 9;   // x y z t start dur r g b
  const RING_STRIDE = 10; // x y z start life r g b max rep
  const FOV = 38 * DEG;

  function Globe(canvas, kind) {
    const cfg = PRESETS[kind] || PRESETS.card;
    const reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    let gl, progs, bufs, counts, maxPt = 64, raf = 0, visible = false, dead = false;
    let yaw = (kind === 'auth' ? -60 : 80) * DEG, tilt = 0.32, spin = cfg.autoSpin;
    let dragging = false, lastX = 0, lastY = 0, parallaxX = 0, parallaxY = 0, tgtPX = 0, tgtPY = 0;
    const t0 = performance.now();
    const now = () => (performance.now() - t0) / 1000;
    let slots = [], arcData, ringData;
    let geo = null, geoArcs = [], geoCountries = [], geoByCode = new Map();
    let fly = null, holdSpinUntil = 0, pick = null, hover = null, downAt = null, tip = null;

    function pickSeverity() {
      let r = Math.random();
      for (const s of SEVERITY) { if ((r -= s.w) <= 0) return s.c; }
      return SEVERITY[2].c;
    }

    // Park a slot: nothing drawn until it is respawned
    function idle(i, until) {
      const n = cfg.arcPts;
      for (let k = 0; k < n; k++) arcData[(i * n + k) * ARC_STRIDE + 4] = 1e9;
      for (let j = 0; j < 2; j++) ringData[(i * 2 + j) * RING_STRIDE + 8] = 0;
      slots[i] = { end: until };
      upload(i);
    }
    function upload(i) {
      if (!gl) return;
      const n = cfg.arcPts;
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.arcs);
      gl.bufferSubData(gl.ARRAY_BUFFER, i * n * ARC_STRIDE * 4, arcData.subarray(i * n * ARC_STRIDE, (i + 1) * n * ARC_STRIDE));
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.rings);
      gl.bufferSubData(gl.ARRAY_BUFFER, i * 2 * RING_STRIDE * 4, ringData.subarray(i * 2 * RING_STRIDE, (i + 1) * 2 * RING_STRIDE));
    }

    function spawn(i, start) {
      let A, B, col, dot;
      if (geo) {
        // Real data: attributed actor origin -> country named in the same report
        if (!geoArcs.length) return idle(i, start + 4);
        let r = Math.random() * geoArcs.reduce((s2, x) => s2 + x.w, 0);
        let arc = geoArcs[0];
        for (const x of geoArcs) { if ((r -= x.w) <= 0) { arc = x; break; } }
        A = arc.A; B = arc.B; col = arc.col;
        dot = A[0] * B[0] + A[1] * B[1] + A[2] * B[2];
      } else {
        // No data (signed out): illustrative traffic between major cities
        let a, b;
        do {
          a = CITIES[(Math.random() * CITIES.length) | 0];
          b = CITIES[(Math.random() * CITIES.length) | 0];
          A = toVec(a[0], a[1], 1); B = toVec(b[0], b[1], 1);
          dot = A[0] * B[0] + A[1] * B[1] + A[2] * B[2];
        } while (a === b || dot > 0.9);
        col = pickSeverity();
      }
      const omega = Math.acos(Math.max(-1, Math.min(1, dot)));
      const so = Math.sin(omega) || 1e-6;
      const lift = 0.08 + 0.3 * (omega / Math.PI);
      const dur = 2.2 + omega * 1.1 + Math.random() * 0.8;
      const n = cfg.arcPts;
      let o = i * n * ARC_STRIDE;
      for (let k = 0; k < n; k++) {
        const t = k / (n - 1);
        const s1 = Math.sin((1 - t) * omega) / so, s2 = Math.sin(t * omega) / so;
        const r = 1.006 + lift * Math.sin(Math.PI * t);
        arcData[o++] = (A[0] * s1 + B[0] * s2) * r;
        arcData[o++] = (A[1] * s1 + B[1] * s2) * r;
        arcData[o++] = (A[2] * s1 + B[2] * s2) * r;
        arcData[o++] = t; arcData[o++] = start; arcData[o++] = dur;
        arcData[o++] = col[0]; arcData[o++] = col[1]; arcData[o++] = col[2];
      }
      const impact = start + dur / 1.35;
      const rings = [
        [A, start, 1.1, cfg.ringMax * 0.45],
        [B, impact, 1.7, cfg.ringMax],
      ];
      rings.forEach(([P, st, life, mx], j) => {
        let q = (i * 2 + j) * RING_STRIDE;
        ringData[q++] = P[0] * 1.006; ringData[q++] = P[1] * 1.006; ringData[q++] = P[2] * 1.006;
        ringData[q++] = st; ringData[q++] = life;
        ringData[q++] = col[0]; ringData[q++] = col[1]; ringData[q++] = col[2];
        ringData[q++] = mx; ringData[q++] = 0;
      });
      slots[i] = { end: Math.max(start + dur, impact + 1.7) + 0.1 };
      upload(i);
    }

    // Beacons: one pulsing ring + a steady core per location
    function writeMarkers(list) {
      const base = cfg.arcs * 2;
      for (let k = 0; k < MAX_MARKERS; k++) {
        const q = (base + k) * RING_STRIDE;
        const m = list[k];
        if (!m) { ringData[q + 8] = 0; continue; }
        const P = toVec(m.lon, m.lat, 1.006);
        ringData.set([P[0], P[1], P[2], m.start, m.life, m.col[0], m.col[1], m.col[2], m.max, m.rep], q);
      }
      if (gl) {
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.rings);
        gl.bufferSubData(gl.ARRAY_BUFFER, base * RING_STRIDE * 4, ringData.subarray(base * RING_STRIDE));
      }
    }
    function cityMarkers() {
      return CITIES.map(([lon, lat]) => ({ lon, lat, start: Math.random() * 3, life: 2.4 + Math.random() * 1.6, col: [0.35, 0.9, 1.0], max: cfg.ringMax * 0.32, rep: 1 }));
    }
    function countryMarkers(list) {
      const top = Math.max(1, ...list.map((c) => c.count));
      const out = [];
      for (const c of list.slice(0, MAX_MARKERS / 2)) {
        const k = Math.log(c.count + 1) / Math.log(top + 1);
        const col = SEV_COLOR[c.worst] || SEV_COLOR.medium;
        out.push({ lon: c.lon, lat: c.lat, start: Math.random() * 2, life: 3.2 - 1.6 * k, col, max: cfg.ringMax * (0.45 + 0.85 * k), rep: 1 });
        out.push({ lon: c.lon, lat: c.lat, start: -1e6, life: 1e9, col, max: cfg.ringMax * (0.5 + 0.6 * k), rep: 0 });
      }
      return out;
    }

    function setGeo(d) {
      geo = d || null;
      geoCountries = geo ? geo.countries : [];
      geoByCode = new Map(geoCountries.map((c) => [c.code, c]));
      geoArcs = [];
      if (geo) {
        for (const a of geo.arcs || []) {
          const f = geoByCode.get(a.from), t = geoByCode.get(a.to);
          if (!f || !t) continue;
          geoArcs.push({ A: toVec(f.lon, f.lat, 1), B: toVec(t.lon, t.lat, 1), col: SEV_COLOR[a.worst] || SEV_COLOR.medium, w: Math.sqrt(a.count) });
        }
      }
      if (!ringData) return;
      writeMarkers(geo ? countryMarkers(geoCountries) : cityMarkers());
      const t = now();
      slots.forEach((sl, i) => { if (sl) sl.end = Math.min(sl.end, t + Math.random() * 1.2); });
      if (cfg.panel) renderPanel();
      schedule();
    }

    function init() {
      gl = canvas.getContext('webgl', { alpha: true, antialias: true, premultipliedAlpha: true, powerPreference: 'default' }) ||
           canvas.getContext('experimental-webgl', { alpha: true, premultipliedAlpha: true });
      if (!gl) { canvas.classList.add('globe3d-off'); dead = true; return false; }
      maxPt = (gl.getParameter(gl.ALIASED_POINT_SIZE_RANGE) || [1, 64])[1];
      progs = {
        sphere: compile(gl, SPHERE_VS, SPHERE_FS),
        dots: compile(gl, DOT_VS, SPRITE_FS),
        arcs: compile(gl, ARC_VS, SPRITE_FS),
        rings: compile(gl, RING_VS, RING_FS),
        halo: compile(gl, HALO_VS, HALO_FS),
        stars: cfg.stars ? compile(gl, STAR_VS, SPRITE_FS) : null,
      };
      bufs = {}; counts = {};

      // Sphere mesh
      const LAT = 48, LON = 96, verts = [], idx = [];
      for (let i = 0; i <= LAT; i++) {
        const th = (i / LAT) * Math.PI;
        for (let j = 0; j <= LON; j++) {
          const ph = (j / LON) * Math.PI * 2;
          verts.push(Math.sin(th) * Math.cos(ph), Math.cos(th), Math.sin(th) * Math.sin(ph));
        }
      }
      for (let i = 0; i < LAT; i++) for (let j = 0; j < LON; j++) {
        const a = i * (LON + 1) + j, b = a + LON + 1;
        idx.push(a, b, a + 1, b, b + 1, a + 1);
      }
      bufs.sphere = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.sphere);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array(verts), gl.STATIC_DRAW);
      bufs.sphereIdx = gl.createBuffer();
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, bufs.sphereIdx);
      gl.bufferData(gl.ELEMENT_ARRAY_BUFFER, new Uint16Array(idx), gl.STATIC_DRAW);
      counts.sphere = idx.length;

      // Land dots
      const dots = landDots(cfg.samples);
      bufs.dots = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.dots);
      gl.bufferData(gl.ARRAY_BUFFER, dots, gl.STATIC_DRAW);
      counts.dots = dots.length / 4;

      // Arcs + rings (dynamic), city markers appended after the arc rings
      arcData = new Float32Array(cfg.arcs * cfg.arcPts * ARC_STRIDE);
      const markers = MAX_MARKERS;
      ringData = new Float32Array((cfg.arcs * 2 + markers) * RING_STRIDE);
      bufs.arcs = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.arcs);
      gl.bufferData(gl.ARRAY_BUFFER, arcData.byteLength, gl.DYNAMIC_DRAW);
      bufs.rings = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.rings);
      gl.bufferData(gl.ARRAY_BUFFER, ringData, gl.DYNAMIC_DRAW);
      counts.arcs = cfg.arcs * cfg.arcPts;
      counts.rings = cfg.arcs * 2 + markers;
      const t = now();
      slots = [];
      // First arcs start part-way through so the globe is busy from frame one
      writeMarkers(geo ? countryMarkers(geoCountries) : cityMarkers());
      for (let i = 0; i < cfg.arcs; i++) spawn(i, t - Math.random() * 2.5 + (i % 3) * 0.6);

      // Halo quad
      bufs.halo = gl.createBuffer();
      gl.bindBuffer(gl.ARRAY_BUFFER, bufs.halo);
      gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);

      // Starfield
      if (cfg.stars) {
        const s = new Float32Array(cfg.stars * 4);
        for (let i = 0; i < cfg.stars; i++) {
          const u = Math.random() * 2 - 1, ph = Math.random() * Math.PI * 2, r = Math.sqrt(1 - u * u);
          s.set([r * Math.cos(ph), u, r * Math.sin(ph), Math.pow(Math.random(), 2.2)], i * 4);
        }
        bufs.stars = gl.createBuffer();
        gl.bindBuffer(gl.ARRAY_BUFFER, bufs.stars);
        gl.bufferData(gl.ARRAY_BUFFER, s, gl.STATIC_DRAW);
        counts.stars = cfg.stars;
      }
      if (cfg.panel) renderPanel();
      return true;
    }

    function resize() {
      const dpr = Math.min(window.devicePixelRatio || 1, kind === 'auth' ? 2 : 1.75);
      const w = Math.max(1, Math.round(canvas.clientWidth * dpr));
      const h = Math.max(1, Math.round(canvas.clientHeight * dpr));
      if (canvas.width !== w || canvas.height !== h) { canvas.width = w; canvas.height = h; }
      return dpr;
    }

    // Where the globe sits. On the sign-in screen it fills the free space to the
    // right of the card (so it never sits behind the form); elsewhere it is centred.
    function distFor(ndcR) { return 1 / Math.sin(Math.atan(ndcR * Math.tan(FOV / 2))); }
    function layout() {
      if (!cfg.offset) return { dist: cfg.dist, x: 0, y: 0 };
      const cr = canvas.getBoundingClientRect();
      const card = canvas.parentElement && canvas.parentElement.querySelector('.auth-card');
      const rr = card && card.getBoundingClientRect();
      if (rr && rr.width && cr.width && cr.height) {
        const gap = cr.right - rr.right;                       // free width right of the card
        const radius = Math.min(gap * 0.40, cr.height * 0.36);  // px, leaves room for arcs
        if (radius > 120) {
          const cx = rr.right + gap * 0.5;
          return { dist: distFor(radius / (cr.height / 2)), x: ((cx - cr.left) / cr.width) * 2 - 1, y: 0 };
        }
      }
      // Narrow screens: a large globe peeking from behind the card's top
      return { dist: distFor(0.62), x: 0, y: 0.32 };
    }

    function frame() {
      raf = 0;
      if (dead || !gl) return;
      const dpr = resize();
      const W = canvas.width, H = canvas.height;
      if (W < 4 || H < 4) return schedule();
      const t = now();
      const dt = Math.min(0.05, frame.last ? t - frame.last : 0.016);
      frame.last = t;

      // Motion: auto-spin with drag inertia, gentle pointer parallax on sign-in
      if (fly) {
        const k = Math.min(1, (t - fly.t0) / fly.dur);
        const e = k < 0.5 ? 4 * k * k * k : 1 - Math.pow(-2 * k + 2, 3) / 2;
        yaw = fly.y0 + (fly.y1 - fly.y0) * e;
        tilt = fly.p0 + (fly.p1 - fly.p0) * e;
        if (k >= 1) fly = null;
        spin = 0;
      } else if (!dragging) {
        const target = t < holdSpinUntil ? 0 : cfg.autoSpin;
        spin += (target - spin) * Math.min(1, dt * 1.5);
        yaw += spin * dt;
      }
      if (cfg.parallax) { parallaxX += (tgtPX - parallaxX) * Math.min(1, dt * 2.5); parallaxY += (tgtPY - parallaxY) * Math.min(1, dt * 2.5); }

      for (let i = 0; i < slots.length; i++) if (t > slots[i].end) spawn(i, t + Math.random() * 1.2);

      const aspect = W / H;
      const P = perspective(FOV, aspect, 0.1, 100);
      const L = layout();
      const dist = L.dist, offX = L.x, offY = L.y;
      const M = mul(rotX(tilt + parallaxY * 0.12), rotY(yaw + parallaxX * 0.25));
      const V = translate(0, 0, -dist);
      const MVP = mul(P, mul(V, M));
      const cam = [0, 0, dist];
      const ndcR = Math.tan(Math.asin(1 / dist)) / Math.tan(FOV / 2);
      const spacing = ndcR * (H / 2) * Math.sqrt((4 * Math.PI) / cfg.samples);
      const dotSize = Math.max(1.4 * dpr, spacing * 0.62);
      pick = { MVP, M, offX, offY, cam };

      gl.viewport(0, 0, W, H);
      gl.clearColor(0, 0, 0, 0);
      gl.clearDepth(1);
      gl.clear(gl.COLOR_BUFFER_BIT | gl.DEPTH_BUFFER_BIT);
      gl.enable(gl.DEPTH_TEST);
      gl.depthFunc(gl.LEQUAL);

      const common = (pr) => {
        gl.useProgram(pr.p);
        if (pr.u.uMVP) gl.uniformMatrix4fv(pr.u.uMVP, false, MVP);
        if (pr.u.uModel) gl.uniformMatrix4fv(pr.u.uModel, false, M);
        if (pr.u.uOffset) gl.uniform2f(pr.u.uOffset, offX, offY);
        if (pr.u.uCam) gl.uniform3fv(pr.u.uCam, cam);
        if (pr.u.uTime) gl.uniform1f(pr.u.uTime, t);
        if (pr.u.uPx) gl.uniform1f(pr.u.uPx, dpr);
        if (pr.u.uMaxPt) gl.uniform1f(pr.u.uMaxPt, maxPt);
      };

      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE);

      // Stars (behind everything; the opaque globe hides those behind it)
      if (progs.stars) {
        const pr = progs.stars;
        gl.useProgram(pr.p);
        gl.depthMask(false);
        const SM = mul(P, mul(rotX(0.2 + parallaxY * 0.03), rotY(t * 0.004 + parallaxX * 0.05)));
        gl.uniformMatrix4fv(pr.u.uMVP, false, SM);
        gl.uniform1f(pr.u.uTime, t);
        gl.uniform1f(pr.u.uPx, dpr);
        const off = bindLayout(gl, pr, bufs.stars, [['aPos', 3], ['aRnd', 1]]);
        gl.drawArrays(gl.POINTS, 0, counts.stars);
        off();
      }

      // Globe body
      gl.disable(gl.BLEND);
      gl.depthMask(true);
      common(progs.sphere);
      let off = bindLayout(gl, progs.sphere, bufs.sphere, [['aPos', 3]]);
      gl.bindBuffer(gl.ELEMENT_ARRAY_BUFFER, bufs.sphereIdx);
      gl.drawElements(gl.TRIANGLES, counts.sphere, gl.UNSIGNED_SHORT, 0);
      off();

      gl.enable(gl.BLEND);
      gl.blendFunc(gl.ONE, gl.ONE);
      gl.depthMask(false);

      // Atmosphere
      gl.disable(gl.DEPTH_TEST);
      const hp = progs.halo;
      gl.useProgram(hp.p);
      gl.uniform2f(hp.u.uCenter, offX, offY);
      gl.uniform1f(hp.u.uAspect, aspect);
      gl.uniform1f(hp.u.uR, ndcR);
      gl.uniform1f(hp.u.uStrength, cfg.halo);
      off = bindLayout(gl, hp, bufs.halo, [['aPos', 2]]);
      gl.drawArrays(gl.TRIANGLES, 0, 3);
      off();
      gl.enable(gl.DEPTH_TEST);

      // Land dots
      common(progs.dots);
      gl.uniform1f(progs.dots.u.uSize, dotSize);
      off = bindLayout(gl, progs.dots, bufs.dots, [['aPos', 3], ['aRnd', 1]]);
      gl.drawArrays(gl.POINTS, 0, counts.dots);
      off();

      // Attack arcs
      common(progs.arcs);
      off = bindLayout(gl, progs.arcs, bufs.arcs, [['aPos', 3], ['aT', 1], ['aStart', 1], ['aDur', 1], ['aCol', 3]]);
      gl.drawArrays(gl.POINTS, 0, counts.arcs);
      off();

      // Launch / impact rings + city beacons
      common(progs.rings);
      off = bindLayout(gl, progs.rings, bufs.rings, [['aPos', 3], ['aStart', 1], ['aLife', 1], ['aCol', 3], ['aMax', 1], ['aRep', 1]]);
      gl.drawArrays(gl.POINTS, 0, counts.rings);
      off();

      gl.depthMask(true);
      if (!canvas.classList.contains('ready')) canvas.classList.add('ready');
      if (!reduceMotion || fly) schedule();
    }

    function schedule() {
      if (!raf && visible && !document.hidden && !dead) raf = requestAnimationFrame(frame);
    }

    // Pointer: drag to spin (with inertia); parallax follows the mouse on sign-in
    // ── Picking: which country beacon is under the pointer ──
    function project(c) {
      const v = toVec(c.lon, c.lat, 1.006);
      const m = pick.M, P = pick.MVP;
      const wx = m[0] * v[0] + m[4] * v[1] + m[8] * v[2];
      const wy = m[1] * v[0] + m[5] * v[1] + m[9] * v[2];
      const wz = m[2] * v[0] + m[6] * v[1] + m[10] * v[2];
      const vx = pick.cam[0] - wx, vy = pick.cam[1] - wy, vz = pick.cam[2] - wz;
      const facing = (wx * vx + wy * vy + wz * vz) / (Math.hypot(wx, wy, wz) * Math.hypot(vx, vy, vz));
      const cx = P[0] * v[0] + P[4] * v[1] + P[8] * v[2] + P[12];
      const cy = P[1] * v[0] + P[5] * v[1] + P[9] * v[2] + P[13];
      const cw = P[3] * v[0] + P[7] * v[1] + P[11] * v[2] + P[15];
      return { x: (cx / cw + pick.offX) * 0.5 + 0.5, y: 0.5 - (cy / cw + pick.offY) * 0.5, facing };
    }
    function pickAt(clientX, clientY) {
      if (!pick || !geoCountries.length) return null;
      const r = canvas.getBoundingClientRect();
      const px = clientX - r.left, py = clientY - r.top;
      const top = Math.max(1, geoCountries[0].count);
      let best = null, bestD = Infinity;
      for (const c of geoCountries) {
        const p = project(c);
        if (p.facing < 0.12) continue;
        const d = Math.hypot(p.x * r.width - px, p.y * r.height - py);
        const reach = 9 + 9 * (Math.log(c.count + 1) / Math.log(top + 1));
        if (d < reach && d < bestD) { best = { c, sx: p.x * r.width, sy: p.y * r.height }; bestD = d; }
      }
      return best;
    }

    // ── Tooltip (DOM text only: headlines come from external feeds) ──
    function showTip(hit) {
      const host = canvas.parentElement;
      if (!host) return;
      if (!tip) { tip = document.createElement('div'); tip.className = 'globe-tip'; tip.setAttribute('role', 'tooltip'); host.appendChild(tip); }
      const c = hit.c;
      tip.textContent = '';
      const head = document.createElement('div'); head.className = 'globe-tip-head';
      const dot = document.createElement('i'); dot.style.background = SEV_CSS[c.worst] || SEV_CSS.medium;
      const name = document.createElement('b'); name.textContent = c.name;
      head.append(dot, name);
      const stats = document.createElement('div'); stats.className = 'globe-tip-stats';
      stats.textContent = `${c.count} report${c.count === 1 ? '' : 's'}` +
        (c.critical ? ` · ${c.critical} critical` : '') + (c.high ? ` · ${c.high} high` : '') +
        (c.ransomware ? ` · ${c.ransomware} ransomware leak${c.ransomware === 1 ? '' : 's'}` : '');
      tip.append(head, stats);
      if (c.origin) {
        const o = document.createElement('div'); o.className = 'globe-tip-origin';
        o.textContent = `Attributed origin in ${c.origin} report${c.origin === 1 ? '' : 's'}`;
        tip.append(o);
      }
      for (const a of (c.top || []).slice(0, 2)) {
        const h = document.createElement('div'); h.className = 'globe-tip-item';
        h.textContent = a.title;
        tip.append(h);
      }
      if (cfg.panel) { const hint = document.createElement('div'); hint.className = 'globe-tip-hint'; hint.textContent = 'Click to filter your feed'; tip.append(hint); }
      const left = canvas.offsetLeft + hit.sx, topPx = canvas.offsetTop + hit.sy;
      const w = host.clientWidth;
      tip.style.left = `${Math.max(6, Math.min(w - 236, left + 14))}px`;
      const maxTop = Math.max(6, host.clientHeight - tip.offsetHeight - 6);
      tip.style.top = `${Math.max(6, Math.min(maxTop, topPx - 18))}px`;
      tip.classList.add('show');
    }
    function hideTip() { if (tip) tip.classList.remove('show'); }

    function flyTo(lat, lon) {
      let y1 = -Math.PI / 2 - lon * DEG;
      while (y1 - yaw > Math.PI) y1 -= 2 * Math.PI;
      while (y1 - yaw < -Math.PI) y1 += 2 * Math.PI;
      const p1 = Math.max(-0.35, Math.min(1.0, lat * DEG));
      fly = { t0: now(), dur: 1.3, y0: yaw, y1, p0: tilt, p1 };
      holdSpinUntil = now() + 12;
      schedule();
    }
    function filterFeed(c) {
      const input = document.getElementById('search-input');
      if (!input) return;
      input.value = c.term || c.name;
      input.dispatchEvent(new Event('input', { bubbles: true }));
      const feed = document.getElementById('feed');
      if (feed && feed.scrollIntoView) feed.scrollIntoView({ behavior: reduceMotion ? 'auto' : 'smooth', block: 'start' });
    }
    function focusCountry(code, alsoFilter) {
      const c = geoByCode.get(code);
      if (!c) return;
      flyTo(c.lat, c.lon);
      if (alsoFilter) filterFeed(c);
    }

    // ── Card panel: summary, time range, top countries ──
    function renderPanel() {
      const card = canvas.closest('.globe-card');
      if (!card) return;
      const sum = card.querySelector('.globe-summary');
      const list = card.querySelector('.globe-top');
      const hud = card.querySelector('.globe-hud-text');
      if (!geo) {
        if (sum) sum.textContent = 'Sign in to map your own feeds';
        if (list) list.textContent = '';
        if (hud) hud.textContent = 'Illustrative traffic · drag to spin';
        return;
      }
      const range = geo.days === 1 ? '24 h' : `${geo.days} days`;
      if (sum) sum.textContent = geo.countries.length
        ? `${geo.geolocated} of ${geo.totalArticles} reports geolocated · ${geo.countries.length} countries · ${range}`
        : `No country named in your ${geo.totalArticles} reports (${range})`;
      if (hud) hud.textContent = geo.arcs.length
        ? `${geo.arcs.length} attributed origin → target path${geo.arcs.length === 1 ? '' : 's'} · hover a beacon`
        : 'Hover a beacon · click to filter';
      if (!list) return;
      list.textContent = '';
      const top = geo.countries.slice(0, 5);
      const max = Math.max(1, ...top.map((c) => c.count));
      for (const c of top) {
        const li = document.createElement('li');
        const btn = document.createElement('button');
        btn.type = 'button';
        btn.title = `Rotate to ${c.name} and filter the feed`;
        const dot = document.createElement('i'); dot.style.background = SEV_CSS[c.worst] || SEV_CSS.medium;
        const name = document.createElement('span'); name.className = 'gt-name'; name.textContent = c.name;
        const bar = document.createElement('span'); bar.className = 'gt-bar';
        const fill = document.createElement('span'); fill.style.width = `${Math.max(6, (c.count / max) * 100)}%`; fill.style.background = SEV_CSS[c.worst] || SEV_CSS.medium;
        bar.append(fill);
        const n = document.createElement('span'); n.className = 'gt-count'; n.textContent = String(c.count);
        btn.append(dot, name, bar, n);
        btn.addEventListener('click', () => focusCountry(c.code, true));
        li.append(btn);
        list.append(li);
      }
    }
    if (cfg.panel) {
      const card = canvas.closest('.globe-card');
      card && card.querySelectorAll('[data-globe-days]').forEach((b) => b.addEventListener('click', () => {
        card.querySelectorAll('[data-globe-days]').forEach((x) => x.classList.toggle('active', x === b));
        GeoFeed.setDays(parseInt(b.dataset.globeDays, 10) || 7);
      }));
    }

    canvas.addEventListener('pointermove', (e) => {
      if (dragging) return;
      const hit = pickAt(e.clientX, e.clientY);
      hover = hit;
      canvas.classList.toggle('over-beacon', !!hit);
      if (hit) showTip(hit); else hideTip();
    });
    canvas.addEventListener('pointerleave', () => { hover = null; hideTip(); canvas.classList.remove('over-beacon'); });

    canvas.addEventListener('pointerdown', (e) => {
      if (e.button !== undefined && e.button !== 0) return;
      downAt = { x: e.clientX, y: e.clientY };
      hideTip();
      dragging = true; lastX = e.clientX; lastY = e.clientY;
      canvas.classList.add('dragging');
      try { canvas.setPointerCapture(e.pointerId); } catch (_) { /* ignore */ }
    });
    canvas.addEventListener('pointermove', (e) => {
      if (!dragging) return;
      const dx = e.clientX - lastX, dy = e.clientY - lastY;
      lastX = e.clientX; lastY = e.clientY;
      const k = 2.6 / Math.max(160, canvas.clientHeight);
      yaw += dx * k; spin = dx * k * 60;
      tilt = Math.max(-0.35, Math.min(1.0, tilt + dy * k * 0.7));
      if (reduceMotion) schedule();
    });
    const endDrag = () => { dragging = false; canvas.classList.remove('dragging'); };
    canvas.addEventListener('pointerup', (e) => {
      endDrag();
      const moved = downAt ? Math.hypot(e.clientX - downAt.x, e.clientY - downAt.y) : 99;
      downAt = null;
      if (moved > 6) return;
      const hit = pickAt(e.clientX, e.clientY);
      if (hit) focusCountry(hit.c.code, !!cfg.panel);
    });
    canvas.addEventListener('pointercancel', endDrag);
    if (cfg.parallax) {
      window.addEventListener('pointermove', (e) => {
        tgtPX = (e.clientX / window.innerWidth - 0.5) * 2;
        tgtPY = (e.clientY / window.innerHeight - 0.5) * 2;
      }, { passive: true });
    }

    canvas.addEventListener('webglcontextlost', (e) => { e.preventDefault(); dead = true; if (raf) cancelAnimationFrame(raf); raf = 0; });
    canvas.addEventListener('webglcontextrestored', () => { dead = false; try { if (init()) schedule(); } catch (_) { dead = true; } });

    const io = 'IntersectionObserver' in window ? new IntersectionObserver((entries) => {
      visible = entries.some((en) => en.isIntersecting);
      if (visible) schedule();
    }) : null;
    if (io) io.observe(canvas); else visible = true;
    document.addEventListener('visibilitychange', schedule);
    if ('ResizeObserver' in window) new ResizeObserver(() => { if (reduceMotion || !raf) { frame.last = 0; schedule(); } }).observe(canvas);

    GeoFeed.subscribe(setGeo);
    try { if (init()) schedule(); } catch (err) {
      dead = true;
      canvas.classList.add('globe3d-off');
      if (window.console) console.warn('[globe3d] disabled:', err.message);
    }
  }

  function start() {
    document.querySelectorAll('canvas[data-globe]').forEach((c) => {
      if (c.__globe) return;
      c.__globe = true;
      // Build the heavier sign-in globe first; the sidebar one right after
      const go = () => Globe(c, c.dataset.globe);
      if (c.dataset.globe === 'card' && 'requestIdleCallback' in window) requestIdleCallback(go, { timeout: 1500 });
      else go();
    });
  }
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
  else start();
})();
