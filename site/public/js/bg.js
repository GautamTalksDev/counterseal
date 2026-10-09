// "Wax light": a slow, soft light moving under the page, like a lamp seen through green sealing wax. WebGL, rendered at
// a quarter of the screen size and blurred by CSS. Light only: no particles, nothing follows the cursor. Paused while the
// tab is hidden; not started at all when the visitor prefers reduced motion or the browser has no WebGL.
export function waxLight(id = 'wax') {
  const cv = document.getElementById(id);
  if (!cv || matchMedia('(prefers-reduced-motion: reduce)').matches) return;
  const gl = cv.getContext('webgl', { antialias: false, alpha: true, premultipliedAlpha: false, powerPreference: 'low-power' });
  if (!gl) return;
  const vs = 'attribute vec2 p;void main(){gl_Position=vec4(p,0.,1.);}';
  const fs = `precision mediump float;uniform vec2 r;uniform float t;uniform float s;
  float h(vec2 p){return fract(sin(dot(p,vec2(127.1,311.7)))*43758.5453);}
  float n(vec2 p){vec2 i=floor(p),f=fract(p);f=f*f*(3.-2.*f);return mix(mix(h(i),h(i+vec2(1,0)),f.x),mix(h(i+vec2(0,1)),h(i+vec2(1,1)),f.x),f.y);}
  float fbm(vec2 p){float v=0.,a=.5;for(int i=0;i<5;i++){v+=a*n(p);p=p*2.02+vec2(3.1,7.7);a*=.5;}return v;}
  void main(){
    vec2 uv=gl_FragCoord.xy/r;vec2 p=uv*vec2(r.x/r.y,1.)*1.25;float T=t*.028;
    p.y+=s*.35;
    vec2 q=vec2(fbm(p+vec2(0.,T)),fbm(p+vec2(4.3,1.9)-T));
    vec2 w=vec2(fbm(p+2.6*q+vec2(1.3,8.1)+T*1.2),fbm(p+2.6*q+vec2(6.7,2.2)-T*.8));
    float f=fbm(p+3.2*w);
    float pool=smoothstep(.40,.86,f);
    float sheen=pow(smoothstep(.58,.80,f)*smoothstep(1.,.74,f),2.)*smoothstep(.45,.9,w.y);
    vec3 deep=vec3(.035,.17,.11),wax=vec3(.09,.38,.25),lime=vec3(.78,.96,.38);
    vec3 c=mix(deep,wax,pool)*pool+lime*sheen*.55;
    float a=clamp(pool*.62+sheen*.5,0.,.7);
    gl_FragColor=vec4(c,a);}`;
  const sh = (type, src) => { const x = gl.createShader(type); gl.shaderSource(x, src); gl.compileShader(x); return x; };
  const pr = gl.createProgram(); gl.attachShader(pr, sh(gl.VERTEX_SHADER, vs)); gl.attachShader(pr, sh(gl.FRAGMENT_SHADER, fs)); gl.linkProgram(pr);
  if (!gl.getProgramParameter(pr, gl.LINK_STATUS)) return;
  gl.useProgram(pr);
  gl.bindBuffer(gl.ARRAY_BUFFER, gl.createBuffer()); gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  const loc = gl.getAttribLocation(pr, 'p'); gl.enableVertexAttribArray(loc); gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);
  const uR = gl.getUniformLocation(pr, 'r'), uT = gl.getUniformLocation(pr, 't'), uS = gl.getUniformLocation(pr, 's');
  const SCALE = 0.25;
  const size = () => { cv.width = Math.max(2, Math.round(innerWidth * SCALE)); cv.height = Math.max(2, Math.round(innerHeight * SCALE)); gl.viewport(0, 0, cv.width, cv.height); gl.uniform2f(uR, cv.width, cv.height); };
  addEventListener('resize', size); size();
  const t0 = performance.now();
  let last = 0;
  const loop = (ts) => {
    // about 30 frames a second is plenty for light this slow
    if (!document.hidden && ts - last > 32) {
      last = ts;
      gl.uniform1f(uT, (ts - t0) / 1000);
      gl.uniform1f(uS, scrollY / Math.max(1, document.documentElement.scrollHeight));
      gl.drawArrays(gl.TRIANGLES, 0, 3);
    }
    requestAnimationFrame(loop);
  };
  requestAnimationFrame(loop);
  cv.classList.add('on');
}
