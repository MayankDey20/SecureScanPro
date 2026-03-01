import { useEffect, useRef } from 'react';

/* ═══════════════════════════════════════════════════════════════
   Cyberpunk Pixel-Art Canvas Background — fully self-contained.
   Paints its own dark background so z-index/CSS conflicts don't
   matter. Layers drawn each frame (back → front):
     1. Deep-space gradient fill
     2. Faint pixel grid (cyan, 32 px)
     3. Horizon neon halos (purple / cyan / magenta)
     4. City silhouette — 3 depth layers with neon windows
     5. Scanline overlay + slow sweep
     6. Matrix pixel-rain columns
     7. Floating neon orbs
     8. Periodic horizontal glitch-stripe flash
═══════════════════════════════════════════════════════════════ */

function ri(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
function ro(arr){return arr[Math.floor(Math.random()*arr.length)];}

const CHARS='01アイウエオカキクケコサシスセソタチツテトナニヌネノ#$%&?!><{}[]';
const WIN_COLORS=['#00ffe0','#00b4ff','#ff00cc','#ffe040','#ff3060'];
const ORB_PAL=[[0,255,200],[0,180,255],[180,0,255],[255,0,160],[0,255,100]];

function makeBuildings(W,count,minW,maxW,minH,maxH){
  const raw=[];let x=0;
  for(let i=0;i<count;i++){
    const bw=ri(minW,maxW),bh=ri(minH,maxH);
    raw.push({x,w:bw,h:bh});
    x+=bw+ri(0,6);
  }
  const scale=W/x;
  return raw.map(b=>({
    x:Math.round(b.x*scale),
    w:Math.max(2,Math.round(b.w*scale)),
    h:b.h,
    wins:Array.from({length:ri(3,14)},()=>({
      rx:ri(2,Math.max(3,Math.round(b.w*scale)-4)),
      ry:ri(4,Math.max(5,b.h-6)),
      c:ro(WIN_COLORS),
    })),
  }));
}

class Drop{
  constructor(colW,col,H){
    this.colW=colW;this.col=col;
    this.x=col*colW+colW/2;this.y=ri(-H,0);
    this.spd=ri(2,8);this.len=ri(6,22);
    this.chars=Array.from({length:this.len},()=>ro(CHARS));
    this.rgb=Math.random()>0.18
      ?`0,${ri(200,255)},${ri(160,255)}`
      :`${ri(0,80)},${ri(180,255)},255`;
    this.tick=0;
  }
  update(H){
    this.y+=this.spd;this.tick++;
    if(this.tick>5){this.tick=0;this.chars[ri(0,this.len-1)]=ro(CHARS);}
    if(this.y-this.len*14>H){
      this.y=ri(-200,-20);this.spd=ri(2,8);this.len=ri(6,22);
      this.chars=Array.from({length:this.len},()=>ro(CHARS));
    }
  }
  draw(ctx){
    const fs=Math.max(9,this.colW-1);
    ctx.font=`bold ${fs}px 'Courier New',monospace`;ctx.textAlign='center';
    for(let i=0;i<this.chars.length;i++){
      const gy=this.y-i*(fs+2);
      if(gy<-fs||gy>ctx.canvas.height+fs)continue;
      const a=i===0?0.38:Math.max(0,0.22-i*0.02);
      if(i===0){ctx.shadowBlur=6;ctx.shadowColor=`rgba(${this.rgb},0.6)`;ctx.fillStyle=`rgba(200,255,255,${a})`;}
      else{ctx.shadowBlur=2;ctx.shadowColor=`rgba(${this.rgb},0.4)`;ctx.fillStyle=`rgba(${this.rgb},${a})`;}
      ctx.fillText(this.chars[i],this.x,gy);
    }
    ctx.shadowBlur=0;
  }
}

class Orb{
  constructor(W,H){this.W=W;this.H=H;this.spawn();this.y=Math.random()*H*0.7;}
  spawn(){
    this.x=Math.random()*this.W;this.y=Math.random()*this.H*0.68;
    this.r=ri(3,8);this.rgb=ro(ORB_PAL);
    this.vx=(Math.random()-0.5)*0.5;this.vy=(Math.random()-0.5)*0.35;
    this.life=0;this.max=ri(280,800);this.a=0;
  }
  update(){
    this.x+=this.vx;this.y+=this.vy;this.life++;
    const h=this.max/2;
    this.a=this.life<h?(this.life/h)*0.30:((this.max-this.life)/h)*0.30;
    if(this.life>=this.max)this.spawn();
  }
  draw(ctx){
    const[r,g,b]=this.rgb;
    const glow=ctx.createRadialGradient(this.x,this.y,0,this.x,this.y,this.r*10);
    glow.addColorStop(0,`rgba(${r},${g},${b},${(this.a*0.9).toFixed(2)})`);
    glow.addColorStop(0.4,`rgba(${r},${g},${b},${(this.a*0.3).toFixed(2)})`);
    glow.addColorStop(1,`rgba(${r},${g},${b},0)`);
    ctx.beginPath();ctx.arc(this.x,this.y,this.r*10,0,Math.PI*2);
    ctx.fillStyle=glow;ctx.fill();
    ctx.beginPath();ctx.arc(this.x,this.y,this.r,0,Math.PI*2);
    ctx.shadowBlur=14;ctx.shadowColor=`rgba(${r},${g},${b},1)`;
    ctx.fillStyle=`rgba(${r},${g},${b},${Math.min(this.a*2.2,1).toFixed(2)})`;
    ctx.fill();ctx.shadowBlur=0;
  }
}

const NetworkBackground=()=>{
  const canvasRef=useRef(null);
  useEffect(()=>{
    const canvas=canvasRef.current;if(!canvas)return;
    const ctx=canvas.getContext('2d');
    let rafId,frame=0,W,H;
    const COLS=72,ORB_N=16;
    let colW,drops,orbs,bldFar,bldMid,bldNear;
    let glitchOn=false,gF=0,nextG=ri(200,500);

    function init(){
      W=canvas.width=window.innerWidth;
      H=canvas.height=window.innerHeight;
      colW=Math.floor(W/COLS);
      drops=Array.from({length:COLS},(_,i)=>new Drop(colW,i,H));
      orbs=Array.from({length:ORB_N},()=>new Orb(W,H));
      const skyH=H*0.62;
      bldFar =makeBuildings(W,55,18, 55, Math.round(skyH*.26),Math.round(skyH*.40));
      bldMid =makeBuildings(W,38,30, 85, Math.round(skyH*.36),Math.round(skyH*.60));
      bldNear=makeBuildings(W,22,55,130, Math.round(skyH*.52),Math.round(skyH*.86));
    }

    function drawBg(){
      const g=ctx.createLinearGradient(0,0,0,H);
      g.addColorStop(0,'#000814');g.addColorStop(0.45,'#020b1f');
      g.addColorStop(0.70,'#031020');g.addColorStop(1,'#000510');
      ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
    }

    function drawGrid(){
      ctx.save();ctx.strokeStyle='rgba(0,220,255,0.022)';ctx.lineWidth=1;
      for(let x=0;x<W;x+=32){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,H);ctx.stroke();}
      for(let y=0;y<H;y+=32){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(W,y);ctx.stroke();}
      ctx.restore();
    }

    function drawHorizon(){
      const hy=H*0.60;
      let g=ctx.createRadialGradient(W*.15,hy,0,W*.15,hy,W*.45);
      g.addColorStop(0,'rgba(160,0,255,0.08)');g.addColorStop(1,'rgba(160,0,255,0)');
      ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
      g=ctx.createRadialGradient(W*.85,hy,0,W*.85,hy,W*.45);
      g.addColorStop(0,'rgba(0,200,255,0.07)');g.addColorStop(1,'rgba(0,200,255,0)');
      ctx.fillStyle=g;ctx.fillRect(0,0,W,H);
      g=ctx.createLinearGradient(0,hy-4,0,hy+80);
      g.addColorStop(0,'rgba(255,0,140,0.05)');g.addColorStop(1,'rgba(255,0,140,0)');
      ctx.fillStyle=g;ctx.fillRect(0,hy-4,W,84);
      g=ctx.createLinearGradient(0,H*.78,0,H);
      g.addColorStop(0,'rgba(0,255,160,0.05)');g.addColorStop(1,'rgba(0,255,160,0)');
      ctx.fillStyle=g;ctx.fillRect(0,H*.78,W,H*.22);
    }

    function drawLayer(blds,baseY,body,edge,wa){
      blds.forEach(b=>{
        const top=baseY-b.h;
        ctx.fillStyle=body;ctx.fillRect(b.x,top,b.w,b.h);
        ctx.fillStyle=edge;ctx.fillRect(b.x,top,1,b.h);
        b.wins.forEach(w=>{
          if(w.rx>=b.w-2||w.ry>=b.h-2)return;
          ctx.fillStyle=w.c;ctx.shadowBlur=6;ctx.shadowColor=w.c;
          ctx.globalAlpha=wa;ctx.fillRect(b.x+w.rx,top+w.ry,2,3);
          ctx.globalAlpha=1;ctx.shadowBlur=0;
        });
      });
    }

    function drawScanlines(){
      ctx.save();ctx.fillStyle='rgba(0,0,0,0.12)';
      for(let y=0;y<H;y+=4)ctx.fillRect(0,y,W,2);
      const sy=(frame*0.35)%H;
      const sg=ctx.createLinearGradient(0,sy-28,0,sy+28);
      sg.addColorStop(0,'rgba(0,255,200,0)');
      sg.addColorStop(0.5,'rgba(0,255,200,0.05)');
      sg.addColorStop(1,'rgba(0,255,200,0)');
      ctx.fillStyle=sg;ctx.fillRect(0,sy-28,W,56);ctx.restore();
    }

    function doGlitch(){
      if(!glitchOn){if(--nextG<=0){glitchOn=true;gF=ri(3,8);nextG=ri(220,480);}return;}
      for(let s=0;s<ri(2,5);s++){
        const sy=ri(0,H-8),sh=ri(1,5),sx=ri(-30,30);
        ctx.save();ctx.globalAlpha=0.18+Math.random()*0.15;
        try{ctx.drawImage(canvas,0,sy,W,sh,sx,sy,W,sh);}catch(e){}
        ctx.fillStyle=ro(['rgba(255,0,60,0.18)','rgba(0,255,200,0.15)','rgba(180,0,255,0.16)']);
        ctx.fillRect(0,sy,W,sh);ctx.restore();
      }
      if(--gF<=0)glitchOn=false;
    }

    function render(){
      frame++;
      drawBg();drawGrid();drawHorizon();
      const baseY=Math.round(H*0.88);
      drawLayer(bldFar, baseY,'#050e22','rgba(0,80,180,0.18)', 0.28);
      drawLayer(bldMid, baseY,'#030b1a','rgba(0,60,160,0.15)',0.38);
      drawLayer(bldNear,baseY,'#010610','rgba(0,40,120,0.12)',0.50);
      drawScanlines();
      drops.forEach(d=>{d.update(H);d.draw(ctx);});
      orbs.forEach(o=>{o.update();o.draw(ctx);});
      doGlitch();
      rafId=requestAnimationFrame(render);
    }

    init();render();
    window.addEventListener('resize',init);
    return()=>{window.removeEventListener('resize',init);cancelAnimationFrame(rafId);};
  },[]);

  return(
    <canvas ref={canvasRef} style={{
      position:'fixed',top:0,left:0,
      width:'100%',height:'100%',
      zIndex:-1,pointerEvents:'none',
    }}/>
  );
};

export default NetworkBackground;
