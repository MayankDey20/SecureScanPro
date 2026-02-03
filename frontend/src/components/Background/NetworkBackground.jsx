import { useEffect, useRef } from 'react';

const NetworkBackground = () => {
  const canvasRef = useRef(null);

  useEffect(() => {
    const canvas = canvasRef.current;
    if (!canvas) return; // Guard clause

    const ctx = canvas.getContext('2d');
    let animationFrameId;
    let width = window.innerWidth;
    let height = window.innerHeight;
    
    // Configuration
    const NODE_COUNT = 50;
    const PACKET_COUNT = 15; // Reduced slightly for cleaner look
    const LINK_DISTANCE = 250;
    const PACKET_SPEED = 0.002; // Slowed down from 0.005

    // State
    const nodes = [];
    const links = [];
    const packets = [];

    // Resize handler
    const handleResize = () => {
      width = window.innerWidth;
      height = window.innerHeight;
      canvas.width = width;
      canvas.height = height;
    };
    
    window.addEventListener('resize', handleResize);
    handleResize();

    // Initialize Nodes
    class Node {
      constructor() {
        this.x = Math.random() * width;
        this.y = Math.random() * height;
        this.vx = (Math.random() - 0.5) * 0.2; // Slower movement (was 0.5)
        this.vy = (Math.random() - 0.5) * 0.2; // Slower movement
      }

      update() {
        this.x += this.vx;
        this.y += this.vy;

        // Bounce off edges
        if (this.x < 0 || this.x > width) this.vx *= -1;
        if (this.y < 0 || this.y > height) this.vy *= -1;
      }
    }

    // Initialize Packets
    class Packet {
      constructor(linkIndex) {
        this.linkIndex = linkIndex;
        this.progress = Math.random();
        this.speed = PACKET_SPEED + (Math.random() * 0.005);
        this.size = 2 + Math.random();
      }

      update(currentLinks) {
        this.progress += this.speed;
        if (this.progress >= 1) {
          this.progress = 0;
          // Jump to a random new link
          if (currentLinks.length > 0) {
             this.linkIndex = Math.floor(Math.random() * currentLinks.length);
          }
        }
      }
    }

    // Create Initial Nodes
    for (let i = 0; i < NODE_COUNT; i++) {
        nodes.push(new Node());
    }

    // Animation Loop
    const render = () => {
      // CLEAR instead of FILL to show CSS gradients underneath
      ctx.clearRect(0, 0, width, height);
      
      // Update Nodes
      nodes.forEach(node => node.update());

      // Re-calculate Links (dynamic topology)
      links.length = 0;
      for (let i = 0; i < nodes.length; i++) {
        for (let j = i + 1; j < nodes.length; j++) {
          const dx = nodes[i].x - nodes[j].x;
          const dy = nodes[i].y - nodes[j].y;
          const distance = Math.sqrt(dx * dx + dy * dy);

          if (distance < LINK_DISTANCE) {
            links.push({
              source: nodes[i],
              target: nodes[j],
              opacity: 1 - (distance / LINK_DISTANCE)
            });
          }
        }
      }

      // Ensure we have packets
      if (packets.length < PACKET_COUNT && links.length > 0) {
          packets.push(new Packet(Math.floor(Math.random() * links.length)));
      }

      // Draw Links ("Wires")
      ctx.lineWidth = 1;
      links.forEach(link => {
        ctx.beginPath();
        ctx.strokeStyle = `rgba(59, 130, 246, ${link.opacity * 0.15})`; // Blue-ish faint
        ctx.moveTo(link.source.x, link.source.y);
        ctx.lineTo(link.target.x, link.target.y);
        ctx.stroke();
      });

      // Draw Nodes ("Routers")
      ctx.fillStyle = 'rgba(148, 163, 184, 0.4)';
      nodes.forEach(node => {
        ctx.beginPath();
        ctx.arc(node.x, node.y, 2, 0, Math.PI * 2);
        ctx.fill();
      });

      // Draw Packets ("Data")
      packets.forEach(packet => {
        if (links[packet.linkIndex]) {
           packet.update(links);
           const link = links[packet.linkIndex];
           
           // Lerp position
           const x = link.source.x + (link.target.x - link.source.x) * packet.progress;
           const y = link.source.y + (link.target.y - link.source.y) * packet.progress;

           // Glow effect
           ctx.save();
           ctx.shadowBlur = 8;
           ctx.shadowColor = '#38bdf8'; // Cyan glow
           
           ctx.beginPath();
           ctx.fillStyle = '#38bdf8';
           ctx.arc(x, y, packet.size, 0, Math.PI * 2);
           ctx.fill();
           ctx.restore();
        }
      });

      animationFrameId = requestAnimationFrame(render);
    };

    render();

    return () => {
      window.removeEventListener('resize', handleResize);
      cancelAnimationFrame(animationFrameId);
    };
  }, []);

  return (
    <canvas 
      ref={canvasRef} 
      className="network-bg"
      style={{
        position: 'fixed',
        top: 0,
        left: 0,
        width: '100%',
        height: '100%',
        zIndex: 0, // Changed from -1 to 0 to be safe, but CSS pointer-events handles interaction
        pointerEvents: 'none',
        opacity: 0.6 // Subtle blending
      }} 
    />
  );
};

export default NetworkBackground;
