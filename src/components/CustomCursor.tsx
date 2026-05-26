import React, { useEffect, useState } from 'react';
import { motion, useSpring, useMotionValue } from 'motion/react';

export const CustomCursor = () => {
  const [isVisible, setIsVisible] = useState(false);
  
  const mouseX = useMotionValue(0);
  const mouseY = useMotionValue(0);

  const springConfig = { damping: 25, stiffness: 250 };
  const cursorX = useSpring(mouseX, springConfig);
  const cursorY = useSpring(mouseY, springConfig);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      mouseX.set(e.clientX - 10);
      mouseY.set(e.clientY - 10);
      if (!isVisible) setIsVisible(true);
    };

    const handleMouseLeave = () => setIsVisible(false);
    const handleMouseEnter = () => setIsVisible(true);

    window.addEventListener('mousemove', handleMouseMove);
    document.addEventListener('mouseleave', handleMouseLeave);
    document.addEventListener('mouseenter', handleMouseEnter);

    return () => {
      window.removeEventListener('mousemove', handleMouseMove);
      document.removeEventListener('mouseleave', handleMouseLeave);
      document.removeEventListener('mouseenter', handleMouseEnter);
    };
  }, [mouseX, mouseY, isVisible]);

  return (
    <motion.div
      id="custom-cursor"
      style={{
        position: 'fixed',
        left: 0,
        top: 0,
        x: cursorX,
        y: cursorY,
        pointerEvents: 'none',
        zIndex: 9999,
        display: isVisible ? 'block' : 'none',
      }}
      className="hidden md:block" // Hide on mobile
    >
      {/* Target Crosshair */}
      <div className="relative flex items-center justify-center">
        <div className="absolute w-5 h-5 border border-[#00ff00]/40 rounded-full animate-pulse" />
        <div className="absolute w-1 h-1 bg-[#00ff00] rounded-full shadow-[0_0_10px_#00ff00]" />
        
        {/* Decorative lines */}
        <div className="absolute w-6 h-[1px] bg-[#00ff00]/20" />
        <div className="absolute h-6 w-[1px] bg-[#00ff00]/20" />
      </div>
    </motion.div>
  );
};
