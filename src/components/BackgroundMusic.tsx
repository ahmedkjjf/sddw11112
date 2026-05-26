import React, { useState, useEffect } from 'react';
import ReactPlayer from 'react-player';
import { Volume2, VolumeX, Music } from 'lucide-react';
import { motion, AnimatePresence } from 'motion/react';

const Player = ReactPlayer as any;

export const BackgroundMusic = () => {
  const [isPlaying, setIsPlaying] = useState(false);
  const [isMuted, setIsMuted] = useState(false);
  const [hasStarted, setHasStarted] = useState(false);

  // Function to start music on first user interaction (browser policy)
  const handleStart = () => {
    if (!hasStarted) {
      setIsPlaying(true);
      setHasStarted(true);
    }
  };

  useEffect(() => {
    const handleInteraction = () => handleStart();
    window.addEventListener('click', handleInteraction);
    return () => window.removeEventListener('click', handleInteraction);
  }, [hasStarted]);

  // Stabilized config for ReactPlayer
  const playerConfig = React.useMemo(() => ({
    youtube: {
      playerVars: { 
        controls: 0,
        showinfo: 0,
        rel: 0,
        modestbranding: 1
      }
    }
  }), []);

  return (
    <div className="fixed bottom-6 right-6 z-[100]">
      {/* Small, transparent but present player to satisfy browser requirements */}
      <div className="opacity-0 pointer-events-none absolute w-1 h-1 overflow-hidden">
        <Player
          url="https://www.youtube.com/watch?v=BVQ_JHmvhCM"
          playing={isPlaying}
          muted={isMuted}
          loop={true}
          volume={0.5}
          playsinline={true}
          config={playerConfig}
          onStart={() => {
            setHasStarted(true);
            setIsPlaying(true);
          }}
          onReady={() => console.log("Audio Engine Ready")}
          onError={(e: any) => {
            // Silently handle common, non-fatal media errors
            const errorMsg = typeof e === 'string' ? e : (e?.message || e?.target?.error?.message || '');
            const isBenignMediaError = 
              errorMsg.toLowerCase().includes('abort') || 
              errorMsg.toLowerCase().includes('user\'s request') ||
              errorMsg.toLowerCase().includes('user agent') ||
              errorMsg.toLowerCase().includes('interrupted') ||
              e?.name === 'AbortError' ||
              e?.code === 20;
            
            if (isBenignMediaError) {
              return;
            }
            console.debug("Recoverable Audio Error:", e);
          }}
        />
      </div>

      <motion.div 
        initial={{ x: 50, opacity: 0 }}
        animate={{ x: 0, opacity: 1 }}
        className="flex items-center gap-3 bg-black/80 border border-[#00ff00]/30 p-2 backdrop-blur-md shadow-[0_0_20px_rgba(0,255,0,0.1)] rounded-full"
      >
        <AnimatePresence mode="wait">
          {!hasStarted ? (
            <motion.button
              key="start"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              exit={{ opacity: 0 }}
              onClick={handleStart}
              className="flex items-center gap-2 px-3 py-1 text-[10px] font-bold text-[#00ff00] hover:bg-[#00ff00]/10 transition-all rounded-full"
            >
              <Music className="w-3 h-3 animate-bounce" /> START_OS_AUDIO
            </motion.button>
          ) : (
            <motion.div
              key="controls"
              initial={{ opacity: 0 }}
              animate={{ opacity: 1 }}
              className="flex items-center gap-2"
            >
              <button
                onClick={() => setIsPlaying(!isPlaying)}
                className={`p-1.5 rounded-full transition-all ${isPlaying ? 'bg-[#00ff00]/20 text-[#00ff00]' : 'text-[#00ff00]/40'}`}
              >
                <Music className={`w-3.5 h-3.5 ${isPlaying ? 'animate-pulse' : ''}`} />
              </button>
              
              <div className="h-4 w-[1px] bg-[#00ff00]/20" />
              
              <button
                onClick={() => setIsMuted(!isMuted)}
                className="p-1.5 text-[#00ff00]/60 hover:text-[#00ff00] transition-colors"
              >
                {isMuted ? <VolumeX className="w-3.5 h-3.5" /> : <Volume2 className="w-3.5 h-3.5" />}
              </button>

              <div className="flex flex-col pr-2">
                <span className="text-[8px] font-bold text-[#00ff00]/40 uppercase tracking-widest leading-none">Audio</span>
                <span className="text-[10px] font-mono text-[#00ff00] leading-none">OS_AMBIENT</span>
              </div>
            </motion.div>
          )}
        </AnimatePresence>
      </motion.div>
    </div>
  );
};
