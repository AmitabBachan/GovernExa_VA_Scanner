import React from 'react';

interface LogoProps {
  className?: string;
  variant?: 'light' | 'dark';
  showText?: boolean;
  stacked?: boolean;
}

export const Logo: React.FC<LogoProps> = ({ 
  className = "", 
  variant = 'dark', 
  showText = true, 
  stacked = false 
}) => {
  return (
    <div className={`inline-flex items-center justify-center ${className}`}>
      <img 
        src="/logo.jpg" 
        alt="GovernExa" 
        className={stacked ? "h-32 object-contain" : "h-12 object-contain"} 
        style={{ mixBlendMode: variant === 'light' ? 'screen' : 'multiply' }} 
      />
    </div>
  );
};
