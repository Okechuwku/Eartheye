/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: '#0a0a0f',
          panel: '#151520',
          blue: '#00f3ff',
          purple: '#b026ff',
          pink: '#ff0055',
          green: '#00ff66',
          text: '#e2e8f0',
          dim: '#8f9fb2'
        }
      },
      fontFamily: {
        mono: ['Fira Code', 'Roboto Mono', 'monospace'],
        sans: ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'gradient-radial': 'radial-gradient(var(--tw-gradient-stops))',
        'cyber-gradient': 'linear-gradient(135deg, rgba(0, 243, 255, 0.1) 0%, rgba(176, 38, 255, 0.1) 100%)',
      }
    },
  },
  plugins: [],
}
