/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,ts,jsx,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['"JetBrains Mono"', '"Fira Code"', 'Consolas', 'monospace'],
        sans: [
          '"Pretendard Variable"',
          'Pretendard',
          '-apple-system',
          'BlinkMacSystemFont',
          'system-ui',
          'Roboto',
          '"Helvetica Neue"',
          '"Segoe UI"',
          '"Apple SD Gothic Neo"',
          '"Noto Sans KR"',
          'sans-serif',
        ],
      },
      colors: {
        surface: {
          950: '#050507',
          900: '#0e0e12',
          800: '#17171d',
          700: '#1f1f27',
          600: '#2a2a35',
        },
        accent: {
          green:  '#4ade80',
          cyan:   '#22d3ee',
          purple: '#a78bfa',
          amber:  '#fbbf24',
        },
      },
      animation: {
        'spin-slow': 'spin 2s linear infinite',
        blink: 'blink 1s step-end infinite',
      },
      keyframes: {
        blink: {
          '0%, 100%': { opacity: '1' },
          '50%':       { opacity: '0' },
        },
      },
    },
  },
  plugins: [],
}
