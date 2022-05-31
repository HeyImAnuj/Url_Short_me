module.exports = {
  purge: [ './index.html', './src/**/*.{js,jsx,ts,tsx}' ],
  darkMode: true,
  content: [],
  theme: {
    extend: {
      fontFamily: {
        'press-start': [ '"Press Start 2P"', 'cursive' ],
        'poppins': [ 'Poppins', 'sans-serif' ],
      },
    },
  },
  plugins: [
    require('tailwind-dracula')(),
  ],
}
