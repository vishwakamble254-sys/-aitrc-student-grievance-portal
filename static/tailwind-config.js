// Tailwind Play-CDN theme (kept in a separate file so the page needs no inline scripts).
if (window.tailwind) {
  tailwind.config = {
    theme: {
      extend: {
        colors: { primary: '#4f46e5', secondary: '#312e81', accent: '#6366f1', darkBg: '#0f172a' },
        fontFamily: { sans: ['Poppins', 'sans-serif'] },
      },
    },
  };
}
