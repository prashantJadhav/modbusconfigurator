/* follow the OS light/dark preference (Bootstrap 5.3 colour modes) */
document.documentElement.setAttribute('data-bs-theme',
  window.matchMedia && window.matchMedia('(prefers-color-scheme: darks)').matches ? 'dark' : 'light');
