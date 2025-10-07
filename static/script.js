// ----------------- Theme Toggle -----------------
const toggle = document.getElementById('theme-toggle');
const html = document.documentElement;

function setTheme(theme) {
  html.setAttribute('data-theme', theme);
  if (theme === 'dark') {
    toggle.textContent = '☀️';
  } else {
    toggle.textContent = '🌙';
  }
  localStorage.setItem('taskzen-theme', theme);
}

if (toggle) {
  toggle.addEventListener('click', () => {
    const current = html.getAttribute('data-theme') || 'dark';
    setTheme(current === 'dark' ? 'light' : 'dark');
  });

  const stored = localStorage.getItem('taskzen-theme') || 'dark';
  setTheme(stored);
}

// ----------------- Page Fade-In Animations -----------------
document.addEventListener('DOMContentLoaded', () => {
  const fadeElems = document.querySelectorAll('.fade-in, .card, .list-group-item, .profile-card');
  fadeElems.forEach((el, i) => {
    el.style.opacity = 0;
    el.style.transform = 'translateY(15px)';
    setTimeout(() => {
      el.style.transition = 'all 0.5s ease';
      el.style.opacity = 1;
      el.style.transform = 'translateY(0)';
    }, i * 100); // stagger effect
  });
});

// ----------------- Profile Image Preview -----------------
const profileInput = document.getElementById('profile-pic-input');
const profilePreview = document.getElementById('profile-pic-preview');

if (profileInput && profilePreview) {
  profileInput.addEventListener('change', (e) => {
    const file = e.target.files[0];
    if (file) {
      const reader = new FileReader();
      reader.onload = (ev) => {
        profilePreview.src = ev.target.result;
      };
      reader.readAsDataURL(file);
    }
  });
}
