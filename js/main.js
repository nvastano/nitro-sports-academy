document.addEventListener('DOMContentLoaded', () => {

  // ============ HAMBURGER MENU ============
  const hamburger = document.getElementById('hamburger');
  const mobileNav = document.getElementById('mobile-nav');
  if (hamburger && mobileNav) {
    hamburger.addEventListener('click', () => {
      hamburger.classList.toggle('open');
      mobileNav.classList.toggle('open');
    });
    document.querySelectorAll('.mobile-nav a').forEach(link => {
      link.addEventListener('click', () => {
        hamburger.classList.remove('open');
        mobileNav.classList.remove('open');
      });
    });
  }

  // ============ CONTACT FORM — sends to coach.pedro.tn@gmail.com via Formspree ============
  const form = document.getElementById('contact-form');
  if (form) {
    form.addEventListener('submit', async (e) => {
      e.preventDefault();
      const btn = form.querySelector('.form-submit');
      btn.textContent = 'Sending…';
      btn.disabled = true;

      const data = {
        name: (document.getElementById('fname').value + ' ' + document.getElementById('lname').value).trim(),
        email: document.getElementById('email').value,
        phone: document.getElementById('phone').value || 'Not provided',
        interest: document.getElementById('interest') ? document.getElementById('interest').value : 'Not specified',
        message: document.getElementById('message').value,
        _replyto: document.getElementById('email').value,
        _subject: 'New message from Nitro Sports Academy website'
      };

      try {
        const res = await fetch('https://formspree.io/f/xwvnrear', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
          body: JSON.stringify(data)
        });
        const json = await res.json();
        if (res.ok) {
          const success = document.getElementById('form-success');
          form.style.display = 'none';
          if (success) success.classList.add('show');
        } else {
          throw new Error('Submission failed');
        }
      } catch (err) {
        btn.textContent = 'Send Message ✉️';
        btn.disabled = false;
        alert('Something went wrong. Please email us directly at coach.pedro.tn@gmail.com');
      }
    });
  }

  // ============ FAQ ACCORDION ============
  document.querySelectorAll('.faq-question').forEach(q => {
    q.addEventListener('click', () => {
      const item = q.parentElement;
      const isOpen = item.classList.contains('open');
      document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
      if (!isOpen) item.classList.add('open');
    });
  });

  // ============ COUNTER ANIMATION ============
  const counters = document.querySelectorAll('.stat-number[data-count]');
  const observed = new Set();
  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && !observed.has(entry.target)) {
        observed.add(entry.target);
        const el = entry.target;
        const target = parseInt(el.dataset.count);
        const duration = 1800;
        const start = performance.now();
        const animate = (now) => {
          const progress = Math.min((now - start) / duration, 1);
          const eased = 1 - Math.pow(1 - progress, 3);
          el.textContent = Math.floor(eased * target) + (el.dataset.suffix || '');
          if (progress < 1) requestAnimationFrame(animate);
        };
        requestAnimationFrame(animate);
      }
    });
  }, { threshold: 0.3 });
  counters.forEach(el => observer.observe(el));

  // ============ FADE-IN ON SCROLL ============
  const fadeEls = document.querySelectorAll('.fade-in');
  const fadeObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('visible');
        fadeObserver.unobserve(entry.target);
      }
    });
  }, { threshold: 0.1 });
  fadeEls.forEach(el => {
    el.style.opacity = '0';
    el.style.transform = 'translateY(24px)';
    el.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
    fadeObserver.observe(el);
  });

});
