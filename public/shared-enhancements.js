/**
 * DoveNest Shared Enhancements
 * Lightweight visual polish — scroll progress, magnetic buttons,
 * enhanced reveals, animated counters, smooth scroll (Lenis-style).
 * Total: ~3 KB unminified. Zero dependencies.
 *
 * PERFORMANCE RULES:
 *   - Only animate `transform` and `opacity` (compositor-only, 60fps)
 *   - Use IntersectionObserver, never scroll-event for element visibility
 *   - requestAnimationFrame for per-frame work
 *   - will-change only on elements about to animate; removed after
 *   - Lazy-init: only set up observers when DOM is ready
 */
(function () {
    'use strict';

    /* ── 1. Scroll Progress Bar ─────────────────────────── */
    const progressBar = document.querySelector('.scroll-progress');
    if (progressBar) {
        let ticking = false;
        window.addEventListener('scroll', function () {
            if (!ticking) {
                requestAnimationFrame(function () {
                    const h = document.documentElement.scrollHeight - window.innerHeight;
                    progressBar.style.width = h > 0 ? (window.scrollY / h * 100) + '%' : '0%';
                    ticking = false;
                });
                ticking = true;
            }
        }, { passive: true });
    }

    /* ── 2. Magnetic Button Effect ──────────────────────── */
    document.querySelectorAll('.magnetic-btn').forEach(function (btn) {
        btn.addEventListener('mousemove', function (e) {
            var rect = btn.getBoundingClientRect();
            var x = e.clientX - rect.left - rect.width / 2;
            var y = e.clientY - rect.top - rect.height / 2;
            btn.style.transform = 'translate(' + (x * 0.25) + 'px,' + (y * 0.25) + 'px)';
        });
        btn.addEventListener('mouseleave', function () {
            btn.style.transform = 'translate(0,0)';
        });
    });

    /* ── 3. Enhanced Scroll Reveal (extends existing [data-reveal]) ── */
    /* Also handles .section-fade-in and .title-underline */
    var revealObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.isIntersecting) {
                entry.target.classList.add('revealed', 'visible');
                revealObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });

    document.querySelectorAll('[data-reveal], [data-reveal-stagger], .section-fade-in, .title-underline').forEach(function (el) {
        revealObserver.observe(el);
    });

    /* ── 4. Animated Counters ───────────────────────────── */
    function animateCounter(el) {
        var target = parseInt(el.getAttribute('data-count'), 10);
        if (isNaN(target)) return;
        var suffix = el.getAttribute('data-suffix') || '';
        var prefix = el.getAttribute('data-prefix') || '';
        var duration = 1800;
        var start = performance.now();

        function step(now) {
            var elapsed = now - start;
            var progress = Math.min(elapsed / duration, 1);
            // ease-out cubic
            var eased = 1 - Math.pow(1 - progress, 3);
            var current = Math.round(eased * target);
            el.textContent = prefix + current.toLocaleString() + suffix;
            if (progress < 1) requestAnimationFrame(step);
        }
        requestAnimationFrame(step);
    }

    var counterObserver = new IntersectionObserver(function (entries) {
        entries.forEach(function (entry) {
            if (entry.isIntersecting) {
                animateCounter(entry.target);
                counterObserver.unobserve(entry.target);
            }
        });
    }, { threshold: 0.3 });

    document.querySelectorAll('[data-count]').forEach(function (el) {
        counterObserver.observe(el);
    });

    /* ── 5. Smooth Scroll (lightweight Lenis-inspired) ─── */
    /* Uses native smooth scroll + CSS scroll-behavior.
       For anchor links, intercept and smooth-scroll. */
    document.querySelectorAll('a[href^="#"]').forEach(function (a) {
        a.addEventListener('click', function (e) {
            var id = a.getAttribute('href');
            if (id === '#' || id.length < 2) return;
            var target = document.querySelector(id);
            if (target) {
                e.preventDefault();
                target.scrollIntoView({ behavior: 'smooth', block: 'start' });
            }
        });
    });

    /* ── 6. Parallax-lite for [data-parallax] elements ─── */
    var parallaxEls = document.querySelectorAll('[data-parallax]');
    if (parallaxEls.length) {
        var paraTicking = false;
        window.addEventListener('scroll', function () {
            if (!paraTicking) {
                requestAnimationFrame(function () {
                    var scrollY = window.scrollY;
                    parallaxEls.forEach(function (el) {
                        var speed = parseFloat(el.getAttribute('data-parallax')) || 0.15;
                        var rect = el.getBoundingClientRect();
                        var offset = (rect.top + scrollY - window.innerHeight / 2) * speed;
                        el.style.transform = 'translateY(' + offset + 'px)';
                    });
                    paraTicking = false;
                });
                paraTicking = true;
            }
        }, { passive: true });
    }

    /* ── 7. Card tilt on hover (subtle 3D) ────────────── */
    document.querySelectorAll('.card-tilt').forEach(function (card) {
        card.addEventListener('mousemove', function (e) {
            var rect = card.getBoundingClientRect();
            var x = (e.clientX - rect.left) / rect.width - 0.5;
            var y = (e.clientY - rect.top) / rect.height - 0.5;
            card.style.transform = 'perspective(800px) rotateY(' + (x * 6) + 'deg) rotateX(' + (-y * 6) + 'deg) translateY(-4px)';
        });
        card.addEventListener('mouseleave', function () {
            card.style.transform = 'perspective(800px) rotateY(0) rotateX(0) translateY(0)';
        });
    });

}());
