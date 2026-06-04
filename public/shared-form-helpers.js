/* ═══════════════════════════════════════════════════════════════
   DoveNest shared form helpers
   - dnPhone: international phone input (wraps intl-tel-input CDN)
   - dnCountryCity: country + city pickers (CountriesNow API)

   Usage:
     dnPhone.init(document.getElementById('inq-phone'));
     dnCountryCity.init({
       countryInput: document.getElementById('inq-country'),
       cityInput:    document.getElementById('inq-city-input'),
     });

   On submit:
     const e164 = dnPhone.getNumber(input);   // e.g. "+254712345678"
     const ok   = dnPhone.isValid(input);
   ═══════════════════════════════════════════════════════════════ */

(function () {
  'use strict';

  // ── intl-tel-input ─────────────────────────────────────────────
  const ITI_VERSION = '18.5.3';
  const ITI_BASE    = `https://cdn.jsdelivr.net/npm/intl-tel-input@${ITI_VERSION}/build`;

  let itiCssLoaded = false;
  let itiJsLoaded  = false;
  let itiJsLoading = null;

  function loadItiCss() {
    if (itiCssLoaded) return;
    itiCssLoaded = true;
    const link = document.createElement('link');
    link.rel  = 'stylesheet';
    link.href = `${ITI_BASE}/css/intlTelInput.css`;
    document.head.appendChild(link);
  }

  function loadItiJs() {
    if (itiJsLoaded) return Promise.resolve();
    if (itiJsLoading) return itiJsLoading;
    itiJsLoading = new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src   = `${ITI_BASE}/js/intlTelInput.min.js`;
      s.onload  = () => { itiJsLoaded = true; resolve(); };
      s.onerror = () => reject(new Error('Failed to load intl-tel-input'));
      document.head.appendChild(s);
    });
    return itiJsLoading;
  }

  const itiInstances = new WeakMap();

  async function initPhone(inputEl, opts) {
    if (!inputEl || itiInstances.has(inputEl)) return itiInstances.get(inputEl);
    loadItiCss();
    await loadItiJs();
    const iti = window.intlTelInput(inputEl, Object.assign({
      initialCountry:     'ke',
      preferredCountries: ['ke', 'ug', 'tz', 'rw', 'gb', 'us'],
      separateDialCode:   true,
      utilsScript:        `${ITI_BASE}/js/utils.js`,
    }, opts || {}));
    itiInstances.set(inputEl, iti);
    return iti;
  }

  window.dnPhone = {
    init: initPhone,
    getNumber(inputEl) {
      const iti = itiInstances.get(inputEl);
      return iti ? iti.getNumber() : (inputEl.value || '');
    },
    isValid(inputEl) {
      const iti = itiInstances.get(inputEl);
      if (!iti) return false;
      return iti.isValidNumber();
    },
    instance(inputEl) { return itiInstances.get(inputEl); },
  };

  // ── Country / City picker (CountriesNow API) ───────────────────
  const COUNTRIES_API = 'https://countriesnow.space/api/v0.1/countries/iso';
  const CITIES_API    = 'https://countriesnow.space/api/v0.1/countries/cities';

  let countryList = [];
  let countryLoadPromise = null;
  const cityCache = {};

  function isoToFlag(iso) {
    if (!iso || iso.length !== 2) return '';
    return iso.toUpperCase().split('').map(c => String.fromCodePoint(127397 + c.charCodeAt(0))).join('');
  }

  function loadCountries() {
    if (countryList.length > 0) return Promise.resolve(countryList);
    if (countryLoadPromise) return countryLoadPromise;
    countryLoadPromise = fetch(COUNTRIES_API)
      .then(r => r.json())
      .then(data => {
        if (data && Array.isArray(data.data)) {
          countryList = data.data
            .map(c => ({ name: c.name, iso2: c.Iso2, flag: isoToFlag(c.Iso2) }))
            .sort((a, b) => a.name.localeCompare(b.name));
        }
        return countryList;
      })
      .catch(() => { countryList = []; return []; });
    return countryLoadPromise;
  }

  function loadCities(countryName) {
    if (cityCache[countryName]) return Promise.resolve(cityCache[countryName]);
    return fetch(CITIES_API, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify({ country: countryName }),
    })
      .then(r => r.json())
      .then(data => {
        const cities = (data && Array.isArray(data.data))
          ? data.data.map(name => ({ name })).sort((a, b) => a.name.localeCompare(b.name))
          : [];
        cityCache[countryName] = cities;
        return cities;
      })
      .catch(() => { cityCache[countryName] = []; return []; });
  }

  function makeCombo(wrapperEl, getOptions, onSelect, opts) {
    opts = opts || {};
    const input    = wrapperEl.querySelector('.dn-combo-input');
    const dropdown = wrapperEl.querySelector('.dn-combo-dropdown');
    let highlighted = -1;
    let filtered    = [];

    function render(query) {
      const all = getOptions();
      const q   = (query || '').trim().toLowerCase();
      filtered  = q ? all.filter(o => o.name.toLowerCase().includes(q)) : all.slice(0, 250);
      highlighted = -1;
      if (!all.length) {
        dropdown.innerHTML = `<div class="dn-combo-empty">${opts.emptyText || 'No options available'}</div>`;
        return;
      }
      if (!filtered.length) {
        dropdown.innerHTML = `<div class="dn-combo-empty">No matches — you can also type freely</div>`;
        return;
      }
      dropdown.innerHTML = filtered.map((o, i) =>
        `<div class="dn-combo-option" data-idx="${i}">${
          o.flag ? `<span class="dn-combo-flag">${o.flag}</span>` : ''
        }<span>${o.name}</span></div>`
      ).join('');
    }

    function highlight(i) {
      const items = dropdown.querySelectorAll('.dn-combo-option');
      items.forEach(el => el.classList.remove('highlighted'));
      if (i >= 0 && items[i]) {
        items[i].classList.add('highlighted');
        items[i].scrollIntoView({ block: 'nearest' });
      }
      highlighted = i;
    }

    function select(option) {
      input.value = option.name;
      wrapperEl.classList.remove('open');
      onSelect(option);
    }

    input.addEventListener('focus', () => { render(input.value); wrapperEl.classList.add('open'); });
    input.addEventListener('input', () => { render(input.value); wrapperEl.classList.add('open'); onSelect({ name: input.value, freeText: true }); });
    input.addEventListener('blur',  () => { setTimeout(() => wrapperEl.classList.remove('open'), 150); });
    input.addEventListener('keydown', e => {
      const items = dropdown.querySelectorAll('.dn-combo-option');
      if (e.key === 'ArrowDown') { e.preventDefault(); if (items.length) highlight(Math.min(highlighted + 1, items.length - 1)); }
      else if (e.key === 'ArrowUp')   { e.preventDefault(); if (items.length) highlight(Math.max(highlighted - 1, 0)); }
      else if (e.key === 'Enter')     { if (highlighted >= 0 && filtered[highlighted]) { e.preventDefault(); select(filtered[highlighted]); } }
      else if (e.key === 'Escape')    { wrapperEl.classList.remove('open'); }
    });
    dropdown.addEventListener('mousedown', e => {
      const opt = e.target.closest('.dn-combo-option');
      if (!opt) return;
      e.preventDefault();
      const idx = parseInt(opt.dataset.idx, 10);
      if (filtered[idx]) select(filtered[idx]);
    });

    return {
      refresh() { render(input.value); },
      setLoading(on)  { wrapperEl.classList.toggle('loading', !!on); },
      setDisabled(on, placeholder) {
        input.disabled = !!on;
        if (placeholder) input.placeholder = placeholder;
      },
      clear() { input.value = ''; },
    };
  }

  function wrapAsCombo(inputEl, placeholder) {
    // Replace the input with our combobox structure
    const wrapper = document.createElement('div');
    wrapper.className = 'dn-combo';
    inputEl.classList.add('dn-combo-input');
    inputEl.setAttribute('autocomplete', 'off');
    if (placeholder) inputEl.placeholder = placeholder;
    inputEl.parentNode.insertBefore(wrapper, inputEl);
    wrapper.appendChild(inputEl);
    wrapper.insertAdjacentHTML('beforeend',
      '<svg class="dn-combo-arrow" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg>' +
      '<div class="dn-combo-spinner"></div>' +
      '<div class="dn-combo-dropdown"></div>'
    );
    return wrapper;
  }

  function initCountryCity(opts) {
    const countryInput = opts.countryInput;
    const cityInput    = opts.cityInput;
    if (!countryInput) return null;

    const countryWrap = wrapAsCombo(countryInput, opts.countryPlaceholder || 'Search country…');
    const cityWrap    = cityInput ? wrapAsCombo(cityInput, 'Select country first') : null;

    let selectedCountry = '';

    const cityCombo = cityWrap ? makeCombo(
      cityWrap,
      () => cityCache[selectedCountry] || [],
      opt => { /* free-text fine */ },
      { emptyText: 'No cities found — type freely' }
    ) : null;

    if (cityCombo) cityCombo.setDisabled(true);

    const countryCombo = makeCombo(
      countryWrap,
      () => countryList,
      opt => {
        selectedCountry = opt.name;
        if (cityCombo) {
          cityCombo.clear();
          if (opt.freeText) return;
          cityCombo.setDisabled(false, 'Search city (optional)…');
          cityCombo.setLoading(true);
          loadCities(opt.name).then(() => cityCombo.setLoading(false));
        }
      }
    );

    loadCountries().then(() => { countryCombo.refresh(); });

    return { countryCombo, cityCombo };
  }

  window.dnCountryCity = { init: initCountryCity, loadCountries, loadCities };
})();
