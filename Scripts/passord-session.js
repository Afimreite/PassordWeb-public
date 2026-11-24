(function () {
  'use strict';
  var form = document.querySelector('form[data-session-timeout]');
  if (!form) return;
  var left = Number(form.getAttribute('data-left-ms'));
  if (!isFinite(left) || left < 0 || left > 600000) return;
  var deadline = Date.now() + left + 250;
  var label = document.querySelector('[data-session-clock]');
  var sent = false;
  function tick() {
    if (sent) return;
    var remaining = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
    if (remaining > 0) {
      if (label) label.textContent = 'Du logges ut om ' + Math.floor(remaining / 60) + ':' + ('0' + (remaining % 60)).slice(-2) + '.';
      return;
    }
    sent = true;
    document.title = document.body.getAttribute('data-session-expired-title') || 'Økten er utløpt';
    if (label) { label.textContent = 'Økten er utløpt. Du logges ut av ID-porten.'; label.setAttribute('role', 'status'); }
    var passwords = document.querySelectorAll('input[type="password"]');
    for (var i = 0; i < passwords.length; i++) { passwords[i].value = ''; passwords[i].disabled = true; }
    var actions = document.querySelectorAll('.reset-form button');
    for (var j = 0; j < actions.length; j++) actions[j].disabled = true;
    var panels = document.querySelectorAll('.single-account, .reset-card');
    for (var k = 0; k < panels.length; k++) panels[k].style.display = 'none';
    HTMLFormElement.prototype.submit.call(form);
  }
  window.setInterval(tick, 1000);
  document.addEventListener('visibilitychange', tick);
  window.addEventListener('pageshow', tick);
  tick();
}());
