/* Edge Gateway UI - small progressive-enhancement helpers (no framework, no CDN) */
(function () {
  // confirm before destructive POST forms
  document.querySelectorAll('form[data-confirm]').forEach(function (f) {
    f.addEventListener('submit', function (e) { if (!confirm(f.dataset.confirm)) e.preventDefault(); });
  });

  // device form: show only the fields of the chosen protocol; disabled inputs are not submitted
  var proto = document.getElementById('protocol');
  if (proto) {
    var sync = function () {
      ['tcp', 'rtu'].forEach(function (p) {
        var show = proto.value.toLowerCase() === p;
        document.querySelectorAll('.' + p + '-only').forEach(function (box) {
          box.classList.toggle('hidden', !show);
          box.classList.toggle('d-none', !show);       // Bootstrap theme
          box.querySelectorAll('input,select,textarea').forEach(function (i) { i.disabled = !show; });
        });
      });
      rts();
    };
    var rts = function () {            // RTS delays only apply to "Toggle" (as in Modbus Poll)
      var r = document.getElementById('rts_control');
      document.querySelectorAll('.rts-delay').forEach(function (i) {
        i.disabled = !(r && r.value === 'Toggle' && proto.value === 'RTU');
      });
    };
    proto.addEventListener('change', sync);
    var r = document.getElementById('rts_control');
    if (r) r.addEventListener('change', rts);
    sync();
  }

  /* defineing for radio button of protocol selection */
  var proto_radio = document.querySelector('input[name="protocol"]');
  if (proto_radio) {
    var getProtocolValue = function () {
                        var selected = document.querySelector('input[name="protocol"]:checked');
            return selected ? selected.value.toLowerCase() : '';
    };

     var rts = function () {
        var r = document.getElementById('rts_control');
        document.querySelectorAll('.rts-delay').forEach(function (i) {
            i.disabled = !(r && r.value === 'Toggle' && getProtocolValue() === 'rtu');
        });
    };

    var sync = function () {
        var protocol = getProtocolValue();

        ['tcp', 'rtu'].forEach(function (p) {
            var show = protocol === p;

            document.querySelectorAll('.' + p + '-only').forEach(function (box) {
                box.classList.toggle('hidden', !show);
                box.classList.toggle('d-none', !show);

                box.querySelectorAll('input,select,textarea').forEach(function (i) {
                    i.disabled = !show;
                });
            });
        });

        rts();
    };

            document.querySelectorAll('input[name="protocol"]').forEach(function (r) {
            r.addEventListener('change', sync);
        });

            var r = document.getElementById('rts_control');
    if (r) r.addEventListener('change', rts);

    sync();


  }


  // tag form: length follows the data type
  var dt = document.getElementById('data_type'), len = document.getElementById('length'), tj = document.getElementById('dtypes');
  if (dt && len && tj) {
    var map = JSON.parse(tj.textContent);
    dt.addEventListener('change', function () { len.value = map[dt.value] || 1; });
  }


  // API log: From/To pickers only for "Custom range" (hidden inputs are disabled so they are not submitted)
  var rs = document.getElementById('range');
  if (rs) {
    var syncRange = function () {
      document.querySelectorAll('.custom-range').forEach(function (box) {
        var show = rs.value === 'custom';
        box.classList.toggle('d-none', !show);
        box.classList.toggle('hidden', !show);
        box.querySelectorAll('input').forEach(function (i) { i.disabled = !show; });
      });
    };
    rs.addEventListener('change', syncRange);
    syncRange();
  }

  // optional auto-refresh of monitoring pages
  var ar = document.getElementById('autorefresh'), timer = null;
  if (ar) {
    ar.checked = sessionStorage.getItem('autorefresh') === '1';
    var apply = function () {
      sessionStorage.setItem('autorefresh', ar.checked ? '1' : '0');
      clearInterval(timer);
      if (ar.checked) timer = setInterval(function () { location.reload(); }, 10000);
    };
    ar.addEventListener('change', apply);
    apply();
  }
})();