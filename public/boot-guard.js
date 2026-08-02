/* Runs before any module, because module imports are hoisted and an error
   thrown while evaluating them would otherwise be invisible: the splash would
   simply sit there with nothing to tell you. A desktop app that hangs on a
   logo is the least debuggable thing you can ship. */
(function () {
  var booted = false;

  window.__efeflowBooted = function () {
    if (booted) return;
    booted = true;
    var boot = document.getElementById("boot");
    if (!boot || boot.dataset.failed) return;
    boot.classList.add("done");
    setTimeout(function () { boot.remove(); }, 700);
  };

  function fatal(what, err) {
    var boot = document.getElementById("boot");
    if (!boot || boot.dataset.failed) return;
    boot.dataset.failed = "1";
    booted = true;
    var bar = boot.querySelector(".boot-bar");
    if (bar) bar.remove();
    var box = document.createElement("div");
    box.className = "boot-error";
    box.innerHTML = '<div class="be-t"></div><pre class="be-m"></pre>' +
                    '<div class="be-h">Ctrl+Shift+I opens the webview inspector</div>';
    box.querySelector(".be-t").textContent = what;
    box.querySelector(".be-m").textContent =
      String((err && (err.stack || err.message)) || err);
    boot.querySelector(".boot-mark").appendChild(box);
  }

  /* After boot an exception inside a click handler goes only to a console
     nobody has open, and the button just looks dead. Surface those too. */
  function runtimeError(err) {
    var bar = document.getElementById("runtime-error");
    if (!bar) {
      bar = document.createElement("div");
      bar.id = "runtime-error";
      bar.innerHTML =
        '<svg viewBox="0 0 24 24"><path d="M12 9v4m0 4h.01M10.3 3.9 2.4 17a2 2 0 0 0 1.7 3h15.8' +
        'a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/></svg>' +
        '<pre></pre><button title="Copy">copy</button><button class="x">×</button>';
      document.body.appendChild(bar);
      bar.querySelector(".x").onclick = function () { bar.remove(); };
      bar.querySelector("button:not(.x)").onclick = function () {
        navigator.clipboard && navigator.clipboard.writeText(bar.querySelector("pre").textContent);
      };
    }
    bar.querySelector("pre").textContent =
      String((err && (err.stack || err.message)) || err);
  }

  function report(err) {
    if (booted) runtimeError(err);
    else fatal("Startup failed", err);
  }
  addEventListener("error", function (e) { report(e.error || e.message); });
  addEventListener("unhandledrejection", function (e) { report(e.reason); });

  /* If the module never reaches its own dismissal, say so rather than hang. */
  setTimeout(function () {
    if (!booted) fatal("The interface did not start", "src/main.js never signalled ready.");
  }, 9000);
})();
