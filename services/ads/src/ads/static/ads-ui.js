/* ADS Threadline v1. Server owns state; this file only wires gestures. */
(function () {
  "use strict";

  var MAX_TEXTAREA = 168;

  function byId(id) {
    return document.getElementById(id);
  }

  function composer() {
    return byId("composer");
  }

  function draftEmpty(textarea) {
    return !textarea || textarea.value.trim().length === 0;
  }

  function sendEnabled() {
    var wrap = composer();
    if (!wrap) {
      return false;
    }
    if (wrap.dataset.inflight === "true" || wrap.dataset.session !== "true") {
      return false;
    }
    var select = wrap.querySelector('select[name="model_id"]');
    if (!select || !select.value) {
      return false;
    }
    return !draftEmpty(wrap.querySelector('textarea[name="user_input"]'));
  }

  function fitTextarea(textarea) {
    if (!textarea) {
      return;
    }
    textarea.style.height = "auto";
    textarea.style.height = Math.min(textarea.scrollHeight, MAX_TEXTAREA) + "px";
  }

  function onComposerKeydown(event) {
    if (event.key !== "Enter" || event.shiftKey) {
      return;
    }
    event.preventDefault();
    if (!sendEnabled()) {
      return;
    }
    var form = event.target.closest("form");
    if (form) {
      form.requestSubmit();
    }
  }

  function bindComposer() {
    var wrap = composer();
    if (!wrap) {
      return;
    }
    var textarea = wrap.querySelector('textarea[name="user_input"]');
    if (textarea && !textarea.dataset.bound) {
      textarea.dataset.bound = "1";
      textarea.addEventListener("input", function () {
        fitTextarea(textarea);
      });
      textarea.addEventListener("keydown", onComposerKeydown);
    }
    fitTextarea(textarea);
  }

  function bindMobileMenu() {
    var menu = byId("menu");
    var rail = byId("session-tree");
    if (!menu || !rail || menu.dataset.bound) {
      return;
    }
    menu.dataset.bound = "1";
    menu.addEventListener("click", function () {
      rail.classList.toggle("open");
    });
  }

  function openDialogs() {
    var host = byId("dialog-host");
    if (!host) {
      return;
    }
    var dialog = host.querySelector("dialog");
    if (!dialog) {
      return;
    }
    if (!dialog.open) {
      dialog.showModal();
    }
    dialog.querySelectorAll("[data-close-dialog]").forEach(function (button) {
      if (button.dataset.bound) {
        return;
      }
      button.dataset.bound = "1";
      button.addEventListener("click", function () {
        dialog.close();
        host.innerHTML = "";
      });
    });
    dialog.addEventListener("cancel", function () {
      host.innerHTML = "";
    });
  }

  function bindModelNames() {
    var form = byId("model-form");
    if (!form || form.dataset.modelNamesBound) {
      return;
    }
    var type = form.querySelector('select[name="type"]');
    var names = form.querySelector('select[name="model-name"]');
    if (!type || !names) {
      return;
    }
    form.dataset.modelNamesBound = "1";
    function syncNames() {
      Array.from(names.options).forEach(function (option) {
        var unsupported = option.value !== "" && option.dataset.modelType !== type.value;
        option.hidden = unsupported;
        option.disabled = unsupported;
      });
      if (!names.selectedOptions.length || names.selectedOptions[0].disabled) {
        names.value = "";
      }
    }
    type.addEventListener("change", syncNames);
    syncNames();
  }

  function bindAll() {
    bindComposer();
    bindMobileMenu();
    bindModelNames();
    bindEgress();
    openDialogs();
  }

  function bindEgress() {
    var form = byId("egress-form");
    if (!form || form.dataset.bound) { return; }
    form.dataset.bound = "1";
    var initial = JSON.parse(form.querySelector("[data-egress-initial]").textContent);
    var rules = form.querySelector("[data-egress-rules]");
    form.elements.mode.value = initial.mode || "whitelist";
    function field(parent, text, kind, value, options) {
      var label = document.createElement("label");
      label.appendChild(document.createTextNode(text));
      var input = document.createElement(kind === "select" ? "select" : "input");
      input.setAttribute("aria-label", text);
      if (kind !== "select") { input.type = kind; }
      (options || []).forEach(function (value) {
        var option = document.createElement("option");
        option.value = option.textContent = value;
        input.appendChild(option);
      });
      if (kind === "checkbox") { input.checked = !!value; }
      else { input.value = value; }
      label.appendChild(input);
      parent.appendChild(label);
      return input;
    }
    function button(parent, label, action) {
      var node = document.createElement("button");
      node.type = "button";
      node.className = "ghost";
      node.textContent = label;
      node.addEventListener("click", action);
      parent.appendChild(node);
    }
    function addRule(rule) {
      var box = document.createElement("fieldset");
      var legend = document.createElement("legend");
      legend.textContent = "Egress rule";
      box.appendChild(legend);
      var domain = field(box, "Domain", "text", rule.domain);
      domain.required = true;
      var port = field(box, "Port", "number", rule.port);
      port.required = true; port.min = "1"; port.max = "65535";
      var protocol = field(box, "Protocol", "select", rule.protocol, ["http", "https"]);
      var sub = field(box, "Sub-protocol", "select", rule.sub_protocol || "any",
        ["any", "http/1.1", "http/2", "websocket"]);
      var settings = rule.protocol_settings;
      var method = field(box, "Method", "select", settings.method,
        ["any", "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"]);
      var upgrades = field(box, "Upgrades", "select",
        Array.isArray(settings.upgrades) ? "selected" : settings.upgrades,
        ["any", "none", "selected"]);
      var targets = document.createElement("div");
      box.appendChild(targets);
      var targetInputs = ["http/2", "websocket"].map(function (target) {
        return field(targets, target, "checkbox",
          Array.isArray(settings.upgrades) && settings.upgrades.indexOf(target) !== -1);
      });
      function syncTargets() { targets.hidden = upgrades.value !== "selected"; }
      upgrades.addEventListener("change", syncTargets); syncTargets();
      var paths = document.createElement("div");
      box.appendChild(paths);
      function addPath(path) {
        var row = document.createElement("div");
        var pattern = field(row, "Path pattern", "text", path.pattern);
        pattern.required = true;
        var caseMode = field(row, "Case matching", "select",
          path.case_insensitive === undefined ? "mode default" :
            path.case_insensitive ? "case insensitive" : "case sensitive",
          ["mode default", "case sensitive", "case insensitive"]);
        row.egressValue = function () {
          var result = { pattern: pattern.value };
          if (caseMode.value !== "mode default") {
            result.case_insensitive = caseMode.value === "case insensitive";
          }
          return result;
        };
        button(row, "Remove path", function () { row.remove(); });
        paths.appendChild(row);
      }
      (settings.paths || []).forEach(addPath);
      button(box, "Add path", function () { addPath({ pattern: "/" }); });
      button(box, "Move up", function () {
        if (box.previousElementSibling) { rules.insertBefore(box, box.previousElementSibling); }
      });
      button(box, "Move down", function () {
        if (box.nextElementSibling) { rules.insertBefore(box.nextElementSibling, box); }
      });
      button(box, "Remove rule", function () { box.remove(); });
      box.egressValue = function () {
        var allowed = upgrades.value === "selected"
          ? ["http/2", "websocket"].filter(function (_, index) { return targetInputs[index].checked; })
          : upgrades.value;
        if (Array.isArray(allowed) && !allowed.length) {
          throw new Error("Select at least one upgrade target, or choose any / none.");
        }
        return {
          domain: domain.value, port: Number(port.value), protocol: protocol.value,
          sub_protocol: sub.value,
          protocol_settings: {
            method: method.value, upgrades: allowed,
            paths: Array.from(paths.children).map(function (row) { return row.egressValue(); })
          }
        };
      };
      rules.appendChild(box);
    }
    initial.rules.forEach(addRule);
    form.querySelector("[data-egress-add]").addEventListener("click", function () {
      addRule({ domain: "", port: 443, protocol: "https",
        protocol_settings: { method: "any", upgrades: "any", paths: [] } });
    });
    // Capture before HTMX constructs its request. Server validates the DTO independently.
    form.addEventListener("submit", function (event) {
      try {
        form.elements.settings.value = JSON.stringify({
          mode: form.elements.mode.value,
          rules: Array.from(rules.children).map(function (box) { return box.egressValue(); })
        });
        form.querySelector("[data-egress-error]").textContent = "";
      } catch (error) {
        event.preventDefault(); event.stopImmediatePropagation();
        form.querySelector("[data-egress-error]").textContent = error.message;
      }
    }, true);
    form.addEventListener("htmx:responseError", function () {
      form.querySelector("[data-egress-error]").textContent =
        "Settings could not be saved. Review the fields and try again.";
    });
  }

  /* Snapshot at swap time, not request time: the reader may scroll while GET waits. */
  var paneStates = new WeakMap();
  var TAIL_SLOP = 24;

  function capturePane(detail) {
    var pane = byId("main-pane");
    var transcript = byId("transcript");
    if (!pane || !transcript) {
      return;
    }
    var wrap = composer();
    var input = wrap && wrap.querySelector('textarea[name="user_input"]');
    var select = wrap && wrap.querySelector('select[name="model_id"]');
    var config = detail.requestConfig || {};
    var sending = String(config.verb).toLowerCase() === "post" &&
      (config.path || "").endsWith("/messages");
    var state = {
      session: pane.dataset.sessionId,
      top: transcript.scrollTop,
      left: transcript.scrollLeft,
      tail: transcript.scrollHeight - transcript.clientHeight - transcript.scrollTop <= TAIL_SLOP,
      details: [],
      anchor: null,
      draft: input ? input.value : "",
      model: select ? select.value : "",
      focus: input === document.activeElement,
      start: input ? input.selectionStart : 0,
      end: input ? input.selectionEnd : 0,
    };
    // Clear only the submitted draft, not text typed while the POST was in flight.
    if (sending && config.parameters && state.draft === config.parameters.user_input) {
      state.draft = "";
      state.start = state.end = 0;
    }
    var bounds = transcript.getBoundingClientRect();
    transcript.querySelectorAll(".turn").forEach(function (turn, turnIndex) {
      turn.querySelectorAll("details").forEach(function (item, index) {
        state.details.push({ id: turn.id, turn: turnIndex, index: index, open: item.open });
      });
      Array.from(turn.children).forEach(function (part, index) {
        var rect = part.getBoundingClientRect();
        if (!state.anchor && rect.bottom > bounds.top && rect.top < bounds.bottom) {
          state.anchor = { id: turn.id, turn: turnIndex, index: index, top: rect.top };
        }
      });
    });
    paneStates.set(detail.xhr, state);
  }

  function restorePane(event) {
    var detail = event.detail;
    var state = detail && paneStates.get(detail.xhr);
    if (!state || !detail.target || detail.target.id !== "main-pane") {
      return;
    }
    paneStates.delete(detail.xhr);
    var pane = byId("main-pane");
    var transcript = byId("transcript");
    if (!pane || !transcript || !state.session || pane.dataset.sessionId !== state.session) {
      return; // Navigation must not inherit another session's position or draft.
    }
    var turns = transcript.querySelectorAll(".turn");
    function turnFor(item) {
      return item.id ? byId(item.id) : turns[item.turn];
    }
    state.details.forEach(function (item) {
      var turn = turnFor(item);
      var node = turn && turn.querySelectorAll("details")[item.index];
      if (node) {
        node.open = item.open;
      }
    });
    var wrap = composer();
    var input = wrap && wrap.querySelector('textarea[name="user_input"]');
    var select = wrap && wrap.querySelector('select[name="model_id"]');
    if (select && Array.from(select.options).some(function (option) {
      return option.value === state.model;
    })) {
      select.value = state.model;
    }
    if (input) {
      input.value = state.draft;
      fitTextarea(input);
      if (state.focus) {
        input.focus({ preventScroll: true });
        input.setSelectionRange(state.start, state.end);
      }
    }
    transcript.scrollLeft = state.left;
    if (state.tail) {
      transcript.scrollTop = transcript.scrollHeight;
    } else {
      transcript.scrollTop = state.top;
      if (state.anchor) {
        var turn = turnFor(state.anchor);
        var anchor = turn && turn.children[state.anchor.index];
        if (anchor) {
          transcript.scrollTop += anchor.getBoundingClientRect().top - state.anchor.top;
        }
      }
    }
  }

  // beforeOnLoad bubbles from the request source even if its old target was removed.
  // Guard here so a stale response cannot apply out-of-band composer/rail fragments.
  document.addEventListener("htmx:beforeOnLoad", function (event) {
    var detail = event.detail;
    var headers = ((detail && detail.requestConfig) || {}).headers || {};
    var liveSession = headers["X-ADS-Live-Session"];
    if (liveSession && (liveSession !== currentSession() || detail.target !== byId("main-pane"))) {
      event.preventDefault();
    }
  });

  document.addEventListener("htmx:beforeSwap", function (event) {
    var detail = event.detail;
    if (!detail || !detail.target || detail.target.id !== "main-pane") {
      return;
    }
    if (detail.shouldSwap && detail.xhr.status >= 200 && detail.xhr.status < 300) {
      capturePane(detail);
    }
  });
  document.addEventListener("htmx:afterSwap", restorePane);

  /* HTMX ignores 400 by default. Only the message POST warning may swap. */
  document.addEventListener("htmx:beforeSwap", function (event) {
    var detail = event.detail;
    if (!detail || !detail.xhr || detail.xhr.status !== 400) {
      return;
    }
    var path = detail.requestConfig && detail.requestConfig.path;
    var verb = detail.requestConfig && detail.requestConfig.verb;
    if (!path || String(verb).toLowerCase() !== "post" || path.indexOf("/messages") === -1) {
      return;
    }
    var warn = byId("composer-warn");
    if (!warn) {
      return;
    }
    detail.shouldSwap = true;
    detail.isError = false;
    detail.target = warn;
    detail.swapOverride = "innerHTML";
  });

  document.addEventListener("htmx:afterSettle", bindAll);
  document.addEventListener("DOMContentLoaded", bindAll);

  /* Live channel: GET the session, then subscribe. Reconnect with backoff. */
  var socket = null;
  var retry = 500;
  var refreshing = false;
  var refreshQueued = false;

  function currentSession() {
    var wrap = composer();
    return wrap && wrap.dataset.sessionId ? wrap.dataset.sessionId : "";
  }

  function refresh() {
    var pane = byId("main-pane");
    var sessionId = currentSession();
    if (!pane || !window.htmx || !sessionId) {
      return;
    }
    if (refreshing) {
      refreshQueued = true;
      return;
    }
    refreshing = true;
    function finished() {
      refreshing = false;
      if (refreshQueued) {
        refreshQueued = false;
        refresh();
      }
    }
    window.htmx.ajax("GET", window.location.pathname, {
      target: "#main-pane",
      swap: "outerHTML",
      headers: { "X-ADS-Live-Session": sessionId },
    }).then(finished, finished);
  }

  function connect() {
    var sessionId = currentSession();
    if (!sessionId || socket) {
      return;
    }
    var scheme = window.location.protocol === "https:" ? "wss" : "ws";
    socket = new WebSocket(scheme + "://" + window.location.host + "/ws");
    socket.addEventListener("open", function () {
      retry = 500;
      socket.send(JSON.stringify({ type: "join", session_id: currentSession() }));
    });
    socket.addEventListener("message", function (event) {
      var payload = {};
      try {
        payload = JSON.parse(event.data);
      } catch (error) {
        return;
      }
      if (payload.type === "session-updated" && payload.session_id === currentSession()) {
        refresh();
      }
    });
    socket.addEventListener("close", function () {
      socket = null;
      window.setTimeout(connect, retry);
      retry = Math.min(retry * 2, 10000);
    });
    socket.addEventListener("error", function () {
      if (socket) {
        socket.close();
      }
    });
  }

  document.addEventListener("DOMContentLoaded", connect);
  document.addEventListener("htmx:afterSettle", function () {
    if (socket && socket.readyState === WebSocket.OPEN) {
      socket.send(JSON.stringify({ type: "join", session_id: currentSession() }));
    } else {
      connect();
    }
  });

  /* Search is a server query. Skip a repeat of the same needle; never filter the DOM. */
  var lastQuery = null;
  document.addEventListener("htmx:configRequest", function (event) {
    var detail = event.detail;
    if (!detail || !detail.elt || detail.elt.name !== "q") {
      return;
    }
    var value = detail.parameters.q || "";
    if (value === lastQuery) {
      event.preventDefault();
      return;
    }
    lastQuery = value;
  });
})();
