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

  function bindAll() {
    bindComposer();
    bindMobileMenu();
    openDialogs();
  }

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

  function currentSession() {
    var wrap = composer();
    return wrap && wrap.dataset.sessionId ? wrap.dataset.sessionId : "";
  }

  function refresh() {
    var pane = byId("main-pane");
    if (!pane || !window.htmx) {
      return;
    }
    window.htmx.ajax("GET", window.location.pathname, {
      target: "#main-pane",
      swap: "outerHTML",
    });
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
