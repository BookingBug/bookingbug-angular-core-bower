(function() {
  'use strict';
  var app;

  app = angular.module('BB', ['BB.Controllers', 'BB.Filters', 'BB.Models', 'BB.Services', 'BB.Directives', 'ngStorage', 'angular-hal', 'ui.bootstrap', 'ngSanitize', 'ui.map', 'ui.router.util', 'ngLocalData', 'ngAnimate', 'angular-data.DSCacheFactory', 'angularFileUpload', 'schemaForm', 'uiGmapgoogle-maps', 'angular.filter', 'ui-rangeSlider', 'ngCookies', 'pascalprecht.translate', 'vcRecaptcha', 'slickCarousel']);

  app.value('AppConfig', {
    appId: 'f6b16c23',
    appKey: 'f0bc4f65f4fbfe7b4b3b7264b655f5eb'
  });

  app.value('AirbrakeConfig', {
    projectId: '122836',
    projectKey: 'e6d6710b2cf00be965e8452d6a384d37',
    environment: window.location.hostname === 'localhost' ? 'development' : 'production'
  });

  if (window.use_no_conflict) {
    window.bbjq = $.noConflict();
    app.value('$bbug', jQuery.noConflict(true));
  } else {
    app.value('$bbug', jQuery);
  }

  app.constant('UriTemplate', window.UriTemplate);

  app.config(function($locationProvider, $httpProvider, $provide, ie8HttpBackendProvider) {
    var int, lowercase, msie, regexp, result, webkit;
    $httpProvider.defaults.headers.common = {
      'App-Id': 'f6b16c23',
      'App-Key': 'f0bc4f65f4fbfe7b4b3b7264b655f5eb'
    };
    int = function(str) {
      return parseInt(str, 10);
    };
    lowercase = function(string) {
      if (angular.isString(string)) {
        return string.toLowerCase();
      } else {
        return string;
      }
    };
    msie = int((/msie (\d+)/.exec(lowercase(navigator.userAgent)) || [])[1]);
    if (isNaN(msie)) {
      msie = int((/trident\/.*; rv:(\d+)/.exec(lowercase(navigator.userAgent)) || [])[1]);
    }
    regexp = /Safari\/([\d.]+)/;
    result = regexp.exec(navigator.userAgent);
    if (result) {
      webkit = parseFloat(result[1]);
    }
    if ((msie && msie <= 9) || (webkit && webkit < 537)) {
      return $provide.provider({
        $httpBackend: ie8HttpBackendProvider
      });
    }
  });

  app.run(function($rootScope, $log, DebugUtilsService, FormDataStoreService, $bbug, $document, $sessionStorage, AppConfig) {
    $rootScope.$log = $log;
    $rootScope.$setIfUndefined = FormDataStoreService.setIfUndefined;
    $rootScope.bb || ($rootScope.bb = {});
    $rootScope.bb.api_url = $sessionStorage.getItem("host");
    if ($bbug.support.opacity === false) {
      document.createElement('header');
      document.createElement('nav');
      document.createElement('section');
      return document.createElement('footer');
    }
  });

  angular.module('BB.Services', ['ngResource', 'ngSanitize', 'ngLocalData']);

  angular.module('BB.Controllers', ['ngLocalData', 'ngSanitize']);

  angular.module('BB.Directives', []);

  angular.module('BB.Filters', []);

  angular.module('BB.Models', []);

  window.bookingbug = {
    logout: function(options) {
      var logout_opts;
      options || (options = {});
      if (options.reload !== false) {
        options.reload = true;
      }
      logout_opts = {
        app_id: 'f6b16c23',
        app_key: 'f0bc4f65f4fbfe7b4b3b7264b655f5eb'
      };
      if (options.root) {
        logout_opts.root = options.root;
      }
      angular.injector(['BB.Services', 'BB.Models', 'ng']).get('LoginService').logout(logout_opts);
      if (options.reload) {
        return window.location.reload();
      }
    }
  };

  moment.locale('en', {
    longDateFormat: {
      LT: "h:mm A",
      LTS: "h:mm:ss A",
      L: "MM/DD/YYYY",
      l: "M/D/YYYY",
      LL: "MMMM Do YYYY",
      ll: "MMM D YYYY",
      LLL: "MMMM Do YYYY LT",
      lll: "MMM D YYYY LT",
      LLLL: "dddd Do MMMM[,] h.mma",
      llll: "ddd, MMM D YYYY LT"
    }
  });

  if (!String.prototype.includes) {
    String.prototype.includes = function(search, start) {
      if (typeof start !== 'number') {
        start = 0;
      }
      if (start + search.length > this.length) {
        return false;
      } else {
        return this.indexOf(search, start) !== -1;
      }
    };
  }

  String.prototype.parameterise = function(seperator) {
    if (seperator == null) {
      seperator = '-';
    }
    return this.trim().replace(/\s/g, seperator).toLowerCase();
  };

}).call(this);

angular.module('BB.Services').provider("ie8HttpBackend", function ie8HttpBackendProvider() {

  this.$get = ['$browser', '$window', '$document', '$sniffer', function ie8HttpBackendFactory($browser, $window, $document, $sniffer) {
    var params = [$browser, createXhr, $browser.defer, $window.angular.callbacks, $document[0], $window.location.protocol.replace(':', ''), $sniffer];
    var param4ie = params.concat([createHttpBackend.apply(this,params)]);
    return (ieCreateHttpBackend && ieCreateHttpBackend.apply(this, param4ie)) ||
      createHttpBackend.apply(this, params);
  }];


  function ieCreateHttpBackend ($browser, XHR, $browserDefer, callbacks, rawDocument, locationProtocol, sniffer, xhr) {

    if ((sniffer.msie && sniffer.msie <= 9) || (sniffer.webkit && sniffer.webkit < 537)) {
      //console.log("create backend");
    } else {
      return null;
    }
 
    var getHostName = function (path) {
      var a = document.createElement('a');
      a.href = path;
      return a.hostname;
    }
 
    var isLocalCall = function (reqUrl) {
      var reqHost = getHostName(reqUrl),
        localHost = getHostName($browser.url());
      if (reqHost == '') return true;
 
      patt = new RegExp( localHost + "$", 'i'); 
      return patt.test(reqHost);
    }
 
    function completeRequest(callback, status, response, headersString) {
      var url = url || $browser.url(),
        URL_MATCH = /^([^:]+):\/\/(\w+:{0,1}\w*@)?(\{?[\w\.-]*\}?)(:([0-9]+))?(\/[^\?#]*)?(\?([^#]*))?(#(.*))?$/;
 
 
      // URL_MATCH is defined in src/service/location.js
      var protocol = (url.match(URL_MATCH) || ['', locationProtocol])[1];
 
      // fix status code for file protocol (it's always 0)
      status = (protocol == 'file') ? (response ? 200 : 404) : status;
 
      // normalize IE bug (http://bugs.jquery.com/ticket/1450)
      status = status == 1223 ? 204 : status;
 
      callback(status, response, headersString);
      $browser.$$completeOutstandingRequest(angular.noop);
    }
    var pmHandler = function (method, url, post, callback, headers, timeout, withCredentials) {
      var win =  $('[name="' + getHostName(url) + '"]')[0].id ;
      pm({
        target: window.frames[win],
        type: 'xhrRequest',
        data: {
          headers: headers,
          method: method,
          data: post,
          url: url
        },
        success: function (respObj) {
          headers = 'Content-Type: ' + respObj.contentType;
          if (respObj.authToken)
            headers += '\r\n' + 'Auth-Token: ' + respObj.authToken; 
          completeRequest(callback, respObj.statusCode.status, respObj.responseText, headers);
        },
        error: function (data) {
          completeRequest(callback, 500, 'Error', 'Content-Type: text/plain');
        }
      });
    }
    return function (method, url, post, callback, headers, timeout, withCredentials) {
      $browser.$$incOutstandingRequestCount();
      url = url || $browser.url();
 
      if (isLocalCall(url) ) {
        xhr(method, url, post, callback, headers, timeout, withCredentials);
      } else {
        pmHandler(method, url, post, callback, headers, timeout, withCredentials);
      }
      if (timeout > 0) {
        $browserDefer(function () {
          status = -1;
          xdr.abort();
        }, timeout);
      }
    }
 
  }


  var lowercase = function(string){return angular.isString(string) ? string.toLowerCase() : string;};

  function int(str) {
    return parseInt(str, 10);
  }

  var msie = int((/msie (\d+)/.exec(lowercase(navigator.userAgent)) || [])[1]);
  if (isNaN(msie)) {
    msie = int((/trident\/.*; rv:(\d+)/.exec(lowercase(navigator.userAgent)) || [])[1]);
  }


  function createXhr(method) {
      //if IE and the method is not RFC2616 compliant, or if XMLHttpRequest
      //is not available, try getting an ActiveXObject. Otherwise, use XMLHttpRequest
      //if it is available
      if (msie <= 8 && (!method.match(/^(get|post|head|put|delete|options)$/i) ||
        !window.XMLHttpRequest)) {
        return new window.ActiveXObject("Microsoft.XMLHTTP");
      } else if (window.XMLHttpRequest) {
        return new window.XMLHttpRequest();
      }

      throw minErr('$httpBackend')('noxhr', "This browser does not support XMLHttpRequest.");
  }

  var lowercase = function(string){return angular.isString(string) ? string.toLowerCase() : string;};

  function isPromiseLike(obj) {
    return obj && isFunction(obj.then);
  }

  function createHttpBackend($browser, createXhr, $browserDefer, callbacks, rawDocument, locationProtocol, msie) {
    var ABORTED = -1;

    // TODO(vojta): fix the signature
    return function(method, url, post, callback, headers, timeout, withCredentials, responseType) {
      var status;
      $browser.$$incOutstandingRequestCount();
      url = url || $browser.url();

      if (lowercase(method) == 'jsonp') {
        var callbackId = '_' + (callbacks.counter++).toString(36);
        callbacks[callbackId] = function(data) {
          callbacks[callbackId].data = data;
          callbacks[callbackId].called = true;
        };

        var jsonpDone = jsonpReq(url.replace('JSON_CALLBACK', 'angular.callbacks.' + callbackId),
            callbackId, function(status, text) {
          completeRequest(callback, status, callbacks[callbackId].data, "", text);
          callbacks[callbackId] = angular.noop;
        });
      } else {

        var xhr = createXhr(method);

        xhr.open(method, url, true);
        angular.forEach(headers, function(value, key) {
          if (angular.isDefined(value)) {
              xhr.setRequestHeader(key, value);
          }
        });

        // In IE6 and 7, this might be called synchronously when xhr.send below is called and the
        // response is in the cache. the promise api will ensure that to the app code the api is
        // always async
        xhr.onreadystatechange = function() {
          // onreadystatechange might get called multiple times with readyState === 4 on mobile webkit caused by
          // xhrs that are resolved while the app is in the background (see #5426).
          // since calling completeRequest sets the `xhr` variable to null, we just check if it's not null before
          // continuing
          //
          // we can't set xhr.onreadystatechange to undefined or delete it because that breaks IE8 (method=PATCH) and
          // Safari respectively.
          if (xhr && xhr.readyState == 4) {
            var responseHeaders = null,
                response = null,
                statusText = '';

            if(status !== ABORTED) {
              responseHeaders = xhr.getAllResponseHeaders();

              // responseText is the old-school way of retrieving response (supported by IE8 & 9)
              // response/responseType properties were introduced in XHR Level2 spec (supported by IE10)
              response = ('response' in xhr) ? xhr.response : xhr.responseText;
            }

            // Accessing statusText on an aborted xhr object will
            // throw an 'c00c023f error' in IE9 and lower, don't touch it.
            if (!(status === ABORTED && msie < 10)) {
              statusText = xhr.statusText;
            }

            completeRequest(callback,
                status || xhr.status,
                response,
                responseHeaders,
                statusText);
          }
        };

        if (withCredentials) {
          xhr.withCredentials = true;
        }

        if (responseType) {
          try {
            xhr.responseType = responseType;
          } catch (e) {
            // WebKit added support for the json responseType value on 09/03/2013
            // https://bugs.webkit.org/show_bug.cgi?id=73648. Versions of Safari prior to 7 are
            // known to throw when setting the value "json" as the response type. Other older
            // browsers implementing the responseType
            //
            // The json response type can be ignored if not supported, because JSON payloads are
            // parsed on the client-side regardless.
            if (responseType !== 'json') {
              throw e;
            }
          }
        }

        xhr.send(post || null);
      }

      if (timeout > 0) {
        var timeoutId = $browserDefer(timeoutRequest, timeout);
      } else if (isPromiseLike(timeout)) {
        timeout.then(timeoutRequest);
      }


      function timeoutRequest() {
        status = ABORTED;
        jsonpDone && jsonpDone();
        xhr && xhr.abort();
      }

      function completeRequest(callback, status, response, headersString, statusText) {
        // cancel timeout and subsequent timeout promise resolution
        timeoutId && $browserDefer.cancel(timeoutId);
        jsonpDone = xhr = null;

        // fix status code when it is 0 (0 status is undocumented).
        // Occurs when accessing file resources or on Android 4.1 stock browser
        // while retrieving files from application cache.
        if (status === 0) {
          status = response ? 200 : urlResolve(url).protocol == 'file' ? 404 : 0;
        }

        // normalize IE bug (http://bugs.jquery.com/ticket/1450)
        status = status === 1223 ? 204 : status;
        statusText = statusText || '';

        callback(status, response, headersString, statusText);
        $browser.$$completeOutstandingRequest(angular.noop);
      }
    };

    function jsonpReq(url, callbackId, done) {
      // we can't use jQuery/jqLite here because jQuery does crazy shit with script elements, e.g.:
      // - fetches local scripts via XHR and evals them
      // - adds and immediately removes script elements from the document
      var script = rawDocument.createElement('script'), callback = null;
      script.type = "text/javascript";
      script.src = url;
      script.async = true;

      callback = function(event) {
        removeEventListenerFn(script, "load", callback);
        removeEventListenerFn(script, "error", callback);
        rawDocument.body.removeChild(script);
        script = null;
        var status = -1;
        var text = "unknown";

        if (event) {
          if (event.type === "load" && !callbacks[callbackId].called) {
            event = { type: "error" };
          }
          text = event.type;
          status = event.type === "error" ? 404 : 200;
        }

        if (done) {
          done(status, text);
        }
      };

      addEventListenerFn(script, "load", callback);
      addEventListenerFn(script, "error", callback);

      if (msie <= 8) {
        script.onreadystatechange = function() {
          if (isString(script.readyState) && /loaded|complete/.test(script.readyState)) {
            script.onreadystatechange = null;
            callback({
              type: 'load'
            });
          }
        };
      }

      rawDocument.body.appendChild(script);
      return callback;
    }
  }

});

/**
 The MIT License

 Copyright (c) 2010 Daniel Park (http://metaweb.com, http://postmessage.freebaseapps.com)

 Permission is hereby granted, free of charge, to any person obtaining a copy
 of this software and associated documentation files (the "Software"), to deal
 in the Software without restriction, including without limitation the rights
 to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 copies of the Software, and to permit persons to whom the Software is
 furnished to do so, subject to the following conditions:

 The above copyright notice and this permission notice shall be included in
 all copies or substantial portions of the Software.

 THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 THE SOFTWARE.
 **/
var NO_JQUERY = {};
(function(window, $, undefined) {

     if (!("console" in window)) {
         var c = window.console = {};
         c.log = c.warn = c.error = c.debug = function(){};
     }

     if ($ === NO_JQUERY) {
         // jQuery is optional
         $ = {
             fn: {},
             extend: function() {
                 var a = arguments[0];
                 for (var i=1,len=arguments.length; i<len; i++) {
                     var b = arguments[i];
                     for (var prop in b) {
                         a[prop] = b[prop];
                     }
                 }
                 return a;
             }
         };
     }

     $.fn.pm = function() {
         console.log("usage: \nto send:    $.pm(options)\nto receive: $.pm.bind(type, fn, [origin])");
         return this;
     };

     // send postmessage
     $.pm = window.pm = function(options) {
         pm.send(options);
     };

     // bind postmessage handler
     $.pm.bind = window.pm.bind = function(type, fn, origin, hash, async_reply) {
         pm.bind(type, fn, origin, hash, async_reply === true);
     };

     // unbind postmessage handler
     $.pm.unbind = window.pm.unbind = function(type, fn) {
         pm.unbind(type, fn);
     };

     // default postmessage origin on bind
     $.pm.origin = window.pm.origin = null;

     // default postmessage polling if using location hash to pass postmessages
     $.pm.poll = window.pm.poll = 200;

     var pm = {

         send: function(options) {
             var o = $.extend({}, pm.defaults, options),
             target = o.target;
             if (!o.target) {
                 console.warn("postmessage target window required");
                 return;
             }
             if (!o.type) {
                 console.warn("postmessage type required");
                 return;
             }
             var msg = {data:o.data, type:o.type};
             if (o.success) {
                 msg.callback = pm._callback(o.success);
             }
             if (o.error) {
                 msg.errback = pm._callback(o.error);
             }
             if (("postMessage" in target) && !o.hash) {
                 pm._bind();
                 target.postMessage(JSON.stringify(msg), o.origin || '*');
             } else if (("postMessage" in target.contentWindow) && !o.hash) {
                pm._bind();
                target.contentWindow.postMessage(JSON.stringify(msg), o.origin || '*');
             }
             else {
                 pm.hash._bind();
                 pm.hash.send(o, msg);
             }
         },

         bind: function(type, fn, origin, hash, async_reply) {
           pm._replyBind ( type, fn, origin, hash, async_reply );
         },
       
         _replyBind: function(type, fn, origin, hash, isCallback) {
           if (("postMessage" in window) && !hash) {
               pm._bind();
           }
           else {
               pm.hash._bind();
           }
           var l = pm.data("listeners.postmessage");
           if (!l) {
               l = {};
               pm.data("listeners.postmessage", l);
           }
           var fns = l[type];
           if (!fns) {
               fns = [];
               l[type] = fns;
           }
           fns.push({fn:fn, callback: isCallback, origin:origin || $.pm.origin});
         },

         unbind: function(type, fn) {
             var l = pm.data("listeners.postmessage");
             if (l) {
                 if (type) {
                     if (fn) {
                         // remove specific listener
                         var fns = l[type];
                         if (fns) {
                             var m = [];
                             for (var i=0,len=fns.length; i<len; i++) {
                                 var o = fns[i];
                                 if (o.fn !== fn) {
                                     m.push(o);
                                 }
                             }
                             l[type] = m;
                         }
                     }
                     else {
                         // remove all listeners by type
                         delete l[type];
                     }
                 }
                 else {
                     // unbind all listeners of all type
                     for (var i in l) {
                       delete l[i];
                     }
                 }
             }
         },

         data: function(k, v) {
             if (v === undefined) {
                 return pm._data[k];
             }
             pm._data[k] = v;
             return v;
         },

         _data: {},

         _CHARS: '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'.split(''),

         _random: function() {
             var r = [];
             for (var i=0; i<32; i++) {
                 r[i] = pm._CHARS[0 | Math.random() * 32];
             };
             return r.join("");
         },

         _callback: function(fn) {
             var cbs = pm.data("callbacks.postmessage");
             if (!cbs) {
                 cbs = {};
                 pm.data("callbacks.postmessage", cbs);
             }
             var r = pm._random();
             cbs[r] = fn;
             return r;
         },

         _bind: function() {
             // are we already listening to message events on this w?
             if (!pm.data("listening.postmessage")) {
                 if (window.addEventListener) {
                     window.addEventListener("message", pm._dispatch, false);
                 }
                 else if (window.attachEvent) {
                     window.attachEvent("onmessage", pm._dispatch);
                 }
                 pm.data("listening.postmessage", 1);
             }
         },

         _dispatch: function(e) {
             //console.log("$.pm.dispatch", e, this);
             try {
                 var msg = JSON.parse(e.data);
             }
             catch (ex) {
                 console.warn("postmessage data invalid json: ", ex);
                 return;
             }
             if (!msg.type) {
                 console.warn("postmessage message type required");
                 return;
             }
             var cbs = pm.data("callbacks.postmessage") || {},
             cb = cbs[msg.type];
             if (cb) {
                 cb(msg.data);
             }
             else {
                 var l = pm.data("listeners.postmessage") || {};
                 var fns = l[msg.type] || [];
                 for (var i=0,len=fns.length; i<len; i++) {
                     var o = fns[i];
                     if (o.origin && o.origin !== '*' && e.origin !== o.origin) {
                         console.warn("postmessage message origin mismatch", e.origin, o.origin);
                         if (msg.errback) {
                             // notify post message errback
                             var error = {
                                 message: "postmessage origin mismatch",
                                 origin: [e.origin, o.origin]
                             };
                             pm.send({target:e.source, data:error, type:msg.errback});
                         }
                         continue;
                     }

                     function sendReply ( data ) {
                       if (msg.callback) {
                           pm.send({target:e.source, data:data, type:msg.callback});
                       }
                     }
                     
                     try {
                         if ( o.callback ) {
                           o.fn(msg.data, sendReply, e);
                         } else {
                           sendReply ( o.fn(msg.data, e) );
                         }
                     }
                     catch (ex) {
                         if (msg.errback) {
                             // notify post message errback
                             pm.send({target:e.source, data:ex, type:msg.errback});
                         } else {
                             throw ex;
                         }
                     }
                 };
             }
         }
     };

     // location hash polling
     pm.hash = {

         send: function(options, msg) {
             //console.log("hash.send", target_window, options, msg);
             var target_window = options.target,
             target_url = options.url;
             if (!target_url) {
                 console.warn("postmessage target window url is required");
                 return;
             }
             target_url = pm.hash._url(target_url);
             var source_window,
             source_url = pm.hash._url(window.location.href);
             if (window == target_window.parent) {
                 source_window = "parent";
             }
             else {
                 try {
                     for (var i=0,len=parent.frames.length; i<len; i++) {
                         var f = parent.frames[i];
                         if (f == window) {
                             source_window = i;
                             break;
                         }
                     };
                 }
                 catch(ex) {
                     // Opera: security error trying to access parent.frames x-origin
                     // juse use window.name
                     source_window = window.name;
                 }
             }
             if (source_window == null) {
                 console.warn("postmessage windows must be direct parent/child windows and the child must be available through the parent window.frames list");
                 return;
             }
             var hashmessage = {
                 "x-requested-with": "postmessage",
                 source: {
                     name: source_window,
                     url: source_url
                 },
                 postmessage: msg
             };
             var hash_id = "#x-postmessage-id=" + pm._random();
             target_window.location = target_url + hash_id + encodeURIComponent(JSON.stringify(hashmessage));
         },

         _regex: /^\#x\-postmessage\-id\=(\w{32})/,

         _regex_len: "#x-postmessage-id=".length + 32,

         _bind: function() {
             // are we already listening to message events on this w?
             if (!pm.data("polling.postmessage")) {
                 setInterval(function() {
                                 var hash = "" + window.location.hash,
                                 m = pm.hash._regex.exec(hash);
                                 if (m) {
                                     var id = m[1];
                                     if (pm.hash._last !== id) {
                                         pm.hash._last = id;
                                         pm.hash._dispatch(hash.substring(pm.hash._regex_len));
                                     }
                                 }
                             }, $.pm.poll || 200);
                 pm.data("polling.postmessage", 1);
             }
         },

         _dispatch: function(hash) {
             if (!hash) {
                 return;
             }
             try {
                 hash = JSON.parse(decodeURIComponent(hash));
                 if (!(hash['x-requested-with'] === 'postmessage' &&
                       hash.source && hash.source.name != null && hash.source.url && hash.postmessage)) {
                     // ignore since hash could've come from somewhere else
                     return;
                 }
             }
             catch (ex) {
                 // ignore since hash could've come from somewhere else
                 return;
             }
             var msg = hash.postmessage,
             cbs = pm.data("callbacks.postmessage") || {},
             cb = cbs[msg.type];
             if (cb) {
                 cb(msg.data);
             }
             else {
                 var source_window;
                 if (hash.source.name === "parent") {
                     source_window = window.parent;
                 }
                 else {
                     source_window = window.frames[hash.source.name];
                 }
                 var l = pm.data("listeners.postmessage") || {};
                 var fns = l[msg.type] || [];
                 for (var i=0,len=fns.length; i<len; i++) {
                     var o = fns[i];
                     if (o.origin) {
                         var origin = /https?\:\/\/[^\/]*/.exec(hash.source.url)[0];
                         if (o.origin !== '*' && origin !== o.origin) {
                             console.warn("postmessage message origin mismatch", origin, o.origin);
                             if (msg.errback) {
                                 // notify post message errback
                                 var error = {
                                     message: "postmessage origin mismatch",
                                     origin: [origin, o.origin]
                                 };
                                 pm.send({target:source_window, data:error, type:msg.errback, hash:true, url:hash.source.url});
                             }
                             continue;
                         }
                     }

                     function sendReply ( data ) {
                       if (msg.callback) {
                         pm.send({target:source_window, data:data, type:msg.callback, hash:true, url:hash.source.url});
                       }
                     }
                     
                     try {
                         if ( o.callback ) {
                           o.fn(msg.data, sendReply);
                         } else {
                           sendReply ( o.fn(msg.data) );
                         }
                     }
                     catch (ex) {
                         if (msg.errback) {
                             // notify post message errback
                             pm.send({target:source_window, data:ex, type:msg.errback, hash:true, url:hash.source.url});
                         } else {
                             throw ex;
                         }
                     }
                 };
             }
         },

         _url: function(url) {
             // url minus hash part
             return (""+url).replace(/#.*$/, "");
         }

     };

     $.extend(pm, {
                  defaults: {
                      target: null,  /* target window (required) */
                      url: null,     /* target window url (required if no window.postMessage or hash == true) */
                      type: null,    /* message type (required) */
                      data: null,    /* message data (required) */
                      success: null, /* success callback (optional) */
                      error: null,   /* error callback (optional) */
                      origin: "*",   /* postmessage origin (optional) */
                      hash: false    /* use location hash for message passing (optional) */
                  }
              });

 })(this, typeof jQuery === "undefined" ? NO_JQUERY : jQuery);

/**
 * http://www.JSON.org/json2.js
 **/
if (! ("JSON" in window && window.JSON)){JSON={}}(function(){function f(n){return n<10?"0"+n:n}if(typeof Date.prototype.toJSON!=="function"){Date.prototype.toJSON=function(key){return this.getUTCFullYear()+"-"+f(this.getUTCMonth()+1)+"-"+f(this.getUTCDate())+"T"+f(this.getUTCHours())+":"+f(this.getUTCMinutes())+":"+f(this.getUTCSeconds())+"Z"};String.prototype.toJSON=Number.prototype.toJSON=Boolean.prototype.toJSON=function(key){return this.valueOf()}}var cx=/[\u0000\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,escapable=/[\\\"\x00-\x1f\x7f-\x9f\u00ad\u0600-\u0604\u070f\u17b4\u17b5\u200c-\u200f\u2028-\u202f\u2060-\u206f\ufeff\ufff0-\uffff]/g,gap,indent,meta={"\b":"\\b","\t":"\\t","\n":"\\n","\f":"\\f","\r":"\\r",'"':'\\"',"\\":"\\\\"},rep;function quote(string){escapable.lastIndex=0;return escapable.test(string)?'"'+string.replace(escapable,function(a){var c=meta[a];return typeof c==="string"?c:"\\u"+("0000"+a.charCodeAt(0).toString(16)).slice(-4)})+'"':'"'+string+'"'}function str(key,holder){var i,k,v,length,mind=gap,partial,value=holder[key];if(value&&typeof value==="object"&&typeof value.toJSON==="function"){value=value.toJSON(key)}if(typeof rep==="function"){value=rep.call(holder,key,value)}switch(typeof value){case"string":return quote(value);case"number":return isFinite(value)?String(value):"null";case"boolean":case"null":return String(value);case"object":if(!value){return"null"}gap+=indent;partial=[];if(Object.prototype.toString.apply(value)==="[object Array]"){length=value.length;for(i=0;i<length;i+=1){partial[i]=str(i,value)||"null"}v=partial.length===0?"[]":gap?"[\n"+gap+partial.join(",\n"+gap)+"\n"+mind+"]":"["+partial.join(",")+"]";gap=mind;return v}if(rep&&typeof rep==="object"){length=rep.length;for(i=0;i<length;i+=1){k=rep[i];if(typeof k==="string"){v=str(k,value);if(v){partial.push(quote(k)+(gap?": ":":")+v)}}}}else{for(k in value){if(Object.hasOwnProperty.call(value,k)){v=str(k,value);if(v){partial.push(quote(k)+(gap?": ":":")+v)}}}}v=partial.length===0?"{}":gap?"{\n"+gap+partial.join(",\n"+gap)+"\n"+mind+"}":"{"+partial.join(",")+"}";gap=mind;return v}}if(typeof JSON.stringify!=="function"){JSON.stringify=function(value,replacer,space){var i;gap="";indent="";if(typeof space==="number"){for(i=0;i<space;i+=1){indent+=" "}}else{if(typeof space==="string"){indent=space}}rep=replacer;if(replacer&&typeof replacer!=="function"&&(typeof replacer!=="object"||typeof replacer.length!=="number")){throw new Error("JSON.stringify")}return str("",{"":value})}}if(typeof JSON.parse!=="function"){JSON.parse=function(text,reviver){var j;function walk(holder,key){var k,v,value=holder[key];if(value&&typeof value==="object"){for(k in value){if(Object.hasOwnProperty.call(value,k)){v=walk(value,k);if(v!==undefined){value[k]=v}else{delete value[k]}}}}return reviver.call(holder,key,value)}cx.lastIndex=0;if(cx.test(text)){text=text.replace(cx,function(a){return"\\u"+("0000"+a.charCodeAt(0).toString(16)).slice(-4)})}if(/^[\],:{}\s]*$/.test(text.replace(/\\(?:["\\\/bfnrt]|u[0-9a-fA-F]{4})/g,"@").replace(/"[^"\\\n\r]*"|true|false|null|-?\d+(?:\.\d*)?(?:[eE][+\-]?\d+)?/g,"]").replace(/(?:^|:|,)(?:\s*\[)+/g,""))){j=eval("("+text+")");return typeof reviver==="function"?walk({"":j},""):j}throw new SyntaxError("JSON.parse")}}}());
(function() {
  angular.module('schemaForm').config(function(schemaFormProvider, schemaFormDecoratorsProvider, sfPathProvider) {
    var datetimepicker, timepicker;
    timepicker = function(name, schema, options) {
      var f;
      if (schema.type === 'string' && (schema.format === 'time')) {
        f = schemaFormProvider.stdFormObj(name, schema, options);
        f.key = options.path;
        f.type = 'timepicker';
        options.lookup[sfPathProvider.stringify(options.path)] = f;
        return f;
      }
    };
    schemaFormProvider.defaults.string.unshift(timepicker);
    datetimepicker = function(name, schema, options) {
      var f;
      if (schema.type === 'string' && (schema.format === 'datetime')) {
        f = schemaFormProvider.stdFormObj(name, schema, options);
        f.key = options.path;
        f.type = 'datetime';
        options.lookup[sfPathProvider.stringify(options.path)] = f;
        return f;
      }
    };
    schemaFormProvider.defaults.string.unshift(datetimepicker);
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'time', 'bootstrap_ui_time_form.html');
    schemaFormDecoratorsProvider.createDirective('time', 'bootstrap_ui_time_form.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'datetime', 'bootstrap_ui_datetime_form.html');
    schemaFormDecoratorsProvider.createDirective('datetime', 'bootstrap_ui_datetime_form.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'price', 'price_form.html');
    schemaFormDecoratorsProvider.createDirective('price', 'price_form.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'date', 'date_form.html');
    schemaFormDecoratorsProvider.createDirective('date', 'date_form.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'radios', 'radios.html');
    schemaFormDecoratorsProvider.createDirective('radios', 'radios.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'radios-inline', 'radios-inline.html');
    schemaFormDecoratorsProvider.createDirective('radios-inline', 'radios-inline.html');
    schemaFormDecoratorsProvider.addMapping('bootstrapDecorator', 'radiobuttons', 'radio-buttons.html');
    return schemaFormDecoratorsProvider.createDirective('radiobuttons', 'radio-buttons.html');
  });

}).call(this);

(function() {
  window.Collection = (function() {
    function Collection() {}

    return Collection;

  })();

  window.Collection.Base = (function() {
    function Base(res, items, params) {
      var clean_params, key, m, n, val;
      this.res = res;
      this.items = items;
      this.params = params;
      this.callbacks = [];
      clean_params = {};
      for (key in params) {
        val = params[key];
        if (val != null) {
          if (val.id != null) {
            clean_params[key + "_id"] = val.id;
          } else {
            clean_params[key] = val;
          }
        }
      }
      this.jparams = JSON.stringify(clean_params);
      if (res) {
        for (n in res) {
          m = res[n];
          this[n] = m;
        }
      }
    }

    Base.prototype.checkItem = function(item) {
      var call, existingItem, i, index, j, k, len1, len2, len3, ref, ref1, ref2, results;
      if (!this.matchesParams(item)) {
        this.deleteItem(item);
        return true;
      } else {
        ref = this.items;
        for (index = i = 0, len1 = ref.length; i < len1; index = ++i) {
          existingItem = ref[index];
          if (item.self === existingItem.self) {
            this.items[index] = item;
            ref1 = this.callbacks;
            for (j = 0, len2 = ref1.length; j < len2; j++) {
              call = ref1[j];
              call[1](item, "update");
            }
            return true;
          }
        }
      }
      this.items.push(item);
      ref2 = this.callbacks;
      results = [];
      for (k = 0, len3 = ref2.length; k < len3; k++) {
        call = ref2[k];
        results.push(call[1](item, "add"));
      }
      return results;
    };

    Base.prototype.deleteItem = function(item) {
      var call, i, len, len1, ref, results;
      len = this.items.length;
      this.items = this.items.filter(function(x) {
        return x.self !== item.self;
      });
      if (this.items.length !== len) {
        ref = this.callbacks;
        results = [];
        for (i = 0, len1 = ref.length; i < len1; i++) {
          call = ref[i];
          results.push(call[1](item, "delete"));
        }
        return results;
      }
    };

    Base.prototype.getItems = function() {
      return this.items;
    };

    Base.prototype.addCallback = function(obj, fn) {
      var call, i, len1, ref;
      ref = this.callbacks;
      for (i = 0, len1 = ref.length; i < len1; i++) {
        call = ref[i];
        if (call[0] === obj) {
          return;
        }
      }
      return this.callbacks.push([obj, fn]);
    };

    Base.prototype.matchesParams = function(item) {
      return true;
    };

    return Base;

  })();

  window.BaseCollections = (function() {
    function BaseCollections() {
      this.collections = [];
    }

    BaseCollections.prototype.count = function() {
      return this.collections.length;
    };

    BaseCollections.prototype.add = function(col) {
      return this.collections.push(col);
    };

    BaseCollections.prototype.checkItems = function(item) {
      var col, i, len1, ref, results;
      ref = this.collections;
      results = [];
      for (i = 0, len1 = ref.length; i < len1; i++) {
        col = ref[i];
        results.push(col.checkItem(item));
      }
      return results;
    };

    BaseCollections.prototype.deleteItems = function(item) {
      var col, i, len1, ref, results;
      ref = this.collections;
      results = [];
      for (i = 0, len1 = ref.length; i < len1; i++) {
        col = ref[i];
        results.push(col.deleteItem(item));
      }
      return results;
    };

    BaseCollections.prototype.find = function(prms) {
      var clean_params, col, i, jprms, key, len1, ref, val;
      clean_params = {};
      for (key in prms) {
        val = prms[key];
        if (val != null) {
          if (val.id != null) {
            clean_params[key + "_id"] = val.id;
          } else {
            clean_params[key] = val;
          }
        }
      }
      jprms = JSON.stringify(clean_params);
      ref = this.collections;
      for (i = 0, len1 = ref.length; i < len1; i++) {
        col = ref[i];
        if (jprms === col.jparams) {
          return col;
        }
      }
    };

    BaseCollections.prototype["delete"] = function(col) {
      return this.collections = _.without(this.collections, col);
    };

    return BaseCollections;

  })();

}).call(this);

(function() {
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  window.Collection.Day = (function(superClass) {
    extend(Day, superClass);

    function Day() {
      return Day.__super__.constructor.apply(this, arguments);
    }

    Day.prototype.checkItem = function(item) {
      return Day.__super__.checkItem.apply(this, arguments);
    };

    return Day;

  })(window.Collection.Base);

  angular.module('BB.Services').provider("DayCollections", function() {
    return {
      $get: function() {
        return new window.BaseCollections();
      }
    };
  });

}).call(this);

(function() {
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  window.Collection.Space = (function(superClass) {
    extend(Space, superClass);

    function Space() {
      return Space.__super__.constructor.apply(this, arguments);
    }

    Space.prototype.checkItem = function(item) {
      return Space.__super__.checkItem.apply(this, arguments);
    };

    return Space;

  })(window.Collection.Base);

  angular.module('BB.Services').provider("SpaceCollections", function() {
    return {
      $get: function() {
        return new window.BaseCollections();
      }
    };
  });

}).call(this);


angular
.module('angular-hal', []).provider('data_cache', function() {
 
    this.$get = function() {
      data = [];

      return {

        set: function(key, val)
        {
          data[key] = val
          return val
        },
        get: function(key)
        {
          return data[key]
        },
        del: function(key)
        {
          delete data[key]
        },
        has: function(key)
        {
          return (key in data)
        },
        delMatching: function(str)
        {
          for (var k in data) {      
            if (k.indexOf(str) != -1)
              delete data[k]
          }
        }

      }
    };
 
})
.provider('shared_header', function() {
   this.$get = function() {
      data = {};

      return {

        set: function(key, val, store)
        {
          // also store this in the session store
          store.setItem(key, val)
          data[key] = val
          return val
        },
        get: function(key)
        {
          return data[key]
        },
        del: function(key)
        {
          delete data[key]
        },
        has: function(key)
        {
          return (key in data)
        }
      }
    };

})
.factory('halClient', [
  '$http', '$q', 'data_cache', 'shared_header', 'UriTemplate', '$cookies', '$sessionStorage', '$localStorage', function(
    $http, $q, data_cache, shared_header, UriTemplate, $cookies, $sessionStorage, $localStorage
  ){

    if ($sessionStorage.getItem('auth_token'))
      shared_header.set('auth_token', $sessionStorage.getItem('auth_token'), $sessionStorage)
    else if ($cookies['Auth-Token'] && !shared_header.has('auth_token')){
      shared_header.set('auth_token', $cookies['Auth-Token'], $sessionStorage)
    }

    return {
      setCache: function(cache) {
        data_cache = cache
      },
      clearCache: function(str) {
        data_cache.delMatching(str)
      },
      createResource: function(store)
      {
        if (typeof store === 'string') {
          store = JSON.parse(store)
        }
        resource = store.data
        resource._links = store.links
        key = store.links.self.href
        options = store.options
        return new BaseResource(key, options, resource)
      },
      $get: function(href, options){
        if(data_cache.has(href) && (!options || !options.no_cache)) return data_cache.get(href);
        return data_cache.set(href, callService('GET', href, options));
//        return callService('GET', href, options);
      }//get
      , $post: function(href, options, data){
        return callService('POST', href, options, data);
      }//post
      , $put: function(href, options, data){
        return callService('PUT', href, options, data);
      }//put
      , $patch: function(href, options, data){
        return callService('PATCH', href, options, data);
      }//patch
      , $del: function(href, options){
        return callService('DELETE', href, options);
      }//del
      , $parse: function(data){
        return parseHal(data)
      }//parse
    };



    function BaseResource(href, options, data, extra){
      if(!options) options = {};
      if(!extra) extra = {};
      var links = {};
      var embedded = data_cache
      if (data.hasOwnProperty('auth_token')) {
        options['auth_token'] = data['auth_token'];
      }

      href = getSelfLink(href, data).href;

      defineHiddenProperty(this, '$href', function(rel, params) {
        if(!(rel in links)) return null;

        return hrefLink(links[rel], params);
      });
      defineHiddenProperty(this, '$has', function(rel) {
        return rel in links;
      });
      defineHiddenProperty(this, '$flush', function(rel, params) {
        var link = links[rel];
        return flushLink(link, params);
      });
      defineHiddenProperty(this, '$get', function(rel, params){
        var link = links[rel];
        return callLink('GET', link, params);
      });
      defineHiddenProperty(this, '$post', function(rel, params, data){
        var link = links[rel];
        return callLink('POST', link, params, data);
      });
      defineHiddenProperty(this, '$put', function(rel, params, data){
        var link = links[rel];
        return callLink('PUT', link, params, data);
      });
      defineHiddenProperty(this, '$patch', function(rel, params, data){
        var link = links[rel];
        return callLink('PATCH', link, params, data);
      });
      defineHiddenProperty(this, '$del', function(rel, params){
        var link = links[rel];
        return callLink('DELETE', link, params);
      });
      defineHiddenProperty(this, '$links', function(){
        return links
      });
      defineHiddenProperty(this, '$toStore', function(){
        return JSON.stringify({data: this, links: links, options:options})
      });
      defineHiddenProperty(this, 'setOption', function(key, value){
        options[key] = value
      });
      defineHiddenProperty(this, 'getOption', function(key){
        return options[key]
      });
      defineHiddenProperty(this, '$link', function(rel){
        return links[rel]
      });

      Object.keys(data)
      .filter(function(key){
        return !~['_', '$'].indexOf(key[0]);
      })
      .forEach(function(key){
        this[key] = data[key]
//        Object.defineProperty(this, key, {
  //        configurable: false
  //        , enumerable: true
  //        , value: data[key]
   //     });
      }, this)
      ;


      if(data._links) {
        Object
        .keys(data._links)
        .forEach(function(rel){
          var link = data._links[rel];          
          link = normalizeLink(href, link);
          links[rel] = link;
        }, this)
        ;
      }

      if(data._embedded) {
        Object
        .keys(data._embedded)
        .forEach(function(rel){
          var embedded = data._embedded[rel];
          var link = getSelfLink(href, embedded);
          links[rel] = link;

          var resource = createResource(href, options, embedded);

          embedResource(resource);

        }, this);
      }

      if(extra.is_new) this.is_new = true;

      function defineHiddenProperty(target, name, value) {
        target[name] = value
//        Object.defineProperty(target, name, {
//          configurable: false
 //         , enumerable: false
  //        , value: value
   //     });
      }//defineHiddenProperty


      function embedResource(resource) {
        if(angular.isArray(resource)) return resource.map(function(resource){
          return embedResource(resource);
        });
        
        var href = resource.$href('self');

        embedded.set(href, $q.when(resource));
      }//embedResource

      function hrefLink(link, params) {
        var href = link.templated
        ? new UriTemplate(link.href).fillFromObject(params || {})
        : link.href
        ;

        return href;
      }//hrefLink

      function callLink(method, link, params, data) {

        if (params == null) {
          params = {};
        }
          
        if(angular.isArray(link)) return $q.all(link.map(function(link){
          if(method !== 'GET') throw 'method is not supported for arrays';

          return callLink(method, link, params, data);
        }));

        var linkHref = hrefLink(link, params);
        if(method === 'GET') {
          if(embedded.has(linkHref) && !params['no_cache']) {
            return embedded.get(linkHref);
          } else {
            return embedded.set(linkHref, callService(method, linkHref, options, data));
          }
        }
        else {
          return callService(method, linkHref, options, data);  
        }

      }//callLink

      function flushLink(link, params) {
        if(angular.isArray(link)) return link.map(function(link){
          return flushLink(link, params);
        });

        var linkHref = hrefLink(link, params);
        if(embedded.has(linkHref)) embedded.del(linkHref);
      }//flushLink

    }//Resource




    function createResource(href, options, data, extra){
      if(angular.isArray(data)) return data.map(function(data){
        return createResource(href, options, data, extra);
      });

      var resource = new BaseResource(href, options, data, extra);

      return resource;

    }//createResource


    function normalizeLink(baseHref, link){
      if(angular.isArray(link)) return link.map(function(link){
        return normalizeLink(baseHref, link);
      });

      if(link) {
        if(typeof link === 'string') link = { href: link };
        link.href = resolveUrl(baseHref, link.href);
      }
      else {
        link = { href: baseHref };      
      }

      return link;
    }//normalizeLink


    function getSelfLink(baseHref, resource){
      if(angular.isArray(resource)) return resource.map(function(resource){
        return getSelfLink(baseHref, resource);
      });

      return normalizeLink(baseHref, resource && resource._links && resource._links.self);
    }//getSelfLink



    function callService(method, href, options, data){
      if(!options) options = {};
      var headers = {
        'Content-Type': 'application/json',
        'Accept': 'application/hal+json,application/json'
      };
      if (options.authorization) headers.Authorization = options.authorization;
      if (options.app_id) shared_header.set('app_id', options.app_id, $sessionStorage);
      if (options.app_key) shared_header.set('app_key', options.app_key, $sessionStorage);
      if (options.auth_token) {
        $sessionStorage.setItem('auth_token', options.auth_token);
        shared_header.set('auth_token', options.auth_token, $sessionStorage);
      }

      if (shared_header.has('app_id')) headers['App-Id'] = shared_header.get('app_id');
      if (shared_header.has('app_key')) headers['App-Key'] = shared_header.get('app_key');

      if (shared_header.has('auth_token')) headers['Auth-Token'] = shared_header.get('auth_token');

      if (options.bypass_auth) headers['Bypass-Auth'] = options.bypass_auth;

      var resource = (
        $http({
          method: method
          , url: options.transformUrl ? options.transformUrl(href) : href
          , headers: headers
          , data: data
        })
        .then(function(res){

          // copy out the auth token from the header if the response is new resource
          // Note: we only take the auth token from created responses as at the app layer, success responses might be cached results, thus we don't want to use the auth token from these 
          if (res.headers('auth-token') && res.status == 201){
            options.auth_token = res.headers('Auth-Token')
            shared_header.set('auth_token', res.headers('Auth-Token'), $sessionStorage)
            // if auth token is present in local storage, set it there too
            if ($localStorage.getItem('auth_token'))
              $localStorage.setItem('auth_token', res.headers('Auth-Token'))
          }
          switch(res.status){
            case 200:
            //For back-ends that return `"null"` instead of `null` -_-
            if(res.data && res.data !== '"null"') return createResource(href, options, res.data);
            return null;

            case 201:
            extra = {is_new: true};
            if(res.data) return createResource(href, options, res.data, extra);
            if(res.headers('Content-Location')) return res.headers('Content-Location');
            return null;

            case 204:
            return null

            default:
            return $q.reject(res);
          }
        }, function(res)
        {
          return $q.reject(res);
        })
      );

      return resource;
    }//callService

    function parseHal(data){
      var resource = createResource(data._links.self.href, null, data);
      return resource;
    }//parseHal



    function resolveUrl(baseHref, href){
      var resultHref = '';
      var reFullUrl = /^((?:\w+\:)?)((?:\/\/)?)([^\/]*)((?:\/.*)?)$/;
      var baseHrefMatch = reFullUrl.exec(baseHref);
      var hrefMatch = reFullUrl.exec(href);

      for(var partIndex = 1; partIndex < 5; partIndex++) {
        if(hrefMatch[partIndex]) resultHref += hrefMatch[partIndex];
        else resultHref += baseHrefMatch[partIndex]
      }

      return resultHref;
    }//resolveUrl

  }
])//service
;

angular.module('ngStorage', [])
.factory('$fakeStorage', [
  '$cookies',
  function($cookies){
    function FakeStorage() {};
    FakeStorage.prototype.setItem = function (key, value) {
      $cookies[key] = value;
    };
    FakeStorage.prototype.getItem = function (key) {
      return typeof $cookies[key] == 'undefined' ? null : $cookies[key];
    }
    FakeStorage.prototype.removeItem = function (key) {
      if ($cookies[key]){
        delete $cookies[key];
      }
    };
    FakeStorage.prototype.clear = function(){
      for (var key in $cookies) {
        if( $cookies.hasOwnProperty(key) )
        {
          delete $cookies[key];
        }
      }
    };
    FakeStorage.prototype.key = function(index){
      return Object.keys($cookies)[index];
    };
    return new FakeStorage();
  }
])
.factory('$localStorage', [
  '$window', '$fakeStorage',
  function($window, $fakeStorage) {
    function isStorageSupported(storageName) 
    {
      var testKey = 'test',
        storage = $window[storageName];
      try
      {
        storage.setItem(testKey, '1');
        storage.removeItem(testKey);
        return true;
      } 
      catch (error) 
      {
        return false;
      }
    }
    var storage = isStorageSupported('localStorage') ? $window.localStorage : $fakeStorage;
    return {
      setItem: function(key, value) {
        storage.setItem(key, value);
      },
      getItem: function(key, defaultValue) {
        return storage.getItem(key) || defaultValue;
      },
      setObject: function(key, value) {
        storage.setItem(key, JSON.stringify(value));
      },
      getObject: function(key) {
        return JSON.parse(storage.getItem(key) || '{}');
      },
      removeItem: function(key){
        storage.removeItem(key);
      },
      clear: function() {
        storage.clear();
      },
      key: function(index){
        storage.key(index);
      }
    }
  }
])
.factory('$sessionStorage', [
  '$window', '$fakeStorage',
  function($window, $fakeStorage) {
    function isStorageSupported(storageName) 
    {
      var testKey = 'test',
        storage = $window[storageName];
      try
      {
        storage.setItem(testKey, '1');
        storage.removeItem(testKey);
        return true;
      } 
      catch (error) 
      {
        return false;
      }
    }
    var storage = isStorageSupported('sessionStorage') ? $window.sessionStorage : $fakeStorage;
    return {
      setItem: function(key, value) {
        storage.setItem(key, value);
      },
      getItem: function(key, defaultValue) {
        return storage.getItem(key) || defaultValue;
      },
      setObject: function(key, value) {
        storage.setItem(key, JSON.stringify(value));
      },
      getObject: function(key) {
        return JSON.parse(storage.getItem(key) || '{}');
      },
      removeItem: function(key){
        storage.removeItem(key);
      },
      clear: function() {
        storage.clear();
      },
      key: function(index){
        storage.key(index);
      }
    }
  }
]);
/**!
 * AngularJS file upload/drop directive with http post and progress
 * @author  Danial  <danial.farid@gmail.com>
 * @version 1.4.0
 */
(function() {
  
var angularFileUpload = angular.module('angularFileUpload', []);

angularFileUpload.service('$upload', ['$http', '$timeout', function($http, $timeout) {
  function sendHttp(config) {
    config.method = config.method || 'POST';
    config.headers = config.headers || {};
    config.transformRequest = config.transformRequest || function(data, headersGetter) {
      if (window.ArrayBuffer && data instanceof window.ArrayBuffer) {
        return data;
      }
      return $http.defaults.transformRequest[0](data, headersGetter);
    };

    if (window.XMLHttpRequest.__isShim) {
      config.headers['__setXHR_'] = function() {
        return function(xhr) {
          if (!xhr) return;
          config.__XHR = xhr;
          config.xhrFn && config.xhrFn(xhr);
          xhr.upload.addEventListener('progress', function(e) {
            if (config.progress) {
              $timeout(function() {
                if(config.progress) config.progress(e);
              });
            }
          }, false);
          //fix for firefox not firing upload progress end, also IE8-9
          xhr.upload.addEventListener('load', function(e) {
            if (e.lengthComputable) {
              if(config.progress) config.progress(e);
            }
          }, false);
        };
      };
    }

    var promise = $http(config);

    promise.progress = function(fn) {
      config.progress = fn;
      return promise;
    };
    promise.abort = function() {
      if (config.__XHR) {
        $timeout(function() {
          config.__XHR.abort();
        });
      }
      return promise;
    };
    promise.xhr = function(fn) {
      config.xhrFn = fn;
      return promise;
    };
    promise.then = (function(promise, origThen) {
      return function(s, e, p) {
        config.progress = p || config.progress;
        var result = origThen.apply(promise, [s, e, p]);
        result.abort = promise.abort;
        result.progress = promise.progress;
        result.xhr = promise.xhr;
        result.then = promise.then;
        return result;
      };
    })(promise, promise.then);
    
    return promise;
  }

  this.upload = function(config) {
    config.headers = config.headers || {};
    config.headers['Content-Type'] = undefined;
    config.transformRequest = config.transformRequest || $http.defaults.transformRequest;
    var formData = new FormData();
    var origTransformRequest = config.transformRequest;
    var origData = config.data;
    config.transformRequest = function(formData, headerGetter) {
      if (origData) {
        if (config.formDataAppender) {
          for (var key in origData) {
            var val = origData[key];
            config.formDataAppender(formData, key, val);
          }
        } else {
          for (var key in origData) {
            var val = origData[key];
            if (typeof origTransformRequest == 'function') {
              val = origTransformRequest(val, headerGetter);
            } else {
              for (var i = 0; i < origTransformRequest.length; i++) {
                var transformFn = origTransformRequest[i];
                if (typeof transformFn == 'function') {
                  val = transformFn(val, headerGetter);
                }
              }
            }
            formData.append(key, val);
          }
        }
      }

      if (config.file != null) {
        var fileFormName = config.fileFormDataName || 'file';

        if (Object.prototype.toString.call(config.file) === '[object Array]') {
          var isFileFormNameString = Object.prototype.toString.call(fileFormName) === '[object String]'; 
          for (var i = 0; i < config.file.length; i++) {
            formData.append(isFileFormNameString ? fileFormName + i : fileFormName[i], config.file[i], config.file[i].name);
          }
        } else {
          formData.append(fileFormName, config.file, config.file.name);
        }
      }
      return formData;
    };

    config.data = formData;

    return sendHttp(config);
  };

  this.http = function(config) {
    return sendHttp(config);
  }
}]);

angularFileUpload.directive('ngFileSelect', [ '$parse', '$timeout', function($parse, $timeout) {
  return function(scope, elem, attr) {
    var fn = $parse(attr['ngFileSelect']);
    elem.bind('change', function(evt) {
      var files = [], fileList, i;
      fileList = evt.target.files;
      if (fileList != null) {
        for (i = 0; i < fileList.length; i++) {
          files.push(fileList.item(i));
        }
      }
      $timeout(function() {
        fn(scope, {
          $files : files,
          $event : evt
        });
      });
    });
    // removed this since it was confusing if the user click on browse and then cancel #181
//    elem.bind('click', function(){
//      this.value = null;
//    });
    
    // touch screens
    if (('ontouchstart' in window) ||
        (navigator.maxTouchPoints > 0) || (navigator.msMaxTouchPoints > 0)) {
      elem.bind('touchend', function(e) {
        e.preventDefault();
        e.target.click();
      });
    }
  };
} ]);

angularFileUpload.directive('ngFileDropAvailable', [ '$parse', '$timeout', function($parse, $timeout) {
  return function(scope, elem, attr) {
    if ('draggable' in document.createElement('span')) {
      var fn = $parse(attr['ngFileDropAvailable']);
      $timeout(function() {
        fn(scope);
      });
    }
  };
} ]);

angularFileUpload.directive('ngFileDrop', [ '$parse', '$timeout', function($parse, $timeout) {
  return function(scope, elem, attr) {    
    if ('draggable' in document.createElement('span')) {
      var cancel = null;
      var fn = $parse(attr['ngFileDrop']);
      elem[0].addEventListener("dragover", function(evt) {
        $timeout.cancel(cancel);
        evt.stopPropagation();
        evt.preventDefault();
        elem.addClass(attr['ngFileDragOverClass'] || "dragover");
      }, false);
      elem[0].addEventListener("dragleave", function(evt) {
        cancel = $timeout(function() {
          elem.removeClass(attr['ngFileDragOverClass'] || "dragover");
        });
      }, false);
      
      var processing = 0;
      function traverseFileTree(files, item) {
        if (item.isDirectory) {
          var dirReader = item.createReader();
          processing++;
          dirReader.readEntries(function(entries) {
            for (var i = 0; i < entries.length; i++) {
              traverseFileTree(files, entries[i]);
            }
            processing--;
          });
        } else {
          processing++;
              item.file(function(file) {
                processing--;
                files.push(file);
              });
          }
      }
      
      elem[0].addEventListener("drop", function(evt) {
        evt.stopPropagation();
        evt.preventDefault();
        elem.removeClass(attr['ngFileDragOverClass'] || "dragover");
        var files = [], items = evt.dataTransfer.items;
        if (items && items.length > 0 && items[0].webkitGetAsEntry) {
          for (var i = 0; i < items.length; i++) {
            traverseFileTree(files, items[i].webkitGetAsEntry());
          }
        } else {
          var fileList = evt.dataTransfer.files;
          if (fileList != null) {
            for (var i = 0; i < fileList.length; i++) {
              files.push(fileList.item(i));
            }
          }
        }
        (function callback(delay) {
          $timeout(function() {
            if (!processing) {
              fn(scope, {
                $files : files,
                $event : evt
              });
            } else {
              callback(10);
            }
          }, delay || 0)
        })();
      }, false);
    }
  };
} ]);

})();
// THIS DOESN'T APPEAR TO BE USED?
angular.module('ngLocalData', ['angular-hal']).
 factory('$localCache', ['halClient', '$q', '$sessionStorage', function( halClient, $q, $sessionStorage) {
    data = {};

    jsonData = function(data) {
        return data && JSON.parse(data);
    }

    storage = function()
    {
      return $sessionStorage
    } 
    localSave = function(key, item){
      storage().setItem(key, item.$toStore())   
    } 
    localLoad = function(key){
      res =  jsonData(storage().getItem(key))
      if (res)
      {  
        r = halClient.createResource(res)
        def = $q.defer()
        def.resolve(r)
        return def.promise
      }
      return null
    } 
    localDelete = function(key) {
      storage().removeItem(key)
    }

    return {

      set: function(key, val)
      {
        data[key] = val
        val.then(function(item){
          localSave(key, item)
        })
        return val
      },
      get: function(key)
      {
        localLoad(key)
        if (!data[key])
          data[key] = localLoad(key)
        return data[key]
      },
      del: function(key)
      {
        localDelete(key)
        delete data[key]
      },
      has: function(key)
      {
        if (!data[key])
        { 
          res = localLoad(key)
          if (res)
            data[key] = res
        }
        return (key in data)
      }      
    }

}]).
 factory('$localData', ['$http', '$rootScope', '$sessionStorage', function($http, $rootScope, $sessionStorage) {
    function LocalDataFactory(name) {
      function LocalData(value){
        this.setStore(value);
      }

      LocalData.prototype.jsonData = function(data) {
          return data && JSON.parse(data);
      }

      LocalData.prototype.storage = function()
      {
        return $sessionStorage
      }  

      LocalData.prototype.localSave = function(item)
      {
        this.storage().setItem(this.store_name + item.id, JSON.stringify(item))
      }


      LocalData.prototype.localSaveIndex = function(ids)
      {
        this.storage().setItem(this.store_name, ids.join(","))
        this.ids = ids;
      }

      LocalData.prototype.localLoadIndex = function()
      {
        store = this.storage().getItem(this.store_name)
        records = (store && store.split(",")) || [];
        return records
      }

      LocalData.prototype.localLoad = function( id)
      {
        return this.jsonData(this.storage().getItem(this.store_name + id))
      }

      LocalData.prototype.count = function()
      {
        return this.ids.length
      }

      LocalData.prototype.setStore = function(name)
      {
        this.store_name = name;
        this.data_store = []
        this.ids = this.localLoadIndex();
        for (a = 0; a < this.ids.length; a++){
          this.data_store.push(this.localLoad(this.ids[a]));
        }
    //    var channel = pusher.subscribe(name);
    //    var ds = this;

     //   channel.bind('add', function(data) {
     //     ds.data_store.push(data);
     //     $rootScope.$broadcast("Refresh_" + ds.store_name, "Updated");          
     //   });

      }

      LocalData.prototype.update = function(data)
      {
        ids = []
        for (x in data){
          if (data[x].id){
           ids.push(data[x].id)
           this.localSave(data[x])
         }
        }
        this.localSaveIndex(ids)
      }

      return new LocalData(name)

    };


    
    return LocalDataFactory
}]);


/* Usefull javascript functions usable directly withing html views - often for getting scope related data */

getControllerScope = function(controller, fn){
  $(document).ready(function(){
    var $element = $('div[data-ng-controller="' + controller + '"]');
    var scope = angular.element($element).scope();
    fn(scope); 
  });
}


function getURIparam( name ){
  name = name.replace(/[\[]/,"\\\[").replace(/[\]]/,"\\\]");
  var regexS = "[\\?&]"+name+"=([^&#]*)";
  var regex = new RegExp( regexS );
  var results = regex.exec( window.location.href );
  if( results == null )
    return "";
  else
    return results[1];
}
(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbAccordianRangeGroup
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of accordian range group for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash} bbAccordianRangeGroup  A hash of options
  * @property {boolean} collaspe_when_time_selected Collapse when time is selected
  * @property {string} setRange Set time range for start and end
  * @property {string} start_time The start time
  * @property {string} end_time The end time
  * @property {array} accordian_slots The accordian slots
  * @property {boolean} is_open Time is open
  * @property {boolean} has_availability Group has have availability
  * @property {boolean} is_selected Group is selected
  * @property {string} source_slots Source of slots
  * @property {boolean} selected_slot Range group selected slot
  * @property {boolean} hideHeading Range group hide heading
   */
  angular.module('BB.Directives').directive('bbAccordianRangeGroup', function(PathSvc) {
    return {
      restrict: 'AE',
      replace: false,
      scope: true,
      require: '^?bbTimeRangeStacked',
      controller: 'AccordianRangeGroup',
      templateUrl: function(element, attrs) {
        return PathSvc.directivePartial("_accordian_range_group");
      },
      link: function(scope, element, attrs, ctrl) {
        scope.options = scope.$eval(attrs.bbAccordianRangeGroup) || {};
        return scope.options.using_stacked_items = ctrl != null;
      }
    };
  });

  angular.module('BB.Controllers').controller('AccordianRangeGroup', function($scope, $attrs, $rootScope, $q, FormDataStoreService) {
    var hasAvailability, setData, updateAvailability;
    $scope.controller = "public.controllers.AccordianRangeGroup";
    $scope.collaspe_when_time_selected = true;
    $rootScope.connection_started.then(function() {
      if ($scope.options && $scope.options.range) {
        return $scope.init($scope.options.range[0], $scope.options.range[1], $scope.options);
      }
    });

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Set form data store by id
    *
    * @param {object} id Id that sets store form data
     */
    $scope.setFormDataStoreId = function(id) {
      return FormDataStoreService.init('AccordianRangeGroup' + id, $scope, []);
    };

    /***
    * @ngdoc method
    * @name init
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Initialization of start time, end time and options
    *
    * @param {date} start_time The start time of the range group
    * @param {date} end_time The end time of the range group
    * @param {object} options The options of the range group
     */
    $scope.init = function(start_time, end_time, options) {
      $scope.setRange(start_time, end_time);
      $scope.collaspe_when_time_selected = options && !options.collaspe_when_time_selected ? false : true;
      return $scope.heading = options.heading ? options.heading : void 0;
    };

    /***
    * @ngdoc method
    * @name setRange
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Set range of start time and end time
    *
    * @param {date} start_time The start time of the range group
    * @param {date} end_time The end time of the range group
     */
    $scope.setRange = function(start_time, end_time) {
      if (!$scope.options) {
        $scope.options = $scope.$eval($attrs.bbAccordianRangeGroup) || {};
      }
      $scope.start_time = start_time;
      $scope.end_time = end_time;
      return setData();
    };

    /***
    * @ngdoc method
    * @name setData
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Set this data as ready
     */
    setData = function() {
      var i, key, len, ref, ref1, slot;
      $scope.accordian_slots = [];
      $scope.is_open = $scope.is_open || false;
      $scope.has_availability = $scope.has_availability || false;
      $scope.is_selected = $scope.is_selected || false;
      if ($scope.options && $scope.options.slots) {
        $scope.source_slots = $scope.options.slots;
      } else if ($scope.day && $scope.day.slots) {
        $scope.source_slots = $scope.day.slots;
      } else {
        $scope.source_slots = null;
      }
      if ($scope.source_slots) {
        if (angular.isArray($scope.source_slots)) {
          ref = $scope.source_slots;
          for (i = 0, len = ref.length; i < len; i++) {
            slot = ref[i];
            if (slot.time >= $scope.start_time && slot.time < $scope.end_time && slot.avail === 1) {
              $scope.accordian_slots.push(slot);
            }
          }
        } else {
          ref1 = $scope.source_slots;
          for (key in ref1) {
            slot = ref1[key];
            if (slot.time >= $scope.start_time && slot.time < $scope.end_time && slot.avail === 1) {
              $scope.accordian_slots.push(slot);
            }
          }
        }
        return updateAvailability();
      }
    };

    /***
    * @ngdoc method
    * @name updateAvailability
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Update availability of the slot
    *
    * @param {date} day The day of range group
    * @param {string} slot The slot of range group
     */
    updateAvailability = function(day, slot) {
      var i, len, ref;
      $scope.selected_slot = null;
      if ($scope.accordian_slots) {
        $scope.has_availability = hasAvailability();
      }
      if (day && slot) {
        if (day.date.isSame($scope.day.date) && slot.time >= $scope.start_time && slot.time < $scope.end_time) {
          $scope.selected_slot = slot;
        }
      } else {
        ref = $scope.accordian_slots;
        for (i = 0, len = ref.length; i < len; i++) {
          slot = ref[i];
          if (slot.selected) {
            $scope.selected_slot = slot;
            break;
          }
        }
      }
      if ($scope.selected_slot) {
        $scope.hideHeading = true;
        $scope.is_selected = true;
        if ($scope.collaspe_when_time_selected) {
          return $scope.is_open = false;
        }
      } else {
        $scope.is_selected = false;
        if ($scope.collaspe_when_time_selected) {
          return $scope.is_open = false;
        }
      }
    };

    /***
    * @ngdoc method
    * @name hasAvailability
    * @methodOf BB.Directives:bbAccordianRangeGroup
    * @description
    * Verify if availability of accordian slots have a slot
     */
    hasAvailability = function() {
      var i, len, ref, slot;
      if (!$scope.accordian_slots) {
        return false;
      }
      ref = $scope.accordian_slots;
      for (i = 0, len = ref.length; i < len; i++) {
        slot = ref[i];
        if (slot.availability() > 0) {
          return true;
        }
      }
      return false;
    };
    $scope.$on('slotChanged', function(event, day, slot) {
      if (day && slot) {
        return updateAvailability(day, slot);
      } else {
        return updateAvailability();
      }
    });
    return $scope.$on('dataReloaded', function(event, earliest_slot) {
      return setData();
    });
  });

}).call(this);


/***
* @ngdoc directive
* @name BB.Directives:bbAddresses
* @restrict AE
* @scope true
*
* @description
*
* Loads a list of addresses for the currently in scope company
*
* <pre>
* restrict: 'AE'
* replace: true
* scope: true
* </pre>
*
* @property {boolean} manual_postcode_entry The manual postcode entry of the address
* @property {string} address1 The first address of the client
* @property {string} address2 The second address of the client
* @property {string} address3 The third address of the client
* @property {string} address4 The fourth address of the client
* @property {string} address5 The fifth address of the client
* @property {boolean} show_complete_address Display complete address of the client
* @property {boolean} postcode_submitted Postcode of the client has been submitted
* @property {string} findByPostcode Find address by postcode
* @property {string} setLoaded Set loaded address list
* @property {string} notLoaded Address list not loaded
 */

(function() {
  angular.module('BB.Directives').directive('bbAddresses', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'AddressList'
    };
  });

  angular.module('BB.Controllers').controller('AddressList', function($scope, $rootScope, $filter, $sniffer, AddressListService, FormDataStoreService) {
    $scope.controller = "public.controllers.AddressList";
    $scope.manual_postcode_entry = false;
    FormDataStoreService.init('AddressList', $scope, ['show_complete_address']);
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.client.postcode && !$scope.bb.postcode) {
          $scope.bb.postcode = $scope.client.postcode;
        }
        if ($scope.client.postcode && $scope.bb.postcode && $scope.client.postcode === $scope.bb.postcode && !$scope.bb.address1) {
          $scope.bb.address1 = $scope.client.address1;
          $scope.bb.address2 = $scope.client.address2;
          $scope.bb.address3 = $scope.client.address3;
          $scope.bb.address4 = $scope.client.address4;
          $scope.bb.address5 = $scope.client.address5;
        }
        $scope.manual_postcode_entry = !$scope.bb.postcode ? true : false;
        $scope.show_complete_address = $scope.bb.address1 ? true : false;
        if (!$scope.postcode_submitted) {
          $scope.findByPostcode();
          return $scope.postcode_submitted = false;
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name findByPostcode
    * @methodOf BB.Directives:bbAddresses
    * @description
    * Make a request for a list of addresses. They come as seperate list of objects containing addresses and monikers, which are converted into a single list of objects containing both properties.
     */
    $scope.findByPostcode = function() {
      $scope.postcode_submitted = true;
      if (!$scope.bb.postcode) {
        return;
      }
      $scope.notLoaded($scope);
      return AddressListService.query({
        company: $scope.bb.company,
        post_code: $scope.bb.postcode
      }).then(function(response) {
        var addressArr, newaddr;
        if (angular.isArray(response)) {
          addressArr = _.map(response, function(item, i) {
            return {
              address: item.partialAddress,
              moniker: item.moniker
            };
          });
        } else {
          addressArr = [
            {
              address: response.partialAddress,
              moniker: response.moniker
            }
          ];
        }
        if (addressArr.length === 1 && $sniffer.msie) {
          newaddr = [];
          newaddr.push(addressArr[0]);
          newaddr.push({
            address: ''
          });
          addressArr = newaddr;
        }
        $scope.addresses = addressArr;
        $scope.bb.address = addressArr[0];
        $scope.client.address = addressArr[0];
        $scope.setLoaded($scope);
      }, function(err) {
        $scope.show_complete_address = true;
        $scope.postcode_submitted = true;
        return $scope.setLoaded($scope);
      });
    };

    /***
    * @ngdoc method
    * @name showCompleteAddress
    * @methodOf BB.Directives:bbAddresses
    * @description
    * Show complete address
     */
    $scope.showCompleteAddress = function() {
      $scope.show_complete_address = true;
      $scope.postcode_submitted = false;
      if ($scope.bb.address && $scope.bb.address.moniker) {
        $scope.notLoaded($scope);
        return AddressListService.getAddress({
          company: $scope.bb.company,
          id: $scope.bb.address.moniker
        }).then(function(response) {
          var address, address2, address3, addressLine2, building_number, house_number, streetName;
          address = response;
          house_number = '';
          if (typeof address.buildingNumber === 'string') {
            house_number = address.buildingNumber;
          } else if (address.buildingNumber == null) {
            house_number = address.buildingName;
          }
          if (typeof address.streetName === 'string') {
            streetName = address.streetName ? address.streetName : '';
            $scope.bb.address1 = house_number + ' ' + streetName;
          } else {
            addressLine2 = address.addressLine2 ? address.addressLine2 : '';
            $scope.bb.address1 = house_number + ' ' + addressLine2;
          }
          if (address.buildingName && (address.buildingNumber == null)) {
            $scope.bb.address1 = house_number;
            $scope.bb.address2 = address.streetName;
            if (address.county != null) {
              $scope.bb.address4 = address.county;
            }
          }
          if (typeof address.buildingNumber === 'string' && typeof address.buildingName === 'string' && typeof address.streetName === 'string') {
            streetName = address.streetName ? address.streetName : '';
            $scope.bb.address1 = address.buildingName;
            $scope.bb.address2 = address.buildingNumber + " " + streetName;
          }
          if ((address.buildingName != null) && address.buildingName.match(/(^[^0-9]+$)/)) {
            building_number = address.buildingNumber ? address.buildingNumber : '';
            $scope.bb.address1 = address.buildingName + " " + building_number;
            $scope.bb.address2 = address.streetName;
          }
          if ((address.buildingNumber == null) && (address.streetName == null)) {
            $scope.bb.address1 = address.buildingName;
            $scope.bb.address2 = address.addressLine3;
            $scope.bb.address4 = address.town;
          }
          if (address.companyName != null) {
            $scope.bb.address1 = address.companyName;
            if ((address.buildingNumber == null) && (address.streetName == null)) {
              $scope.bb.address2 = address.addressLine3;
            } else if (address.buildingNumber == null) {
              address2 = address.buildingName ? address.buildingName + ', ' + address.streetName : address.streetName;
              $scope.bb.address2 = address2;
            } else if ((address.buildingName == null) && (address.addressLine2 == null)) {
              $scope.bb.address2 = address.buildingNumber + ", " + address.streetName;
            } else {
              $scope.bb.address2 = address.buildingName;
            }
            $scope.bb.address3 = address.buildingName;
            if (address.addressLine3 && (address.buildingNumber != null)) {
              address3 = address.addressLine3;
            } else if ((address.addressLine2 == null) && (address.buildingNumber != null)) {
              address3 = address.buildingNumber + " " + address.streetName;
            } else if ((address.addressLine2 == null) && (address.buildingNumber == null) && (address.buildingName != null)) {
              address3 = address.addressLine3;
            } else {
              address3 = '';
            }
            $scope.bb.address3 = address3;
            $scope.bb.address4 = address.town;
            $scope.bb.address5 = "";
            $scope.bb.postcode = address.postCode;
          }
          if ((address.buildingName == null) && (address.companyName == null) && (address.county == null)) {
            if ((address.addressLine2 == null) && (address.companyName == null)) {
              address2 = address.addressLine3;
            } else {
              address2 = address.addressLine2;
            }
            $scope.bb.address2 = address2;
          } else if ((address.buildingName == null) && (address.companyName == null)) {
            $scope.bb.address2 = address.addressLine3;
          }
          if ((address.buildingName != null) && (address.streetName != null) && (address.companyName == null) && (address.addressLine3 != null)) {
            if (address.addressLine3 == null) {
              $scope.bb.address3 = address.buildingName;
            } else {
              $scope.bb.address3 = address.addressLine3;
            }
          } else if ((address.buildingName == null) && (address.companyName == null) && (address.addressLine2 != null)) {
            $scope.bb.address3 = address.addressLine3;
          } else if ((address.buildingName == null) && (address.streetName != null) && (address.addressLine3 == null)) {
            $scope.bb.address3 = address.addressLine3;
          }
          $scope.bb.address4 = address.town;
          if (address.county != null) {
            $scope.bb.address5 = address.county;
          }
          $scope.setLoaded($scope);
        }, function(err) {
          $scope.show_complete_address = true;
          $scope.postcode_submitted = false;
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
    };

    /***
    * @ngdoc method
    * @name setManualPostcodeEntry
    * @methodOf BB.Directives:bbAddresses
    * @description
    * Set manual postcode entry
    *
    * @param {string} value The value of postcode
     */
    $scope.setManualPostcodeEntry = function(value) {
      return $scope.manual_postcode_entry = value;
    };
    return $scope.$on("client_details:reset_search", function(event) {
      $scope.bb.address1 = null;
      $scope.bb.address2 = null;
      $scope.bb.address3 = null;
      $scope.bb.address4 = null;
      $scope.bb.address5 = null;
      $scope.show_complete_address = false;
      $scope.postcode_submitted = false;
      return $scope.bb.address = $scope.addresses[0];
    });
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbAttendees', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: function($scope, $rootScope, $q, PurchaseService, BBModel, AlertService, ValidatorService, ClientService) {
        var initialise, updateBooking;
        $scope.validator = ValidatorService;
        $rootScope.connection_started.then(function() {
          return initialise();
        });
        initialise = function() {
          return $scope.items = $scope.bb.basket.timeItems();
        };
        updateBooking = function() {
          var deferred, params;
          deferred = $q.defer();
          params = {
            purchase: $scope.bb.moving_purchase,
            bookings: $scope.bb.basket.items,
            notify: true
          };
          PurchaseService.update(params).then(function(purchase) {
            $scope.bb.purchase = purchase;
            $scope.setLoaded($scope);
            $scope.bb.current_item.move_done = true;
            $rootScope.$broadcast("booking:updated");
            return deferred.resolve();
          }, function(err) {
            return deferred.reject();
          });
          return deferred.promise;
        };

        /***
        * @ngdoc method
        * @name markItemAsChanged
        * @methodOf BB.Directives:bbAttendees
        * @description
        * Call this when an attendee is changed
         */
        $scope.markItemAsChanged = function(item) {
          return item.attendee_changed = true;
        };

        /***
        * @ngdoc method
        * @name updateBooking
        * @methodOf BB.Directives:bbAttendees
        * @description
        * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
         */
        $scope.changeAttendees = function() {
          var client, client_promises, deferred, i, item, len, ref;
          if (!$scope.bb.current_item.ready || !$scope.bb.moving_purchase) {
            return false;
          }
          deferred = $q.defer();
          $scope.notLoaded($scope);
          client_promises = [];
          ref = $scope.items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            if (item.attendee_changed) {
              client = new BBModel.Client();
              client.first_name = item.first_name;
              client.last_name = item.last_name;
              client_promises.push(ClientService.create_or_update($scope.bb.company, client));
            } else {
              client_promises.push($q.when([]));
            }
          }
          $q.all(client_promises).then(function(result) {
            var index, j, len1, ref1;
            ref1 = $scope.items;
            for (index = j = 0, len1 = ref1.length; j < len1; index = ++j) {
              item = ref1[index];
              if (result[index] && result[index].id) {
                item.client_id = result[index].id;
              }
            }
            return updateBooking().then(function() {
              if ($scope.$parent.$has_page_control) {
                return deferred.resolve();
              } else {
                $scope.decideNextPage('purchase');
                AlertService.raise('ATTENDEES_CHANGED');
                return deferred.resolve();
              }
            }, function(err) {
              return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
            });
          });
          return deferred.promise;
        };

        /***
        * @ngdoc method
        * @name setReady
        * @methodOf BB.Directives:bbAttendees
        * @description
        * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
         */
        return $scope.setReady = function() {
          return $scope.changeAttendees();
        };
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbWidget
  * @restrict A
  * @scope
  *   client: '=?'
  *   apiUrl: '@?'
  *   useParent:'='
  * @description
  *
  * Loads a list of widgets for the currently in scope company
  *
  * <pre>
  * restrict: 'A'
  * scope:
  *   client: '=?'
  *   apiUrl: '@?'
  *   useParent:'='
  * transclude: true
  * </pre>
  *
  * @param {hash} bbWidget A hash of options
  * @property {string} pusher The pusher
  * @property {string} pusher_channel The pusher channel
  * @property {string} init_params Initialization of basic parameters
   */
  angular.module('BB.Directives').directive('bbWidget', function(PathSvc, $http, $log, $templateCache, $compile, $q, AppConfig, $timeout, $bbug, $rootScope) {

    /***
    * @ngdoc method
    * @name getTemplate
    * @methodOf BB.Directives:bbWidget
    * @description
    * Get template
    *
    * @param {object} template The template
     */
    var appendCustomPartials, getTemplate, renderTemplate, setupPusher, updatePartials;
    getTemplate = function(template) {
      var fromTemplateCache, partial, src;
      partial = template ? template : 'main';
      fromTemplateCache = $templateCache.get(partial);
      if (fromTemplateCache) {
        return fromTemplateCache;
      } else {
        src = PathSvc.directivePartial(partial).$$unwrapTrustedValue();
        return $http.get(src, {
          cache: $templateCache
        }).then(function(response) {
          return response.data;
        });
      }
    };

    /***
    * @ngdoc method
    * @name updatePartials
    * @methodOf BB.Directives:bbWidget
    * @description
    * Update partials
    *
    * @param {object} prms The parameter
     */
    updatePartials = function(scope, element, prms) {
      var i, j, len, ref;
      ref = element.children();
      for (j = 0, len = ref.length; j < len; j++) {
        i = ref[j];
        if ($bbug(i).hasClass('custom_partial')) {
          $bbug(i).remove();
        }
      }
      return appendCustomPartials(scope, element, prms).then(function() {
        return scope.$broadcast('refreshPage');
      });
    };

    /***
    * @ngdoc method
    * @name setupPusher
    * @methodOf BB.Directives:bbWidget
    * @description
    * Push setup
    *
    * @param {object} prms The parameter
     */
    setupPusher = function(scope, element, prms) {
      return $timeout(function() {
        scope.pusher = new Pusher('c8d8cea659cc46060608');
        scope.pusher_channel = scope.pusher.subscribe("widget_" + prms.design_id);
        return scope.pusher_channel.bind('update', function(data) {
          return updatePartials(scope, element, prms);
        });
      });
    };

    /***
    * @ngdoc method
    * @name appendCustomPartials
    * @methodOf BB.Directives:bbWidget
    * @description
    * Appent custom partials
    *
    * @param {object} prms The parameter
     */
    appendCustomPartials = function(scope, element, prms) {
      var defer;
      defer = $q.defer();
      $http.get(prms.custom_partial_url).then(function(custom_templates) {
        return $compile(custom_templates.data)(scope, function(custom, scope) {
          var non_style, style, tag;
          custom.addClass('custom_partial');
          style = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = custom.length; j < len; j++) {
              tag = custom[j];
              if (tag.tagName === "STYLE") {
                results.push(tag);
              }
            }
            return results;
          })();
          non_style = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = custom.length; j < len; j++) {
              tag = custom[j];
              if (tag.tagName !== "STYLE") {
                results.push(tag);
              }
            }
            return results;
          })();
          $bbug("#widget_" + prms.design_id).html(non_style);
          element.append(style);
          scope.bb.path_setup = true;
          return defer.resolve(style);
        });
      });
      return defer.promise;
    };

    /***
    * @ngdoc method
    * @name renderTemplate
    * @methodOf BB.Directives:bbWidget
    * @description
    * Render template
    *
    * @param {object} design_mode The design mode
    * @param {object} template The template
     */
    renderTemplate = function(scope, element, design_mode, template) {
      return $q.when(getTemplate(template)).then(function(template) {
        element.html(template).show();
        if (design_mode) {
          element.append('<style widget_css scoped></style>');
        }
        return $compile(element.contents())(scope);
      });
    };
    return {
      restrict: 'A',
      scope: {
        client: '=?',
        apiUrl: '@?',
        useParent: '='
      },
      transclude: true,
      controller: 'BBCtrl',
      link: function(scope, element, attrs, controller, transclude) {
        var evaluator, init_params;
        if (attrs.member != null) {
          scope.client = attrs.member;
        }
        evaluator = scope;
        if (scope.useParent && (scope.$parent != null)) {
          evaluator = scope.$parent;
        }
        init_params = evaluator.$eval(attrs.bbWidget);
        scope.initWidget(init_params);
        return $rootScope.widget_started.then((function(_this) {
          return function() {
            var prms;
            prms = scope.bb;
            if (prms.custom_partial_url) {
              prms.design_id = prms.custom_partial_url.match(/^.*\/(.*?)$/)[1];
              $bbug("[ng-app='BB']").append("<div id='widget_" + prms.design_id + "'></div>");
            }
            if (scope.bb.partial_url) {
              if (init_params.partial_url) {
                AppConfig['partial_url'] = init_params.partial_url;
              } else {
                AppConfig['partial_url'] = scope.bb.partial_url;
              }
            }
            return transclude(scope, function(clone) {
              scope.has_content = clone.length > 1 || (clone.length === 1 && (!clone[0].wholeText || /\S/.test(clone[0].wholeText)));
              if (!scope.has_content) {
                if (prms.custom_partial_url) {
                  appendCustomPartials(scope, element, prms).then(function(style) {
                    return $q.when(getTemplate()).then(function(template) {
                      element.html(template).show();
                      $compile(element.contents())(scope);
                      element.append(style);
                      if (prms.update_design) {
                        return setupPusher(scope, element, prms);
                      }
                    });
                  });
                } else if (prms.template) {
                  renderTemplate(scope, element, prms.design_mode, prms.template);
                } else {
                  renderTemplate(scope, element, prms.design_mode);
                }
                return scope.$on('refreshPage', function() {
                  return renderTemplate(scope, element, prms.design_mode);
                });
              } else if (prms.custom_partial_url) {
                appendCustomPartials(scope, element, prms);
                if (prms.update_design) {
                  setupPusher(scope, element, prms);
                }
                return scope.$on('refreshPage', function() {
                  return scope.showPage(scope.bb.current_page);
                });
              } else {
                element.html(clone).show();
                if (prms.design_mode) {
                  element.append('<style widget_css scoped></style>');
                }
                return $compile(element.contents())(scope);
              }
            });
          };
        })(this));
      }
    };
  });

  angular.module('BB.Controllers').controller('bbContentController', function($scope) {
    $scope.controller = "public.controllers.bbContentController";
    return $scope.initPage = (function(_this) {
      return function() {
        $scope.setPageLoaded();
        return $scope.setLoadingPage(false);
      };
    })(this);
  });

  angular.module('BB.Controllers').controller('BBCtrl', function($scope, $location, $rootScope, halClient, $window, $http, $localCache, $q, $timeout, BasketService, LoginService, AlertService, $sce, $element, $compile, $sniffer, $modal, $log, BBModel, BBWidget, SSOService, ErrorService, AppConfig, QueryStringService, QuestionService, LocaleService, PurchaseService, $sessionStorage, $bbug, SettingsService, UriTemplate, $anchorScroll, $localStorage) {
    var base, base1, con_started, first_call, restoreBasket, setupDefaults, widget_started;
    $scope.cid = "BBCtrl";
    $scope.controller = "public.controllers.BBCtrl";
    $scope.bb = new BBWidget();
    AppConfig.uid = $scope.bb.uid;
    $scope.qs = QueryStringService;
    $scope.company_api_path = '/api/v1/company/{company_id}{?embed,category_id}';
    $scope.company_admin_api_path = '/api/v1/admin/{company_id}/company{?embed,category_id}';
    if ($scope.apiUrl) {
      $scope.bb || ($scope.bb = {});
      $scope.bb.api_url = $scope.apiUrl;
    }
    if ($rootScope.bb && $rootScope.bb.api_url) {
      $scope.bb.api_url = $rootScope.bb.api_url;
      if (!$rootScope.bb.partial_url) {
        $scope.bb.partial_url = "";
      } else {
        $scope.bb.partial_url = $rootScope.bb.partial_url;
      }
    }
    if ($location.port() !== 80 && $location.port() !== 443) {
      (base = $scope.bb).api_url || (base.api_url = $location.protocol() + "://" + $location.host() + ":" + $location.port());
    } else {
      (base1 = $scope.bb).api_url || (base1.api_url = $location.protocol() + "://" + $location.host());
    }
    $scope.bb.stacked_items = [];
    first_call = true;
    con_started = $q.defer();
    $rootScope.connection_started = con_started.promise;
    widget_started = $q.defer();
    $rootScope.widget_started = widget_started.promise;
    moment.locale([LocaleService, "en"]);
    $rootScope.Route = {
      Company: 0,
      Category: 1,
      Service: 2,
      Person: 3,
      Resource: 4,
      Duration: 5,
      Date: 6,
      Time: 7,
      Client: 8,
      Summary: 9,
      Basket: 10,
      Checkout: 11,
      Slot: 12,
      Event: 13,
      Login: 14
    };
    $scope.Route = $rootScope.Route;
    $compile("<span bb-display-mode></span>")($scope, (function(_this) {
      return function(cloned, scope) {
        return $bbug($element).append(cloned);
      };
    })(this));
    $scope.set_company = (function(_this) {
      return function(prms) {
        return $scope.initWidget(prms);
      };
    })(this);
    $scope.initWidget = (function(_this) {
      return function(prms) {
        var url;
        if (prms == null) {
          prms = {};
        }
        _this.$init_prms = prms;
        con_started = $q.defer();
        $rootScope.connection_started = con_started.promise;
        if ((($sniffer.webkit && $sniffer.webkit < 537) || ($sniffer.msie && $sniffer.msie <= 9)) && first_call) {
          if ($scope.bb.api_url) {
            url = document.createElement('a');
            url.href = $scope.bb.api_url;
            if (url.host === '' || url.host === $location.host() || url.host === (($location.host()) + ":" + ($location.port()))) {
              $scope.initWidget2();
              return;
            }
          }
          if ($rootScope.iframe_proxy_ready) {
            $scope.initWidget2();
          } else {
            $scope.$on('iframe_proxy_ready', function(event, args) {
              if (args.iframe_proxy_ready) {
                return $scope.initWidget2();
              }
            });
          }
        } else {
          $scope.initWidget2();
        }
      };
    })(this);
    $scope.initWidget2 = (function(_this) {
      return function() {
        var aff_promise, comp_category_id, comp_def, comp_promise, comp_url, company_id, embed_params, get_total, k, match, options, params, prms, ref, setup_promises, setup_promises2, sso_admin_login, sso_member_login, total_id, v;
        $scope.init_widget_started = true;
        prms = _this.$init_prms;
        if (prms.query) {
          ref = prms.query;
          for (k in ref) {
            v = ref[k];
            prms[k] = QueryStringService(v);
          }
        }
        if (prms.custom_partial_url) {
          $scope.bb.custom_partial_url = prms.custom_partial_url;
          $scope.bb.partial_id = prms.custom_partial_url.substring(prms.custom_partial_url.lastIndexOf("/") + 1);
          if (prms.update_design) {
            $scope.bb.update_design = prms.update_design;
          }
        } else if (prms.design_mode) {
          $scope.bb.design_mode = prms.design_mode;
        }
        company_id = $scope.bb.company_id;
        if (prms.company_id) {
          company_id = prms.company_id;
        }
        if (prms.affiliate_id) {
          $scope.bb.affiliate_id = prms.affiliate_id;
          $rootScope.affiliate_id = prms.affiliate_id;
        }
        if (prms.api_url) {
          $scope.bb.api_url = prms.api_url;
        }
        if (prms.partial_url) {
          $scope.bb.partial_url = prms.partial_url;
        }
        if (prms.page_suffix) {
          $scope.bb.page_suffix = prms.page_suffix;
        }
        if (prms.admin) {
          $scope.bb.isAdmin = prms.admin;
        }
        if (prms.auth_token) {
          $sessionStorage.setItem("auth_token", prms.auth_token);
        }
        $scope.bb.app_id = 1;
        $scope.bb.app_key = 1;
        $scope.bb.clear_basket = true;
        if (prms.basket) {
          $scope.bb.clear_basket = false;
        }
        if (prms.clear_basket === false) {
          $scope.bb.clear_basket = false;
        }
        if ($window.bb_setup || prms.client) {
          prms.clear_member || (prms.clear_member = true);
        }
        $scope.bb.client_defaults = prms.client || {};
        if (prms.client_defaults) {
          if (prms.client_defaults.membership_ref) {
            $scope.bb.client_defaults.membership_ref = prms.client_defaults.membership_ref;
          }
        }
        if ($scope.bb.client_defaults && $scope.bb.client_defaults.name) {
          match = $scope.bb.client_defaults.name.match(/^(\S+)(?:\s(\S+))?/);
          if (match) {
            $scope.bb.client_defaults.first_name = match[1];
            if (match[2] != null) {
              $scope.bb.client_defaults.last_name = match[2];
            }
          }
        }
        if (prms.clear_member) {
          $scope.bb.clear_member = prms.clear_member;
          $sessionStorage.removeItem('login');
        }
        if (prms.app_id) {
          $scope.bb.app_id = prms.app_id;
        }
        if (prms.app_key) {
          $scope.bb.app_key = prms.app_key;
        }
        if (prms.item_defaults) {
          $scope.bb.original_item_defaults = prms.item_defaults;
          $scope.bb.item_defaults = angular.copy($scope.bb.original_item_defaults);
        } else if ($scope.bb.original_item_defaults) {
          $scope.bb.item_defaults = angular.copy($scope.bb.original_item_defaults);
        }
        if (prms.route_format) {
          $scope.bb.setRouteFormat(prms.route_format);
          if ($scope.bb_route_init) {
            $scope.bb_route_init();
          }
        }
        if (prms.locale) {
          moment.locale(prms.locale);
        }
        if (prms.hide === true) {
          $scope.hide_page = true;
        } else {
          $scope.hide_page = false;
        }
        if (!prms.custom_partial_url) {
          $scope.bb.path_setup = true;
        }
        if (prms.reserve_without_questions) {
          $scope.bb.reserve_without_questions = prms.reserve_without_questions;
        }
        if (prms.extra_setup) {
          $scope.bb.extra_setup = prms.extra_setup;
          if (prms.extra_setup.step) {
            $scope.bb.starting_step_number = parseInt(prms.extra_setup.step);
          }
          if (prms.extra_setup.return_url) {
            $scope.bb.return_url = prms.extra_setup.return_url;
          }
          if (prms.extra_setup.destination) {
            $scope.bb.destination = prms.extra_setup.destination;
          }
        }
        if (prms.template) {
          $scope.bb.template = prms.template;
        }
        if (prms.i18n) {
          SettingsService.enableInternationalizaton();
        }
        if (prms.login_required) {
          $scope.bb.login_required = true;
        }
        if (prms.private_note) {
          $scope.bb.private_note = prms.private_note;
        }
        if (prms.qudini_booking_id) {
          $scope.bb.qudini_booking_id = prms.qudini_booking_id;
        }
        if (prms.scroll_offset) {
          SettingsService.setScrollOffset(prms.scroll_offset);
        }
        _this.waiting_for_conn_started_def = $q.defer();
        $scope.waiting_for_conn_started = _this.waiting_for_conn_started_def.promise;
        if (company_id || $scope.bb.affiliate_id) {
          $scope.waiting_for_conn_started = $rootScope.connection_started;
        } else {
          _this.waiting_for_conn_started_def.resolve();
        }
        widget_started.resolve();
        setup_promises2 = [];
        setup_promises = [];
        if ($scope.bb.affiliate_id) {
          aff_promise = halClient.$get($scope.bb.api_url + '/api/v1/affiliates/' + $scope.bb.affiliate_id);
          setup_promises.push(aff_promise);
          aff_promise.then(function(affiliate) {
            var comp_p, comp_promise;
            if ($scope.bb.$wait_for_routing) {
              setup_promises2.push($scope.bb.$wait_for_routing.promise);
            }
            $scope.setAffiliate(new BBModel.Affiliate(affiliate));
            $scope.bb.item_defaults.affiliate = $scope.affiliate;
            if (prms.company_ref) {
              comp_p = $q.defer();
              comp_promise = $scope.affiliate.getCompanyByRef(prms.company_ref);
              setup_promises2.push(comp_p.promise);
              return comp_promise.then(function(company) {
                return $scope.setCompany(company, prms.keep_basket).then(function(val) {
                  return comp_p.resolve(val);
                }, function(err) {
                  return comp_p.reject(err);
                });
              }, function(err) {
                return comp_p.reject(err);
              });
            }
          });
        }
        if (company_id) {
          if (prms.embed) {
            embed_params = prms.embed;
          }
          embed_params || (embed_params = null);
          comp_category_id = null;
          if ($scope.bb.item_defaults.category != null) {
            if ($scope.bb.item_defaults.category.id != null) {
              comp_category_id = $scope.bb.item_defaults.category.id;
            } else {
              comp_category_id = $scope.bb.item_defaults.category;
            }
          }
          comp_def = $q.defer();
          comp_promise = comp_def.promise;
          options = {};
          if ($sessionStorage.getItem('auth_token')) {
            options.auth_token = $sessionStorage.getItem('auth_token');
          }
          if ($scope.bb.isAdmin) {
            comp_url = new UriTemplate($scope.bb.api_url + $scope.company_admin_api_path).fillFromObject({
              company_id: company_id,
              category_id: comp_category_id,
              embed: embed_params
            });
            halClient.$get(comp_url, options).then(function(company) {
              return comp_def.resolve(company);
            }, function(err) {
              comp_url = new UriTemplate($scope.bb.api_url + $scope.company_api_path).fillFromObject({
                company_id: company_id,
                category_id: comp_category_id,
                embed: embed_params
              });
              return halClient.$get(comp_url, options).then(function(company) {
                return comp_def.resolve(company);
              }, function(err) {
                return comp_def.reject(err);
              });
            });
          } else {
            comp_url = new UriTemplate($scope.bb.api_url + $scope.company_api_path).fillFromObject({
              company_id: company_id,
              category_id: comp_category_id,
              embed: embed_params
            });
            halClient.$get(comp_url, options).then(function(company) {
              if (company) {
                return comp_def.resolve(company);
              } else {
                return comp_def.reject("Invalid company ID " + company_id);
              }
            }, function(err) {
              return comp_def.reject(err);
            });
          }
          setup_promises.push(comp_promise);
          comp_promise.then(function(company) {
            var child, comp, cprom, parent_company;
            if ($scope.bb.$wait_for_routing) {
              setup_promises2.push($scope.bb.$wait_for_routing.promise);
            }
            comp = new BBModel.Company(company);
            cprom = $q.defer();
            setup_promises2.push(cprom.promise);
            child = null;
            if (comp.companies && $scope.bb.item_defaults.company) {
              child = comp.findChildCompany($scope.bb.item_defaults.company);
            }
            if (child) {
              parent_company = comp;
              return halClient.$get($scope.bb.api_url + '/api/v1/company/' + child.id).then(function(company) {
                comp = new BBModel.Company(company);
                setupDefaults(comp.id);
                $scope.bb.parent_company = parent_company;
                return $scope.setCompany(comp, prms.keep_basket).then(function() {
                  return cprom.resolve();
                }, function(err) {
                  return cprom.reject();
                });
              }, function(err) {
                return cprom.reject();
              });
            } else {
              setupDefaults(comp.id);
              return $scope.setCompany(comp, prms.keep_basket).then(function() {
                return cprom.resolve();
              }, function(err) {
                return cprom.reject();
              });
            }
          });
          if (prms.member_sso) {
            params = {
              company_id: company_id,
              root: $scope.bb.api_url,
              member_sso: prms.member_sso
            };
            sso_member_login = SSOService.memberLogin(params).then(function(client) {
              return $scope.setClient(client);
            });
            setup_promises.push(sso_member_login);
          }
          if (prms.admin_sso) {
            params = {
              company_id: prms.parent_company_id ? prms.parent_company_id : company_id,
              root: $scope.bb.api_url,
              admin_sso: prms.admin_sso
            };
            sso_admin_login = SSOService.adminLogin(params).then(function(admin) {
              return $scope.bb.admin = admin;
            });
            setup_promises.push(sso_admin_login);
          }
          total_id = QueryStringService('total_id');
          if (total_id) {
            params = {
              purchase_id: total_id,
              url_root: $scope.bb.api_url
            };
            get_total = PurchaseService.query(params).then(function(total) {
              $scope.bb.total = total;
              if (total.paid > 0) {
                return $scope.bb.payment_status = 'complete';
              }
            });
            setup_promises.push(get_total);
          }
        }
        $scope.isLoaded = false;
        return $q.all(setup_promises).then(function() {
          return $q.all(setup_promises2).then(function() {
            var base2, clear_prom, def_clear;
            if (!$scope.bb.basket) {
              (base2 = $scope.bb).basket || (base2.basket = new BBModel.Basket(null, $scope.bb));
            }
            if (!$scope.client) {
              $scope.clearClient();
            }
            def_clear = $q.defer();
            clear_prom = def_clear.promise;
            if (!$scope.bb.current_item) {
              clear_prom = $scope.clearBasketItem();
            } else {
              def_clear.resolve();
            }
            return clear_prom.then(function() {
              var page;
              if (!$scope.client_details) {
                $scope.client_details = new BBModel.ClientDetails();
              }
              if (!$scope.bb.stacked_items) {
                $scope.bb.stacked_items = [];
              }
              if ($scope.bb.company || $scope.bb.affiliate) {
                con_started.resolve();
                $scope.done_starting = true;
                if (!prms.no_route) {
                  page = null;
                  if (first_call && $bbug.isEmptyObject($scope.bb.routeSteps)) {
                    page = $scope.bb.firstStep;
                  }
                  if (prms.first_page) {
                    page = prms.first_page;
                  }
                  first_call = false;
                  return $scope.decideNextPage(page);
                }
              }
            });
          }, function(err) {
            con_started.reject("Failed to start widget");
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        }, function(err) {
          con_started.reject("Failed to start widget");
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);
    setupDefaults = (function(_this) {
      return function(company_id) {
        var category, clinic, def, event, event_chain, event_group, k, person, ref, resource, service, v;
        def = $q.defer();
        if (first_call || ($scope.bb.orginal_company_id && $scope.bb.orginal_company_id !== company_id)) {
          $scope.bb.orginal_company_id = company_id;
          $scope.bb.default_setup_promises = [];
          if ($scope.bb.item_defaults.query) {
            ref = $scope.bb.item_defaults.query;
            for (k in ref) {
              v = ref[k];
              $scope.bb.item_defaults[k] = QueryStringService(v);
            }
          }
          if ($scope.bb.item_defaults.resource) {
            if ($scope.bb.isAdmin) {
              resource = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/resources/' + $scope.bb.item_defaults.resource);
            } else {
              resource = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/resources/' + $scope.bb.item_defaults.resource);
            }
            $scope.bb.default_setup_promises.push(resource);
            resource.then(function(res) {
              return $scope.bb.item_defaults.resource = new BBModel.Resource(res);
            });
          }
          if ($scope.bb.item_defaults.person) {
            if ($scope.bb.isAdmin) {
              person = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/people/' + $scope.bb.item_defaults.person);
            } else {
              person = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/people/' + $scope.bb.item_defaults.person);
            }
            $scope.bb.default_setup_promises.push(person);
            person.then(function(res) {
              return $scope.bb.item_defaults.person = new BBModel.Person(res);
            });
          }
          if ($scope.bb.item_defaults.person_ref) {
            if ($scope.bb.isAdmin) {
              person = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/people/find_by_ref/' + $scope.bb.item_defaults.person_ref);
            } else {
              person = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/people/find_by_ref/' + $scope.bb.item_defaults.person_ref);
            }
            $scope.bb.default_setup_promises.push(person);
            person.then(function(res) {
              return $scope.bb.item_defaults.person = new BBModel.Person(res);
            });
          }
          if ($scope.bb.item_defaults.service) {
            if ($scope.bb.isAdmin) {
              service = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/services/' + $scope.bb.item_defaults.service);
            } else {
              service = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/services/' + $scope.bb.item_defaults.service);
            }
            $scope.bb.default_setup_promises.push(service);
            service.then(function(res) {
              return $scope.bb.item_defaults.service = new BBModel.Service(res);
            });
          }
          if ($scope.bb.item_defaults.service_ref) {
            if ($scope.bb.isAdmin) {
              service = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/services?api_ref=' + $scope.bb.item_defaults.service_ref);
            } else {
              service = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/services?api_ref=' + $scope.bb.item_defaults.service_ref);
            }
            $scope.bb.default_setup_promises.push(service);
            service.then(function(res) {
              return $scope.bb.item_defaults.service = new BBModel.Service(res);
            });
          }
          if ($scope.bb.item_defaults.event_group) {
            if ($scope.bb.isAdmin) {
              event_group = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/event_groups/' + $scope.bb.item_defaults.event_group);
            } else {
              event_group = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/event_groups/' + $scope.bb.item_defaults.event_group);
            }
            $scope.bb.default_setup_promises.push(event_group);
            event_group.then(function(res) {
              return $scope.bb.item_defaults.event_group = new BBModel.EventGroup(res);
            });
          }
          if ($scope.bb.item_defaults.event) {
            if ($scope.bb.isAdmin) {
              event = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/event_chains/' + $scope.bb.item_defaults.event_chain + '/events/' + $scope.bb.item_defaults.event);
            } else {
              event = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/events/' + $scope.bb.item_defaults.event);
            }
            $scope.bb.default_setup_promises.push(event);
            event.then(function(res) {
              return $scope.bb.item_defaults.event = new BBModel.Event(res);
            });
          }
          if ($scope.bb.item_defaults.event_chain) {
            if ($scope.bb.isAdmin) {
              event_chain = halClient.$get($scope.bb.api_url + '/api/v1/admin/' + company_id + '/event_chains/' + $scope.bb.item_defaults.event_chain);
            } else {
              event_chain = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/event_chains/' + $scope.bb.item_defaults.event_chain);
            }
            $scope.bb.default_setup_promises.push(event_chain);
            event_chain.then(function(res) {
              return $scope.bb.item_defaults.event_chain = new BBModel.EventChain(res);
            });
          }
          if ($scope.bb.item_defaults.category) {
            category = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/categories/' + $scope.bb.item_defaults.category);
            $scope.bb.default_setup_promises.push(category);
            category.then(function(res) {
              return $scope.bb.item_defaults.category = new BBModel.Category(res);
            });
          }
          if ($scope.bb.item_defaults.clinic) {
            clinic = halClient.$get($scope.bb.api_url + '/api/v1/' + company_id + '/clinics/' + $scope.bb.item_defaults.clinic);
            $scope.bb.default_setup_promises.push(clinic);
            clinic.then(function(res) {
              return $scope.bb.item_defaults.clinic = new BBModel.Clinic(res);
            });
          }
          if ($scope.bb.item_defaults.duration) {
            $scope.bb.item_defaults.duration = parseInt($scope.bb.item_defaults.duration);
          }
          $q.all($scope.bb.default_setup_promises)['finally'](function() {
            return def.resolve();
          });
        } else {
          def.resolve();
        }
        return def.promise;
      };
    })(this);
    $scope.setLoadingPage = (function(_this) {
      return function(val) {
        return $scope.loading_page = val;
      };
    })(this);
    $scope.isLoadingPage = (function(_this) {
      return function() {
        return $scope.loading_page;
      };
    })(this);
    $scope.$on('$locationChangeStart', function(angular_event, new_url, old_url) {
      var step_number;
      if (!$scope.bb.routeFormat && $scope.bb.routing) {
        return;
      }
      $scope.history_at_widget_init = $scope.history_at_widget_init || window.parent.history.length;
      step_number = $scope.bb.matchURLToStep();
      if ((step_number != null) && step_number > $scope.bb.current_step) {
        $scope.loadStep(step_number);
      } else if ((step_number != null) && step_number < $scope.bb.current_step) {
        $scope.loadPreviousStep('locationChangeStart');
      }
      return $scope.bb.routing = false;
    });
    $scope.showPage = (function(_this) {
      return function(route, dont_record_page) {
        $scope.bb.updateRoute(route);
        $scope.jumped = false;
        if ($scope.isLoadingPage()) {
          return;
        }
        if ($window._gaq) {
          $window._gaq.push(['_trackPageview', route]);
        }
        $scope.setLoadingPage(true);
        if ($scope.bb.current_page === route) {
          $scope.bb_main = "";
          setTimeout(function() {
            $scope.bb_main = $sce.trustAsResourceUrl($scope.bb.pageURL(route));
            return $scope.$apply();
          }, 0);
        } else {
          AlertService.clear();
          $scope.bb.current_page = route;
          if (!dont_record_page) {
            $scope.bb.recordCurrentPage();
          }
          $scope.notLoaded($scope);
          $scope.bb_main = $sce.trustAsResourceUrl($scope.bb.pageURL(route));
        }
        return $rootScope.$broadcast("page:loaded");
      };
    })(this);
    $scope.jumpToPage = (function(_this) {
      return function(route) {
        $scope.current_page = route;
        $scope.jumped = true;
        return $scope.bb_main = $sce.trustAsResourceUrl($scope.partial_url + route + $scope.page_suffix);
      };
    })(this);
    $scope.clearPage = function() {
      return $scope.bb_main = "";
    };
    $scope.getPartial = function(file) {
      return $scope.bb.pageURL(file);
    };
    $scope.setPageLoaded = function() {
      return $scope.setLoaded($scope);
    };
    $scope.setPageRoute = (function(_this) {
      return function(route) {
        $scope.bb.current_page_route = route;
        if ($scope.bb.routeSteps && $scope.bb.routeSteps[route]) {
          $scope.showPage($scope.bb.routeSteps[route]);
          return true;
        }
        return false;
      };
    })(this);
    $scope.decideNextPage = function(route) {
      if (route) {
        if (route === 'none') {
          return;
        } else {
          if ($scope.bb.total && $scope.bb.payment_status === 'complete') {
            $scope.showPage('confirmation');
          } else {
            return $scope.showPage(route);
          }
        }
      }
      if ($scope.bb.nextSteps && $scope.bb.current_page && $scope.bb.nextSteps[$scope.bb.current_page] && !$scope.bb.routeSteps) {
        return $scope.showPage($scope.bb.nextSteps[$scope.bb.current_page]);
      }
      if (!$scope.client.valid() && LoginService.isLoggedIn()) {
        $scope.client = new BBModel.Client(LoginService.member()._data);
      }
      if (($scope.bb.company && $scope.bb.company.companies) || (!$scope.bb.company && $scope.affiliate)) {
        if ($scope.setPageRoute($rootScope.Route.Company)) {
          return;
        }
        return $scope.showPage('company_list');
      } else if ($scope.bb.total && $scope.bb.payment_status === "complete") {
        return $scope.showPage('confirmation');
      } else if ($scope.bb.total && $scope.bb.payment_status === "pending") {
        return $scope.showPage('payment');
      } else if (($scope.bb.company.$has('event_groups') && !$scope.bb.current_item.event_group && !$scope.bb.current_item.service && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) || ($scope.bb.company.$has('events') && $scope.bb.current_item.event_group && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal)) {
        if ($scope.setPageRoute($rootScope.Route.Event)) {
          return;
        }
        return $scope.showPage('event_list');
      } else if ($scope.bb.company.$has('events') && $scope.bb.current_item.event && !$scope.bb.current_item.num_book && (!$scope.bb.current_item.tickets || !$scope.bb.current_item.tickets.qty) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) {
        return $scope.showPage('event');
      } else if ($scope.bb.company.$has('services') && !$scope.bb.current_item.service && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) {
        if ($scope.setPageRoute($rootScope.Route.Service)) {
          return;
        }
        return $scope.showPage('service_list');
      } else if ($scope.bb.company.$has('resources') && !$scope.bb.current_item.resource && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) {
        if ($scope.setPageRoute($rootScope.Route.Resource)) {
          return;
        }
        return $scope.showPage('resource_list');
      } else if ($scope.bb.company.$has('people') && !$scope.bb.current_item.person && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) {
        if ($scope.setPageRoute($rootScope.Route.Person)) {
          return;
        }
        return $scope.showPage('person_list');
      } else if (!$scope.bb.current_item.duration && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.product && !$scope.bb.current_item.deal) {
        if ($scope.setPageRoute($rootScope.Route.Duration)) {
          return;
        }
        return $scope.showPage('duration_list');
      } else if ($scope.bb.current_item.days_link && !$scope.bb.current_item.date && ($scope.bb.current_item.event == null) && !$scope.bb.current_item.deal) {
        if ($scope.bb.company.$has('availability_slots')) {
          if ($scope.setPageRoute($rootScope.Route.Slot)) {
            return;
          }
          return $scope.showPage('slot_list');
        } else {
          if ($scope.setPageRoute($rootScope.Route.Date)) {
            return;
          }
          return $scope.showPage('calendar');
        }
      } else if ($scope.bb.current_item.days_link && !$scope.bb.current_item.time && ($scope.bb.current_item.event == null) && (!$scope.bb.current_item.service || $scope.bb.current_item.service.duration_unit !== 'day') && !$scope.bb.current_item.deal) {
        if ($scope.setPageRoute($rootScope.Route.Time)) {
          return;
        }
        return $scope.showPage('time');
      } else if ($scope.bb.moving_booking && (!$scope.bb.current_item.ready || !$scope.bb.current_item.move_done)) {
        return $scope.showPage('check_move');
      } else if (!$scope.client.valid()) {
        if ($scope.setPageRoute($rootScope.Route.Client)) {
          return;
        }
        return $scope.showPage('client');
      } else if ((!$scope.bb.basket.readyToCheckout() || !$scope.bb.current_item.ready) && ($scope.bb.current_item.item_details && $scope.bb.current_item.item_details.hasQuestions)) {
        if ($scope.setPageRoute($rootScope.Route.Summary)) {
          return;
        }
        return $scope.showPage('check_items');
      } else if ($scope.bb.usingBasket && (!$scope.bb.confirmCheckout || $scope.bb.company_settings.has_vouchers || $scope.bb.company.$has('coupon'))) {
        if ($scope.setPageRoute($rootScope.Route.Basket)) {
          return;
        }
        return $scope.showPage('basket');
      } else if ($scope.bb.moving_booking && $scope.bb.basket.readyToCheckout()) {
        return $scope.showPage('purchase');
      } else if ($scope.bb.basket.readyToCheckout() && $scope.bb.payment_status === null && !$scope.bb.basket.waiting_for_checkout) {
        if ($scope.setPageRoute($rootScope.Route.Checkout)) {
          return;
        }
        return $scope.showPage('checkout');
      } else if ($scope.bb.payment_status === "complete") {
        return $scope.showPage('confirmation');
      }
    };
    $scope.showCheckout = function() {
      return $scope.bb.current_item.ready;
    };
    $scope.addItemToBasket = function() {
      var add_defer;
      add_defer = $q.defer();
      if (!$scope.bb.current_item.submitted && !$scope.bb.moving_booking) {
        $scope.moveToBasket();
        $scope.bb.current_item.submitted = $scope.updateBasket();
        $scope.bb.current_item.submitted.then(function(basket) {
          return add_defer.resolve(basket);
        }, function(err) {
          if (err.status === 409) {
            $scope.bb.current_item.person = null;
            $scope.bb.current_item.resource = null;
            $scope.bb.current_item.setTime(null);
            if ($scope.bb.current_item.service) {
              $scope.bb.current_item.setService($scope.bb.current_item.service);
            }
          }
          $scope.bb.current_item.submitted = null;
          return add_defer.reject(err);
        });
      } else if ($scope.bb.current_item.submitted) {
        return $scope.bb.current_item.submitted;
      } else {
        add_defer.resolve();
      }
      return add_defer.promise;
    };
    $scope.updateBasket = function() {
      var add_defer, params;
      add_defer = $q.defer();
      params = {
        member_id: $scope.client.id,
        member: $scope.client,
        items: $scope.bb.basket.items,
        bb: $scope.bb
      };
      BasketService.updateBasket($scope.bb.company, params).then(function(basket) {
        var item, j, len, ref;
        ref = basket.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          item.storeDefaults($scope.bb.item_defaults);
          item.reserve_without_questions = $scope.bb.reserve_without_questions;
        }
        halClient.clearCache("time_data");
        halClient.clearCache("events");
        basket.setSettings($scope.bb.basket.settings);
        $scope.setBasket(basket);
        $scope.setBasketItem(basket.items[0]);
        if (!$scope.bb.current_item) {
          return $scope.clearBasketItem().then(function() {
            return add_defer.resolve(basket);
          });
        } else {
          return add_defer.resolve(basket);
        }
      }, function(err) {
        var error_modal;
        add_defer.reject(err);
        if (err.status === 409) {
          halClient.clearCache("time_data");
          halClient.clearCache("events");
          $scope.bb.current_item.person = null;
          $scope.bb.current_item.selected_person = null;
          error_modal = $modal.open({
            templateUrl: $scope.getPartial('_error_modal'),
            controller: function($scope, $modalInstance) {
              $scope.message = ErrorService.getError('ITEM_NO_LONGER_AVAILABLE').msg;
              return $scope.ok = function() {
                return $modalInstance.close();
              };
            }
          });
          return error_modal.result["finally"](function() {
            if ($scope.bb.nextSteps) {
              if ($scope.setPageRoute($rootScope.Route.Date)) {

              } else if ($scope.setPageRoute($rootScope.Route.Event)) {

              } else {
                return $scope.loadPreviousStep();
              }
            } else {
              return $scope.decideNextPage();
            }
          });
        }
      });
      return add_defer.promise;
    };
    $scope.emptyBasket = function() {
      var defer;
      if (!$scope.bb.basket.items || ($scope.bb.basket.items && $scope.bb.basket.items.length === 0)) {
        return;
      }
      defer = $q.defer();
      BasketService.empty($scope.bb).then(function(basket) {
        if ($scope.bb.current_item.id) {
          delete $scope.bb.current_item.id;
        }
        $scope.setBasket(basket);
        return defer.resolve();
      }, function(err) {
        return defer.reject();
      });
      return defer.promise;
    };
    $scope.deleteBasketItem = function(item) {
      return BasketService.deleteItem(item, $scope.bb.company, {
        bb: $scope.bb
      }).then(function(basket) {
        return $scope.setBasket(basket);
      });
    };
    $scope.deleteBasketItems = function(items) {
      var item, j, len, results;
      results = [];
      for (j = 0, len = items.length; j < len; j++) {
        item = items[j];
        results.push(BasketService.deleteItem(item, $scope.bb.company, {
          bb: $scope.bb
        }).then(function(basket) {
          return $scope.setBasket(basket);
        }));
      }
      return results;
    };
    $scope.clearBasketItem = function() {
      var def;
      def = $q.defer();
      $scope.setBasketItem(new BBModel.BasketItem(null, $scope.bb));
      $scope.bb.current_item.reserve_without_questions = $scope.bb.reserve_without_questions;
      if ($scope.bb.default_setup_promises) {
        $q.all($scope.bb.default_setup_promises)['finally'](function() {
          $scope.bb.current_item.setDefaults($scope.bb.item_defaults);
          return $q.all($scope.bb.current_item.promises)['finally'](function() {
            return def.resolve();
          });
        });
      } else {
        def.resolve();
      }
      return def.promise;
    };
    $scope.setBasketItem = function(item) {
      $scope.bb.current_item = item;
      return $scope.current_item = $scope.bb.current_item;
    };
    $scope.setReadyToCheckout = function(ready) {
      return $scope.bb.confirmCheckout = ready;
    };
    $scope.moveToBasket = function() {
      return $scope.bb.basket.addItem($scope.bb.current_item);
    };
    $scope.quickEmptybasket = function(options) {
      var def, preserve_stacked_items;
      preserve_stacked_items = options && options.preserve_stacked_items ? true : false;
      if (!preserve_stacked_items) {
        $scope.bb.stacked_items = [];
        $scope.setBasket(new BBModel.Basket(null, $scope.bb));
        return $scope.clearBasketItem();
      } else {
        $scope.bb.basket = new BBModel.Basket(null, $scope.bb);
        $scope.basket = $scope.bb.basket;
        $scope.bb.basket.company_id = $scope.bb.company_id;
        def = $q.defer();
        def.resolve();
        return def.promise;
      }
    };
    $scope.setBasket = function(basket) {
      $scope.bb.basket = basket;
      $scope.basket = basket;
      $scope.bb.basket.company_id = $scope.bb.company_id;
      if ($scope.bb.stacked_items) {
        return $scope.bb.setStackedItems(basket.timeItems());
      }
    };
    $scope.logout = function(route) {
      if ($scope.client && $scope.client.valid()) {
        return LoginService.logout({
          root: $scope.bb.api_url
        }).then(function() {
          $scope.client = new BBModel.Client();
          return $scope.decideNextPage(route);
        });
      } else if ($scope.member) {
        return LoginService.logout({
          root: $scope.bb.api_url
        }).then(function() {
          $scope.member = new BBModel.Member.Member();
          return $scope.decideNextPage(route);
        });
      }
    };
    $scope.setAffiliate = function(affiliate) {
      $scope.bb.affiliate_id = affiliate.id;
      $scope.bb.affiliate = affiliate;
      $scope.affiliate = affiliate;
      return $scope.affiliate_id = affiliate.id;
    };
    restoreBasket = function() {
      var restore_basket_defer;
      restore_basket_defer = $q.defer();
      $scope.quickEmptybasket().then(function() {
        var auth_token, href, params, status, uri;
        auth_token = $localStorage.getItem('auth_token') || $sessionStorage.getItem('auth_token');
        href = $scope.bb.api_url + '/api/v1/status{?company_id,affiliate_id,clear_baskets,clear_member}';
        params = {
          company_id: $scope.bb.company_id,
          affiliate_id: $scope.bb.affiliate_id,
          clear_baskets: $scope.bb.clear_basket ? '1' : null,
          clear_member: $scope.bb.clear_member ? '1' : null
        };
        uri = new UriTemplate(href).fillFromObject(params);
        status = halClient.$get(uri, {
          "auth_token": auth_token,
          "no_cache": true
        });
        return status.then((function(_this) {
          return function(res) {
            if (res.$has('client')) {
              res.$get('client').then(function(client) {
                if (!$scope.client || ($scope.client && !$scope.client.valid())) {
                  return $scope.client = new BBModel.Client(client);
                }
              });
            }
            if (res.$has('member')) {
              res.$get('member').then(function(member) {
                if (member.client_type !== 'Contact') {
                  member = LoginService.setLogin(member);
                  return $scope.setClient(member);
                }
              });
            }
            if ($scope.bb.clear_basket) {
              return restore_basket_defer.resolve();
            } else {
              if (res.$has('baskets')) {
                return res.$get('baskets').then(function(baskets) {
                  var basket;
                  basket = _.find(baskets, function(b) {
                    return parseInt(b.company_id) === $scope.bb.company_id;
                  });
                  if (basket) {
                    basket = new BBModel.Basket(basket, $scope.bb);
                    return basket.$get('items').then(function(items) {
                      var i, j, len, promises;
                      items = (function() {
                        var j, len, results;
                        results = [];
                        for (j = 0, len = items.length; j < len; j++) {
                          i = items[j];
                          results.push(new BBModel.BasketItem(i));
                        }
                        return results;
                      })();
                      for (j = 0, len = items.length; j < len; j++) {
                        i = items[j];
                        basket.addItem(i);
                      }
                      $scope.setBasket(basket);
                      promises = [].concat.apply([], (function() {
                        var l, len1, results;
                        results = [];
                        for (l = 0, len1 = items.length; l < len1; l++) {
                          i = items[l];
                          results.push(i.promises);
                        }
                        return results;
                      })());
                      return $q.all(promises).then(function() {
                        if (basket.items.length > 0) {
                          $scope.setBasketItem(basket.items[0]);
                        }
                        return restore_basket_defer.resolve();
                      });
                    });
                  } else {
                    return restore_basket_defer.resolve();
                  }
                });
              } else {
                return restore_basket_defer.resolve();
              }
            }
          };
        })(this), function(err) {
          return restore_basket_defer.resolve();
        });
      });
      return restore_basket_defer.promise;
    };
    $scope.setCompany = function(company, keep_basket) {
      var defer;
      defer = $q.defer();
      $scope.bb.company_id = company.id;
      $scope.bb.company = company;
      $scope.company = company;
      $scope.bb.item_defaults.company = $scope.bb.company;
      SettingsService.setCountryCode($scope.bb.company.country_code);
      if (company.$has('settings')) {
        company.getSettings().then((function(_this) {
          return function(settings) {
            $scope.bb.company_settings = settings;
            if ($scope.bb.company_settings.merge_resources) {
              $scope.bb.item_defaults.merge_resources = true;
            }
            if ($scope.bb.company_settings.merge_people) {
              $scope.bb.item_defaults.merge_people = true;
            }
            $rootScope.bb_currency = $scope.bb.company_settings.currency;
            $scope.bb.currency = $scope.bb.company_settings.currency;
            $scope.bb.has_prices = $scope.bb.company_settings.has_prices;
            if (!$scope.bb.basket || ($scope.bb.basket.company_id !== $scope.bb.company_id && !keep_basket)) {
              return restoreBasket().then(function() {
                defer.resolve();
                return $scope.$emit('company:setup');
              });
            } else {
              defer.resolve();
              return $scope.$emit('company:setup');
            }
          };
        })(this));
      } else {
        if (!$scope.bb.basket || ($scope.bb.basket.company_id !== $scope.bb.company_id && !keep_basket)) {
          restoreBasket().then(function() {
            defer.resolve();
            return $scope.$emit('company:setup');
          });
        } else {
          defer.resolve();
          $scope.$emit('company:setup');
        }
      }
      return defer.promise;
    };
    $scope.recordStep = function(step, title) {
      return $scope.bb.recordStep(step, title);
    };
    $scope.setStepTitle = function(title) {
      return $scope.bb.steps[$scope.bb.current_step - 1].title = title;
    };
    $scope.getCurrentStepTitle = function() {
      var steps;
      steps = $scope.bb.steps;
      if (!_.compact(steps).length) {
        steps = $scope.bb.allSteps;
      }
      if ($scope.bb.current_step) {
        return steps[$scope.bb.current_step - 1].title;
      }
    };
    $scope.checkStepTitle = function(title) {
      if (!$scope.bb.steps[$scope.bb.current_step - 1].title) {
        return $scope.setStepTitle(title);
      }
    };
    $scope.loadStep = function(step) {
      var j, len, prev_step, ref, st;
      if (step === $scope.bb.current_step) {
        return;
      }
      $scope.bb.calculatePercentageComplete(step);
      st = $scope.bb.steps[step];
      prev_step = $scope.bb.steps[step - 1];
      if (st && !prev_step) {
        prev_step = st;
      }
      if (!st) {
        st = prev_step;
      }
      if (st && !$scope.bb.last_step_reached) {
        if (!st.stacked_length || st.stacked_length === 0) {
          $scope.bb.stacked_items = [];
        }
        $scope.bb.current_item.loadStep(st.current_item);
        if ($scope.bb.steps.length > 1) {
          $scope.bb.steps.splice(step, $scope.bb.steps.length - step);
        }
        $scope.bb.current_step = step;
        $scope.showPage(prev_step.page, true);
      }
      if ($scope.bb.allSteps) {
        ref = $scope.bb.allSteps;
        for (j = 0, len = ref.length; j < len; j++) {
          step = ref[j];
          step.active = false;
          step.passed = step.number < $scope.bb.current_step;
        }
        if ($scope.bb.allSteps[$scope.bb.current_step - 1]) {
          return $scope.bb.allSteps[$scope.bb.current_step - 1].active = true;
        }
      }
    };

    /***
    * @ngdoc method
    * @name loadPreviousStep
    * @methodOf BB.Directives:bbWidget
    * @description
    * Loads the previous unskipped step
    *
    * @param {integer} steps_to_go_back: The number of steps to go back
    * @param {string} caller: The method that called this function
     */
    $scope.loadPreviousStep = function(caller) {
      var ignore_browser_history_sync, last_step, pages_to_remove_from_history, past_steps, step_to_load;
      past_steps = _.without($scope.bb.steps, _.last($scope.bb.steps));
      step_to_load = 0;
      while (past_steps[0]) {
        last_step = past_steps.pop();
        if (!last_step) {
          break;
        }
        if (!last_step.skipped) {
          step_to_load = last_step.number;
          break;
        }
      }
      pages_to_remove_from_history = step_to_load === 0 ? $scope.bb.current_step + 1 : $scope.bb.current_step - step_to_load;
      if (caller === "locationChangeStart") {
        pages_to_remove_from_history--;
      }
      ignore_browser_history_sync = $scope.history_at_widget_init === window.history.length;
      if ((pages_to_remove_from_history != null) && pages_to_remove_from_history > 0 && !ignore_browser_history_sync) {
        window.history.go(pages_to_remove_from_history * -1);
      }
      return $scope.loadStep(step_to_load);
    };
    $scope.loadStepByPageName = function(page_name) {
      var j, len, ref, step;
      ref = $scope.bb.allSteps;
      for (j = 0, len = ref.length; j < len; j++) {
        step = ref[j];
        if (step.page === page_name) {
          return $scope.loadStep(step.number);
        }
      }
      return $scope.loadStep(1);
    };
    $scope.reset = function() {
      $rootScope.$broadcast('clear:formData');
      $rootScope.$broadcast('widget:restart');
      $scope.setLastSelectedDate(null);
      $scope.client = new BBModel.Client();
      $scope.bb.last_step_reached = false;
      return $scope.bb.steps.splice(1);
    };
    $scope.restart = function() {
      $scope.reset();
      return $scope.loadStep(1);
    };
    $scope.setRoute = function(rdata) {
      return $scope.bb.setRoute(rdata);
    };
    $scope.setBasicRoute = function(routes) {
      return $scope.bb.setBasicRoute(routes);
    };

    /***
    * @ngdoc method
    * @name skipThisStep
    * @methodOf BB.Directives:bbWidget
    * @description
    * Marks the current step as skipped
     */
    $scope.skipThisStep = function() {
      if ($scope.bb.steps[$scope.bb.steps.length - 1]) {
        return $scope.bb.steps[$scope.bb.steps.length - 1].skipped = true;
      }
    };
    $scope.setUsingBasket = (function(_this) {
      return function(usingBasket) {
        return $scope.bb.usingBasket = usingBasket;
      };
    })(this);
    $scope.setClient = (function(_this) {
      return function(client) {
        $scope.client = client;
        if (client.postcode && !$scope.bb.postcode) {
          return $scope.bb.postcode = client.postcode;
        }
      };
    })(this);
    $scope.clearClient = (function(_this) {
      return function() {
        $scope.client = new BBModel.Client();
        if ($window.bb_setup) {
          $scope.client.setDefaults($window.bb_setup);
        }
        if ($scope.bb.client_defaults) {
          return $scope.client.setDefaults($scope.bb.client_defaults);
        }
      };
    })(this);
    $scope.today = moment().toDate();
    $scope.tomorrow = moment().add(1, 'days').toDate();
    $scope.parseDate = (function(_this) {
      return function(d) {
        return moment(d);
      };
    })(this);
    $scope.getUrlParam = (function(_this) {
      return function(param) {
        return $window.getURIparam(param);
      };
    })(this);
    $scope.base64encode = (function(_this) {
      return function(param) {
        return $window.btoa(param);
      };
    })(this);
    $scope.setLastSelectedDate = (function(_this) {
      return function(date) {
        return $scope.last_selected_date = date;
      };
    })(this);
    $scope.setLoaded = function(cscope) {
      var loadingFinished;
      cscope.$emit('hide:loader', cscope);
      cscope.isLoaded = true;
      loadingFinished = true;
      while (cscope) {
        if (cscope.hasOwnProperty('scopeLoaded')) {
          if ($scope.areScopesLoaded(cscope)) {
            cscope.scopeLoaded = true;
          } else {
            loadingFinished = false;
          }
        }
        cscope = cscope.$parent;
      }
      if (loadingFinished) {
        $rootScope.$broadcast('loading:finished');
      }
    };
    $scope.setLoadedAndShowError = function(scope, err, error_string) {
      $log.warn(err, error_string);
      scope.setLoaded(scope);
      if (err && err.status === 409) {
        return AlertService.danger(ErrorService.getError('ITEM_NO_LONGER_AVAILABLE'));
      } else if (err && err.data && err.data.error === "Number of Bookings exceeds the maximum") {
        return AlertService.danger(ErrorService.getError('MAXIMUM_TICKETS'));
      } else {
        return AlertService.danger(ErrorService.getError('GENERIC'));
      }
    };
    $scope.areScopesLoaded = function(cscope) {
      var child;
      if (cscope.hasOwnProperty('isLoaded') && !cscope.isLoaded) {
        return false;
      } else {
        child = cscope.$$childHead;
        while (child) {
          if (!$scope.areScopesLoaded(child)) {
            return false;
          }
          child = child.$$nextSibling;
        }
        return true;
      }
    };
    $scope.notLoaded = function(cscope) {
      $scope.$emit('show:loader', $scope);
      cscope.isLoaded = false;
      while (cscope) {
        if (cscope.hasOwnProperty('scopeLoaded')) {
          cscope.scopeLoaded = false;
        }
        cscope = cscope.$parent;
      }
    };
    $scope.broadcastItemUpdate = (function(_this) {
      return function() {
        return $scope.$broadcast("currentItemUpdate", $scope.bb.current_item);
      };
    })(this);
    $scope.hidePage = function() {
      return $scope.hide_page = true;
    };
    $scope.bb.company_set = function() {
      return $scope.bb.company_id != null;
    };
    $scope.isAdmin = function() {
      return $scope.bb.isAdmin;
    };
    $scope.isAdminIFrame = function() {
      var err, error, location;
      if (!$scope.bb.isAdmin) {
        return false;
      }
      try {
        location = $window.parent.location.href;
        if (location && $window.parent.reload_dashboard) {
          return true;
        } else {
          return false;
        }
      } catch (error) {
        err = error;
        return false;
      }
    };
    $scope.reloadDashboard = function() {
      return $window.parent.reload_dashboard();
    };
    $scope.$debounce = function(tim) {
      if ($scope._debouncing) {
        return false;
      }
      tim || (tim = 100);
      $scope._debouncing = true;
      return $timeout(function() {
        return $scope._debouncing = false;
      }, tim);
    };
    $scope.supportsTouch = function() {
      return Modernizr.touch;
    };
    $rootScope.$on('show:loader', function() {
      return $scope.loading = true;
    });
    $rootScope.$on('hide:loader', function() {
      return $scope.loading = false;
    });
    $scope.isMemberLoggedIn = function() {
      return LoginService.isLoggedIn();
    };
    $scope.scrollTo = function(id) {
      $location.hash(id);
      return $anchorScroll();
    };
    return $scope.redirectTo = function(url) {
      return $window.location.href = url;
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbMiniBasket
  * @restrict AE
  * @scope true
  *
  * @description
  * Loads a list of mini basket for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {boolean} setUsingBasket Set using basket  or not
   */
  angular.module('BB.Directives').directive('bbMiniBasket', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: function($scope, $rootScope, BasketService, $q) {
        $scope.controller = "public.controllers.MiniBasket";
        return $scope.setUsingBasket(true);
      }
    };
  });

  angular.module('BB.Directives').directive('bbBasketList', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'BasketList'
    };
  });

  angular.module('BB.Controllers').controller('BasketList', function($scope, $element, $attrs, $rootScope, BasketService, $q, AlertService, FormDataStoreService, LoginService) {
    $scope.controller = "public.controllers.BasketList";
    $scope.setUsingBasket(true);
    $scope.show_wallet = $scope.bb.company_settings.hasOwnProperty('has_wallets') && $scope.bb.company_settings.has_wallets && $scope.client.valid() && LoginService.isLoggedIn() && LoginService.member().id === $scope.client.id && $scope.client.has_active_wallet;
    $scope.bb.basket.setSettings($scope.$eval($attrs.bbBasketList || {}));
    $rootScope.connection_started.then(function() {
      var basket_item, i, len, params, promises, ref;
      if ($scope.client) {
        $scope.bb.basket.setClient($scope.client);
      }
      if ($scope.client.$has('pre_paid_bookings') && $scope.bb.basket.timeItems().length > 0) {
        $scope.notLoaded($scope);
        promises = [];
        ref = $scope.bb.basket.timeItems();
        for (i = 0, len = ref.length; i < len; i++) {
          basket_item = ref[i];
          params = {
            event_id: basket_item.getEventId()
          };
          promises.push($scope.client.getPrePaidBookingsPromise(params));
        }
        return $q.all(promises).then(function(result) {
          var booking_left, index, j, k, l, len1, len2, len3, len4, m, prepaid_booking, prepaid_bookings, ref1;
          booking_left = {};
          for (j = 0, len1 = result.length; j < len1; j++) {
            basket_item = result[j];
            for (k = 0, len2 = basket_item.length; k < len2; k++) {
              prepaid_booking = basket_item[k];
              booking_left[prepaid_booking.id] = prepaid_booking.number_of_bookings_remaining;
            }
          }
          ref1 = $scope.bb.basket.timeItems();
          for (index = l = 0, len3 = ref1.length; l < len3; index = ++l) {
            basket_item = ref1[index];
            prepaid_bookings = result[index];
            if ($scope.bb.basket.settings && $scope.bb.basket.settings.auto_use_prepaid_bookings && prepaid_bookings.length > 0 && basket_item.price > 0) {
              for (index = m = 0, len4 = prepaid_bookings.length; m < len4; index = ++m) {
                prepaid_booking = prepaid_bookings[index];
                if (booking_left[prepaid_booking.id] > 0) {
                  basket_item.setPrepaidBooking(prepaid_booking);
                  booking_left[prepaid_booking.id] -= 1;
                  break;
                }
              }
            }
          }
          return $scope.updateBasket().then(function() {
            return $scope.setLoaded($scope);
          });
        }, function(err) {
          return $scope.setLoaded($scope);
        });
      }
    });

    /***
    * @ngdoc method
    * @name addAnother
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Add another basket item in acording of route parameter
    *
    * @param {string} route A route of the added another item
     */
    $scope.addAnother = (function(_this) {
      return function(route) {
        $scope.clearBasketItem();
        $scope.bb.emptyStackedItems();
        $scope.bb.current_item.setCompany($scope.bb.company);
        return $scope.restart();
      };
    })(this);

    /***
    * @ngdoc method
    * @name checkout
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Reset the basket to the last item whereas the curren_item is not complete and should not be in the basket and that way, we can proceed to checkout instead of hard-coding it on the html page.
    *
    * @param {string} route A route of the added another item
     */
    $scope.checkout = (function(_this) {
      return function(route) {
        if ($scope.bb.basket.settings && $scope.bb.basket.settings.requires_deal && !$scope.bb.basket.hasDeal()) {
          AlertService.raise('GIFT_CERTIFICATE_REQUIRED');
          return false;
        }
        if ($scope.bb.basket.items.length > 0) {
          $scope.setReadyToCheckout(true);
          if ($scope.$parent.$has_page_control) {
            return true;
          } else {
            return $scope.decideNextPage(route);
          }
        } else {
          AlertService.raise('EMPTY_BASKET_FOR_CHECKOUT');
          return false;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Set this page section as ready
     */
    $scope.setReady = function() {
      return $scope.checkout();
    };

    /***
    * @ngdoc method
    * @name applyCoupon
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Apply the coupon of basket item in according of coupon parameter
    *
    * @param {string} coupon The applied coupon
     */
    $scope.applyCoupon = (function(_this) {
      return function(coupon) {
        var params;
        AlertService.clear();
        $scope.notLoaded($scope);
        params = {
          bb: $scope.bb,
          coupon: coupon
        };
        return BasketService.applyCoupon($scope.bb.company, params).then(function(basket) {
          var i, item, len, ref;
          ref = basket.items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            item.storeDefaults($scope.bb.item_defaults);
            item.reserve_without_questions = $scope.bb.reserve_without_questions;
          }
          basket.setSettings($scope.bb.basket.settings);
          $scope.setBasket(basket);
          return $scope.setLoaded($scope);
        }, function(err) {
          if (err && err.data && err.data.error) {
            AlertService.clear();
            AlertService.add("danger", {
              msg: err.data.error
            });
          }
          return $scope.setLoaded($scope);
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name applyDeal
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Apply the coupon of basket item in according of deal code parameter
    *
    * @param {string} deal code The deal code
     */
    $scope.applyDeal = (function(_this) {
      return function(deal_code) {
        var params;
        AlertService.clear();
        if ($scope.client) {
          params = {
            bb: $scope.bb,
            deal_code: deal_code,
            member_id: $scope.client.id
          };
        } else {
          params = {
            bb: $scope.bb,
            deal_code: deal_code,
            member_id: null
          };
        }
        return BasketService.applyDeal($scope.bb.company, params).then(function(basket) {
          var i, item, len, ref;
          ref = basket.items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            item.storeDefaults($scope.bb.item_defaults);
            item.reserve_without_questions = $scope.bb.reserve_without_questions;
          }
          basket.setSettings($scope.bb.basket.settings);
          $scope.setBasket(basket);
          $scope.items = $scope.bb.basket.items;
          return $scope.deal_code = null;
        }, function(err) {
          if (err && err.data && err.data.error) {
            AlertService.clear();
            return AlertService.add("danger", {
              msg: err.data.error
            });
          }
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name removeDeal
    * @methodOf BB.Directives:bbMiniBasket
    * @description
    * Remove the deal in according of deal code parameter
    *
    * @param {string} deal code The deal code
     */
    $scope.removeDeal = (function(_this) {
      return function(deal_code) {
        var params;
        params = {
          bb: $scope.bb,
          deal_code_id: deal_code.id
        };
        return BasketService.removeDeal($scope.bb.company, params).then(function(basket) {
          var i, item, len, ref;
          ref = basket.items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            item.storeDefaults($scope.bb.item_defaults);
            item.reserve_without_questions = $scope.bb.reserve_without_questions;
          }
          basket.setSettings($scope.bb.basket.settings);
          $scope.setBasket(basket);
          return $scope.items = $scope.bb.basket.items;
        }, function(err) {
          if (err && err.data && err.data.error) {
            AlertService.clear();
            return AlertService.add("danger", {
              msg: err.data.error
            });
          }
        });
      };
    })(this);
    return $scope.topUpWallet = function() {
      return $scope.decideNextPage("basket_wallet");
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbBulkPurchases
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of bulk purchases for the currently in scroe company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbBulkPurchases   A hash of options
  * @property {array} bulk_purchases An array of all services
  * @property {array} bookable_items An array of all BookableItems - used if the current_item has already selected a resource or person
  * @property {bulk_purchase} bulk_purchase The currectly selected bulk_purchase
  * @example
  *  <example module="BB"> 
  *    <file name="index.html">
  *   <div bb-api-url='https://uk.bookingbug.com'>
  *   <div  bb-widget='{company_id:21}'>
  *     <div bb-bulk-purchases>
  *        <ul>
  *          <li ng-repeat='bulk in bulk_purchases'> {{bulk.name}}</li>
  *        </ul>
  *     </div>
  *     </div>
  *     </div>
  *   </file> 
  *  </example>
  *
   */
  angular.module('BB.Directives').directive('bbBulkPurchases', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'BulkPurchase'
    };
  });

  angular.module('BB.Controllers').controller('BulkPurchase', function($scope, $rootScope, BulkPurchaseService) {
    $scope.controller = "public.controllers.BulkPurchase";
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        return $scope.init($scope.bb.company);
      }
    });
    $scope.init = function(company) {
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      return BulkPurchaseService.query(company).then(function(bulk_purchases) {
        return $scope.bulk_purchases = bulk_purchases;
      });
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbBulkPurchases
    * @description
    * Select a bulk purchase into the current booking journey and route on to the next page dpending on the current page control
    *
    * @param {object} package Bulk_purchase or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = function(item, route) {
      if ($scope.$parent.$has_page_control) {
        $scope.bulk_purchase = item;
        return false;
      } else {
        $scope.booking_item.setBulkPurchase(item);
        $scope.decideNextPage(route);
        return true;
      }
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbBulkPurchases
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    return $scope.setReady = (function(_this) {
      return function() {
        if ($scope.bulk_purchase) {
          $scope.booking_item.setBulkPurchase($scope.bulk_purchase);
          return true;
        } else {
          return false;
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbCategories
  * @restrict AE
  * @scope true
  *
  * @description
  * Loads a list of categories for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {string} name The category name
  * @property {integer} id The category id
  * @example
  *  <example module="BB"> 
  *    <file name="index.html">
  *   <div bb-api-url='https://uk.bookingbug.com'>
  *   <div  bb-widget='{company_id:21}'>
  *     <div bb-categories>
  *        <ul>
  *          <li ng-repeat='category in items'>name: {{category.name}}</li>
  *        </ul>
  *     </div>
  *     </div>
  *     </div>
  *   </file> 
  *  </example>
  *
   */
  angular.module('BB.Directives').directive('bbCategories', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'CategoryList'
    };
  });

  angular.module('BB.Controllers').controller('CategoryList', function($scope, $rootScope, CategoryService, $q, PageControllerService) {
    $scope.controller = "public.controllers.CategoryList";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.company) {
          return $scope.init($scope.bb.company);
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = (function(_this) {
      return function(comp) {
        return CategoryService.query(comp).then(function(items) {
          $scope.items = items;
          if (items.length === 1) {
            $scope.skipThisStep();
            $rootScope.categories = items;
            $scope.selectItem(items[0], $scope.nextRoute);
          }
          return $scope.setLoaded($scope);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbCategories
    * @description
    * Select an item 
    *
    * @param {object} item The Service or BookableItem to select
    * @param {string=} route A specific route to load
     */
    return $scope.selectItem = (function(_this) {
      return function(item, route) {
        $scope.bb.current_item.setCategory(item);
        return $scope.decideNextPage(route);
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbCheckout
  * @restrict AE
  * @scope true
  *
  * @description
  * Loads a list of checkouts for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbCheckout   A hash of options
  * @property {string} loadingTotal The loading total
  * @property {string} skipThisStep The skip this step
  * @property {string} decideNextPage The decide next page
  * @property {boolean} checkoutSuccess The checkout success
  * @property {string} setLoaded The set loaded
  * @property {string} setLoadedAndShowError The set loaded and show error
  * @property {boolean} checkoutFailed The checkout failed
   */
  angular.module('BB.Directives').directive('bbCheckout', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Checkout'
    };
  });

  angular.module('BB.Controllers').controller('Checkout', function($scope, $rootScope, $attrs, BasketService, $q, $location, $window, $bbug, FormDataStoreService, $timeout) {
    $scope.controller = "public.controllers.Checkout";
    $scope.notLoaded($scope);
    $scope.options = $scope.$eval($attrs.bbCheckout) || {};
    FormDataStoreService.destroy($scope);
    $rootScope.connection_started.then((function(_this) {
      return function() {
        $scope.bb.basket.setClient($scope.client);
        if ($scope.options.no_notifications) {
          $scope.bb.no_notifications = $scope.options.no_notifications;
        }
        $scope.loadingTotal = BasketService.checkout($scope.bb.company, $scope.bb.basket, {
          bb: $scope.bb
        });
        return $scope.loadingTotal.then(function(total) {
          $scope.total = total;
          if (!total.$has('new_payment')) {
            $scope.$emit("checkout:success", total);
            $scope.bb.total = $scope.total;
            $scope.bb.payment_status = 'complete';
            if (!$scope.options.disable_confirmation) {
              $scope.skipThisStep();
              $scope.decideNextPage();
            } else {
              $scope.reset();
            }
          }
          $scope.checkoutSuccess = true;
          return $scope.setLoaded($scope);
        }, function(err) {
          $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          $scope.checkoutFailed = true;
          return $scope.$emit("checkout:fail", err);
        });
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name print
    * @methodOf BB.Directives:bbCheckout
    * @description
    * Print booking details using print_purchase.html template
    *
     */
    $scope.print = (function(_this) {
      return function() {
        $window.open($scope.bb.partial_url + 'print_purchase.html?id=' + $scope.total.long_id, '_blank', 'width=700,height=500,toolbar=0,menubar=0,location=0,status=1,scrollbars=1,resizable=1,left=0,top=0');
        return true;
      };
    })(this);

    /***
    * @ngdoc method
    * @name printElement
    * @methodOf BB.Directives:bbCheckout
    * @description
    * Print by creating popup containing the contents of the specified element
    *
    * @param {integer} id The id of the specified element
    * @param {string} stylesheet The stylesheet of popup
     */
    return $scope.printElement = function(id, stylesheet) {
      var data, mywindow;
      data = $bbug('#' + id).html();
      mywindow = $window.open('', '', 'height=600,width=800');
      return $timeout(function() {
        mywindow.document.write('<html><head><title>Booking Confirmation</title>');
        if (stylesheet) {
          mywindow.document.write('<link rel="stylesheet" href="' + stylesheet + '" type="text/css" />');
        }
        mywindow.document.write('</head><body>');
        mywindow.document.write(data);
        mywindow.document.write('</body></html>');
        return $timeout(function() {
          mywindow.document.close();
          mywindow.focus();
          mywindow.print();
          return mywindow.close();
        }, 100);
      }, 2000);
    };
  });

}).call(this);


/***
* @ngdoc directive
* @name BB.Directives:bbClientDetails
* @restrict AE
* @scope true
*
* @description
* Loads a list of client details for the currently in scope company
*
* <pre>
* restrict: 'AE'
* replace: true
* scope: true
* </pre>
*
* @property {array} questions Questions of the client
* @property {integer} company_id The company id of the client company
* @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
* @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
* @example
*  <example module="BB">
*    <file name="index.html">
*   <div bb-api-url='https://uk.bookingbug.com'>
*   <div  bb-widget='{company_id:21}'>
*     <div bb-client-details>
*        <p>company_id: {{client_details.company_id}}</p>
*        <p>offer_login: {{client_details.offer_login}}</p>
*        <p>ask_address: {{client_details.ask_address}}</p>
*        <p>no_phone: {{client_details.no_phone}}</p>
*      </div>
*     </div>
*     </div>
*   </file>
*  </example>
*
 */

(function() {
  angular.module('BB.Directives').directive('bbClientDetails', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'ClientDetails'
    };
  });

  angular.module('BB.Controllers').controller('ClientDetails', function($scope, $attrs, $rootScope, ClientDetailsService, ClientService, LoginService, BBModel, ValidatorService, QuestionService, AlertService) {
    var handleError, options;
    $scope.controller = "public.controllers.ClientDetails";
    $scope.notLoaded($scope);
    $scope.validator = ValidatorService;
    $scope.existing_member = false;
    $scope.login_error = false;
    options = $scope.$eval($attrs.bbClientDetails) || {};
    $scope.suppress_client_create = ($attrs.bbSuppressCreate != null) || options.suppress_client_create;
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if (!$scope.client.valid() && LoginService.isLoggedIn()) {
          $scope.setClient(new BBModel.Client(LoginService.member()._data));
        }
        if (LoginService.isLoggedIn() && LoginService.member().$has("child_clients") && LoginService.member()) {
          LoginService.member().getChildClientsPromise().then(function(children) {
            $scope.bb.parent_client = new BBModel.Client(LoginService.member()._data);
            $scope.bb.child_clients = children;
            return $scope.bb.basket.parent_client_id = $scope.bb.parent_client.id;
          });
        }
        if ($scope.client.client_details) {
          $scope.client_details = $scope.client.client_details;
          if ($scope.client_details.questions) {
            QuestionService.checkConditionalQuestions($scope.client_details.questions);
          }
          return $scope.setLoaded($scope);
        } else {
          return ClientDetailsService.query($scope.bb.company).then(function(details) {
            $scope.client_details = details;
            if ($scope.client) {
              $scope.client.pre_fill_answers($scope.client_details);
            }
            if ($scope.client_details.questions) {
              QuestionService.checkConditionalQuestions($scope.client_details.questions);
            }
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $rootScope.$watch('member', (function(_this) {
      return function(oldmem, newmem) {
        if (!$scope.client.valid() && LoginService.isLoggedIn()) {
          return $scope.setClient(new BBModel.Client(LoginService.member()._data));
        }
      };
    })(this));

    /***
    * @ngdoc method
    * @name validateClient
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Validate the client
    *
    * @param {object} client_form The client form
    * @param {string=} route A specific route to load
     */
    $scope.validateClient = (function(_this) {
      return function(client_form, route) {
        $scope.notLoaded($scope);
        $scope.existing_member = false;
        if ($scope.bb && $scope.bb.parent_client) {
          $scope.client.parent_client_id = $scope.bb.parent_client.id;
        }
        $scope.client.setClientDetails($scope.client_details);
        return ClientService.create_or_update($scope.bb.company, $scope.client).then(function(client) {
          $scope.setLoaded($scope);
          $scope.setClient(client);
          if ($scope.bb.isAdmin) {
            $scope.client.setValid(true);
          }
          $scope.existing_member = false;
          return $scope.decideNextPage(route);
        }, function(err) {
          return handleError(err);
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name clientLogin
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Client login
     */
    $scope.clientLogin = (function(_this) {
      return function() {
        $scope.login_error = false;
        if ($scope.login) {
          return LoginService.companyLogin($scope.bb.company, {}, {
            email: $scope.login.email,
            password: $scope.login.password
          }).then(function(client) {
            $scope.setClient(new BBModel.Client(client));
            $scope.login_error = false;
            return $scope.decideNextPage();
          }, function(err) {
            $scope.login_error = true;
            $scope.setLoaded($scope);
            return AlertService.raise('LOGIN_FAILED');
          });
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    $scope.setReady = (function(_this) {
      return function() {
        var prom;
        $scope.client.setClientDetails($scope.client_details);
        if (!$scope.suppress_client_create) {
          prom = ClientService.create_or_update($scope.bb.company, $scope.client);
          prom.then(function(client) {
            $scope.setLoaded($scope);
            $scope.setClient(client);
            if (client.waitingQuestions) {
              return client.gotQuestions.then(function() {
                return $scope.client_details = client.client_details;
              });
            }
          }, function(err) {
            return handleError(err);
          });
          return prom;
        } else {
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name clientSearch
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Client search
     */
    $scope.clientSearch = function() {
      if (($scope.client != null) && ($scope.client.email != null) && $scope.client.email !== "") {
        $scope.notLoaded($scope);
        return ClientService.query_by_email($scope.bb.company, $scope.client.email).then(function(client) {
          if (client != null) {
            $scope.setClient(client);
            $scope.client = client;
          }
          return $scope.setLoaded($scope);
        }, function(err) {
          return $scope.setLoaded($scope);
        });
      } else {
        $scope.setClient({});
        return $scope.client = {};
      }
    };

    /***
    * @ngdoc method
    * @name switchNumber
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Switch number
    *
    * @param {array} to Switch number to mobile
     */
    $scope.switchNumber = function(to) {
      $scope.no_mobile = !$scope.no_mobile;
      if (to === 'mobile') {
        $scope.bb.basket.setSettings({
          send_sms_reminder: true
        });
        return $scope.client.phone = null;
      } else {
        $scope.bb.basket.setSettings({
          send_sms_reminder: false
        });
        return $scope.client.mobile = null;
      }
    };

    /***
    * @ngdoc method
    * @name getQuestion
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Get question by id
    *
    * @param {integer} id The id question
     */
    $scope.getQuestion = function(id) {
      var i, len, question, ref;
      ref = $scope.client_details.questions;
      for (i = 0, len = ref.length; i < len; i++) {
        question = ref[i];
        if (question.id === id) {
          return question;
        }
      }
      return null;
    };

    /***
    * @ngdoc method
    * @name useClient
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Use client by client
    *
    * @param {array} client The client
     */
    $scope.useClient = function(client) {
      return $scope.setClient(client);
    };

    /***
    * @ngdoc method
    * @name recalc_question
    * @methodOf BB.Directives:bbClientDetails
    * @description
    * Recalculate question
     */
    $scope.recalc_question = function() {
      if ($scope.client_details.questions) {
        return QuestionService.checkConditionalQuestions($scope.client_details.questions);
      }
    };
    return handleError = function(error) {
      if (error.data.error === "Please Login") {
        $scope.existing_member = true;
        AlertService.raise('ALREADY_REGISTERED');
      } else if (error.data.error === "Invalid Password") {
        AlertService.raise('PASSWORD_INVALID');
      }
      return $scope.setLoaded($scope);
    };
  });

}).call(this);

(function() {
  'use strict';
  var CompanyListBase;

  CompanyListBase = function($scope, $rootScope, $q, $attrs) {
    var options;
    $scope.controller = "public.controllers.CompanyList";
    $scope.notLoaded($scope);
    options = $scope.$eval($attrs.bbCompanies);
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.company.companies) {
          $scope.init($scope.bb.company);
          return $rootScope.parent_id = $scope.bb.company.id;
        } else if ($rootScope.parent_id) {
          $scope.initWidget({
            company_id: $rootScope.parent_id,
            first_page: $scope.bb.current_page
          });
        } else {
          return $scope.init($scope.bb.company);
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = (function(_this) {
      return function(comp) {
        $scope.companies = $scope.bb.company.companies;
        if (!$scope.companies || $scope.companies.length === 0) {
          $scope.companies = [$scope.bb.company];
        }
        if ($scope.companies.length === 1) {
          $scope.skipThisStep();
          $scope.selectItem($scope.companies[0]);
        } else {
          if (options && options.hide_not_live_stores) {
            $scope.items = $scope.companies.filter(function(c) {
              return c.live;
            });
          } else {
            $scope.items = $scope.companies;
          }
        }
        return $scope.setLoaded($scope);
      };
    })(this);
    $scope.selectItem = (function(_this) {
      return function(item, route) {
        var company_id, prms;
        if (angular.isNumber(item)) {
          company_id = item;
        } else {
          company_id = item.id;
        }
        $scope.notLoaded($scope);
        prms = {
          company_id: company_id
        };
        return $scope.initWidget(prms);
      };
    })(this);
    return $scope.splitString = function(company) {
      var arr, result;
      arr = company.name.split(' ');
      return result = arr[2] ? arr[2] : "";
    };
  };


  /***
  * @ngdoc directive
  * @name BB.Directives:bbCompanies
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of companies for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {integer} id The company id
  * @property {string} name The company name
  * @property {integer} address_id Company address id
  * @property {string} country_code Company country code
  * @property {string} currency_code The company currency code
  * @property {string} timezone The company time zone
  * @property {integer} numeric_widget_id The numeric widget id of the company
  * @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
  * @example
  *  <example module="BB"> 
  *    <file name="index.html">
  *   <div bb-api-url='https://uk.bookingbug.com'>
  *   <div  bb-widget='{company_id:21}'>
  *     <div bb-company>
  *       <p>id: {{company.id}}</p>
  *        <p>name: {{company.name}}</p>
  *        <p>address_id: {{company.address_id}}</p>
  *        <p>country_code: {{company.country_code}}</p>
  *        <p>currency_code: {{company.country_code}}</p>
  *        <p>timezone: {{company.timezone}}</p>
  *        <p>numeric_widget_id: {{company.numeric_widget_id}}</p>
  *      </div>
  *     </div>
  *     </div>
  *   </file> 
  *  </example>
   */

  angular.module('BB.Directives').directive('bbCompanies', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'CompanyList'
    };
  });

  angular.module('BB.Controllers').controller('CompanyList', CompanyListBase);

  angular.module('BB.Directives').directive('bbPostcodeLookup', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PostcodeLookup'
    };
  });

  angular.module('BB.Controllers').controller('PostcodeLookup', function($scope, $rootScope, $q, ValidatorService, AlertService, $attrs) {
    $scope.controller = "PostcodeLookup";
    angular.extend(this, new CompanyListBase($scope, $rootScope, $q, $attrs));
    $scope.validator = ValidatorService;

    /***
    * @ngdoc method
    * @name searchPostcode
    * @methodOf BB.Directives:bbCompanies
    * @description
    * Search the postcode
    *
    * @param {object} form The form where postcode has been searched
    * @param {object} prms The parameters of postcode searching
     */
    $scope.searchPostcode = (function(_this) {
      return function(form, prms) {
        var promise;
        $scope.notLoaded($scope);
        promise = ValidatorService.validatePostcode(form, prms);
        if (promise) {
          return promise.then(function() {
            var loc;
            $scope.bb.postcode = ValidatorService.getGeocodeResult().address_components[0].short_name;
            $scope.postcode = $scope.bb.postcode;
            loc = ValidatorService.getGeocodeResult().geometry.location;
            return $scope.selectItem($scope.getNearestCompany({
              center: loc
            }));
          }, function(err) {
            return $scope.setLoaded($scope);
          });
        } else {
          return $scope.setLoaded($scope);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name getNearestCompany
    * @methodOf BB.Directives:bbCompanies
    * @description
    * Get nearest company in according of center parameter
    * 
    * @param {string} center Geolocation parameter
     */
    return $scope.getNearestCompany = (function(_this) {
      return function(arg) {
        var R, a, c, center, chLat, chLon, company, d, dLat, dLon, distances, i, lat1, lat2, latlong, len, lon1, lon2, pi, rLat1, rLat2, ref;
        center = arg.center;
        pi = Math.PI;
        R = 6371;
        distances = [];
        lat1 = center.lat();
        lon1 = center.lng();
        ref = $scope.items;
        for (i = 0, len = ref.length; i < len; i++) {
          company = ref[i];
          if (company.address.lat && company.address.long && company.live) {
            latlong = new google.maps.LatLng(company.address.lat, company.address.long);
            lat2 = latlong.lat();
            lon2 = latlong.lng();
            chLat = lat2 - lat1;
            chLon = lon2 - lon1;
            dLat = chLat * (pi / 180);
            dLon = chLon * (pi / 180);
            rLat1 = lat1 * (pi / 180);
            rLat2 = lat2 * (pi / 180);
            a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(rLat1) * Math.cos(rLat2);
            c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
            d = R * c;
            company.distance = d;
            distances.push(company);
          }
          distances.sort(function(a, b) {
            return a.distance - b.distance;
          });
        }
        return distances[0];
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbCustomBookingText
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of custom booking text for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {string} messages The messages text
  * @property {string} setLoaded Loading set of custom text
  * @property {object} setLoadedAndShowError Set loaded and show error
   */
  angular.module('BB.Directives').directive('bbCustomBookingText', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'CustomBookingText'
    };
  });

  angular.module('BB.Controllers').controller('CustomBookingText', function($scope, $rootScope, CustomTextService, $q) {
    $scope.controller = "public.controllers.CustomBookingText";
    $scope.notLoaded($scope);
    return $rootScope.connection_started.then((function(_this) {
      return function() {
        return CustomTextService.BookingText($scope.bb.company, $scope.bb.current_item).then(function(msgs) {
          $scope.messages = msgs;
          return $scope.setLoaded($scope);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
  });

  angular.module('BB.Directives').directive('bbCustomConfirmationText', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'CustomConfirmationText'
    };
  });

  angular.module('BB.Controllers').controller('CustomConfirmationText', function($scope, $rootScope, CustomTextService, $q, PageControllerService) {
    $scope.controller = "public.controllers.CustomConfirmationText";
    $scope.notLoaded($scope);
    $rootScope.connection_started.then(function() {
      return $scope.loadData();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name loadData
    * @methodOf BB.Directives:bbCustomBookingText
    * @description
    * Load data and display a text message
     */
    return $scope.loadData = (function(_this) {
      return function() {
        if ($scope.total) {
          return CustomTextService.confirmationText($scope.bb.company, $scope.total).then(function(msgs) {
            $scope.messages = msgs;
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else if ($scope.loadingTotal) {
          return $scope.loadingTotal.then(function(total) {
            return CustomTextService.confirmationText($scope.bb.company, total).then(function(msgs) {
              $scope.messages = msgs;
              return $scope.setLoaded($scope);
            }, function(err) {
              return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
            });
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.setLoaded($scope);
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbMonthAvailability
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of month availability for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {string} message The message text
  * @property {string} setLoaded  Set the day list loaded
  * @property {object} setLoadedAndShowError Set loaded and show error
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbMonthAvailability', function() {
    return {
      restrict: 'A',
      replace: true,
      scope: true,
      controller: 'DayList'
    };
  });

  angular.module('BB.Controllers').controller('DayList', function($scope, $rootScope, $q, DayService, AlertService) {
    $scope.controller = "public.controllers.DayList";
    $scope.notLoaded($scope);
    $scope.WeekHeaders = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun'];
    $scope.day_data = {};
    if (!$scope.type) {
      $scope.type = "month";
    }
    if (!$scope.data_source) {
      $scope.data_source = $scope.bb.current_item;
    }
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if (!$scope.current_date && $scope.last_selected_date) {
          $scope.current_date = $scope.last_selected_date.startOf($scope.type);
        } else if (!$scope.current_date) {
          $scope.current_date = moment().startOf($scope.type);
        }
        return $scope.loadData();
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.$on("currentItemUpdate", function(event) {
      return $scope.loadData();
    });

    /***
    * @ngdoc method
    * @name setCalType
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Set cal type in acording of type
    *
    * @param {array} type The type of day list
     */
    $scope.setCalType = (function(_this) {
      return function(type) {
        return $scope.type = type;
      };
    })(this);

    /***
    * @ngdoc method
    * @name setDataSource
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Set data source in according of source
    *
    * @param {string} source The source of day list
     */
    $scope.setDataSource = (function(_this) {
      return function(source) {
        return $scope.data_source = source;
      };
    })(this);

    /***
    * @ngdoc method
    * @name format_date
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Format date and get current date
    *
    * @param {date} fmt The format date
     */
    $scope.format_date = (function(_this) {
      return function(fmt) {
        if ($scope.current_date) {
          return $scope.current_date.format(fmt);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name format_start_date
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Format start date in according of fmt parameter
    *
    * @param {date} fmt The format date
     */
    $scope.format_start_date = (function(_this) {
      return function(fmt) {
        return $scope.format_date(fmt);
      };
    })(this);

    /***
    * @ngdoc method
    * @name format_end_date
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Format end date in according of fmt parameter
    *
    * @param {date} fmt The format date
     */
    $scope.format_end_date = (function(_this) {
      return function(fmt) {
        if ($scope.end_date) {
          return $scope.end_date.format(fmt);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectDay
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Select day
    *
    * @param {date} day The day
    * @param {string=} route A specific route to load
    * @param {string} force The force
     */
    $scope.selectDay = (function(_this) {
      return function(day, route, force) {
        if (day.spaces === 0 && !force) {
          return false;
        }
        $scope.setLastSelectedDate(day.date);
        $scope.bb.current_item.setDate(day);
        if ($scope.$parent.$has_page_control) {

        } else {
          return $scope.decideNextPage(route);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setMonth
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Set month
    *
    * @param {date} month The month
    * @param {date} year The year
     */
    $scope.setMonth = (function(_this) {
      return function(month, year) {
        $scope.current_date = moment().startOf('month').year(year).month(month - 1);
        $scope.current_date.year();
        return $scope.type = "month";
      };
    })(this);

    /***
    * @ngdoc method
    * @name setWeek
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Set month
    *
    * @param {date} week The week
    * @param {date} year The year
     */
    $scope.setWeek = (function(_this) {
      return function(week, year) {
        $scope.current_date = moment().year(year).isoWeek(week).startOf('week');
        $scope.current_date.year();
        return $scope.type = "week";
      };
    })(this);

    /***
    * @ngdoc method
    * @name add
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Add the current date in according of type and amount parameters
    *
    * @param {string} type The type
    * @param {string} amount The amount
     */
    $scope.add = (function(_this) {
      return function(type, amount) {
        $scope.current_date.add(amount, type);
        return $scope.loadData();
      };
    })(this);

    /***
    * @ngdoc method
    * @name subtract
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Substract the current date in according of type and amount
    *
    * @param {string} type The type
    * @param {string} amount The amount
     */
    $scope.subtract = (function(_this) {
      return function(type, amount) {
        return $scope.add(type, -amount);
      };
    })(this);

    /***
    * @ngdoc method
    * @name isPast
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Calculate if the current earlist date is in the past - in which case we might want to disable going backwards
     */
    $scope.isPast = (function(_this) {
      return function() {
        if (!$scope.current_date) {
          return true;
        }
        return moment().isAfter($scope.current_date);
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadData
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Load week if type is equals with week else load month
     */
    $scope.loadData = (function(_this) {
      return function() {
        if ($scope.type === "week") {
          return $scope.loadWeek();
        } else {
          return $scope.loadMonth();
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadMonth
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Load month
     */
    $scope.loadMonth = (function(_this) {
      return function() {
        var date, edate;
        date = $scope.current_date;
        $scope.month = date.month();
        $scope.notLoaded($scope);
        edate = moment(date).add(1, 'months');
        $scope.end_date = moment(edate).add(-1, 'days');
        if ($scope.data_source) {
          return DayService.query({
            company: $scope.bb.company,
            cItem: $scope.data_source,
            'month': date.format("MMYY"),
            client: $scope.client
          }).then(function(days) {
            var d, day, i, j, k, len, w, week, weeks;
            $scope.days = days;
            for (i = 0, len = days.length; i < len; i++) {
              day = days[i];
              $scope.day_data[day.string_date] = day;
            }
            weeks = [];
            for (w = j = 0; j <= 5; w = ++j) {
              week = [];
              for (d = k = 0; k <= 6; d = ++k) {
                week.push(days[w * 7 + d]);
              }
              weeks.push(week);
            }
            $scope.weeks = weeks;
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.setLoaded($scope);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadWeek
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Load week
     */
    $scope.loadWeek = (function(_this) {
      return function() {
        var date, edate;
        date = $scope.current_date;
        $scope.notLoaded($scope);
        edate = moment(date).add(7, 'days');
        $scope.end_date = moment(edate).add(-1, 'days');
        if ($scope.data_source) {
          return DayService.query({
            company: $scope.bb.company,
            cItem: $scope.data_source,
            date: date.toISODate(),
            edate: edate.toISODate(),
            client: $scope.client
          }).then(function(days) {
            var day, i, len;
            $scope.days = days;
            for (i = 0, len = days.length; i < len; i++) {
              day = days[i];
              $scope.day_data[day.string_date] = day;
            }
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.setLoaded($scope);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbMonthAvailability
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = (function(_this) {
      return function() {
        if ($scope.bb.current_item.date) {
          return true;
        } else {
          AlertService.clear();
          AlertService.add("danger", {
            msg: "You need to select a date"
          });
          return false;
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbDeals
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of deals for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} deals The deals list
  * @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbDeals', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'DealList'
    };
  });

  angular.module('BB.Controllers').controller('DealList', function($scope, $rootScope, DealService, $q, BBModel, AlertService, FormDataStoreService, ValidatorService, $modal) {
    var ModalInstanceCtrl, init;
    $scope.controller = "public.controllers.DealList";
    FormDataStoreService.init('TimeRangeList', $scope, ['deals']);
    $rootScope.connection_started.then(function() {
      return init();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    init = function() {
      var deal_promise;
      $scope.notLoaded($scope);
      if (!$scope.deals) {
        deal_promise = DealService.query($scope.bb.company);
        return deal_promise.then(function(deals) {
          $scope.deals = deals;
          return $scope.setLoaded($scope);
        });
      }
    };

    /***
    * @ngdoc method
    * @name selectDeal
    * @methodOf BB.Directives:bbDeals
    * @description
    * Select the deal and open modal
    *
    * @param {array} deal The deals array
     */
    $scope.selectDeal = function(deal) {
      var iitem, modalInstance;
      iitem = new BBModel.BasketItem(null, $scope.bb);
      iitem.setDefaults($scope.bb.item_defaults);
      iitem.setDeal(deal);
      if (!$scope.bb.company_settings.no_recipient) {
        modalInstance = $modal.open({
          templateUrl: $scope.getPartial('_add_recipient'),
          scope: $scope,
          controller: ModalInstanceCtrl,
          resolve: {
            item: function() {
              return iitem;
            }
          }
        });
        return modalInstance.result.then(function(item) {
          $scope.notLoaded($scope);
          $scope.setBasketItem(item);
          return $scope.addItemToBasket().then(function() {
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        });
      } else {
        $scope.notLoaded($scope);
        $scope.setBasketItem(iitem);
        return $scope.addItemToBasket().then(function() {
          return $scope.setLoaded($scope);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
    };
    ModalInstanceCtrl = function($scope, $modalInstance, item, ValidatorService) {
      $scope.controller = 'ModalInstanceCtrl';
      $scope.item = item;
      $scope.recipient = false;

      /***
      * @ngdoc method
      * @name addToBasket
      * @methodOf BB.Directives:bbDeals
      * @description
      * Add to basket in according of form parameter
      *
      * @param {object} form The form where is added deal list to basket
       */
      $scope.addToBasket = function(form) {
        if (!ValidatorService.validateForm(form)) {
          return;
        }
        return $modalInstance.close($scope.item);
      };
      return $scope.cancel = function() {
        return $modalInstance.dismiss('cancel');
      };
    };

    /***
    * @ngdoc method
    * @name purchaseDeals
    * @methodOf BB.Directives:bbDeals
    * @description
    * Purchase deals if basket items and basket items length is bigger than 0 else display a alert message
     */
    $scope.purchaseDeals = function() {
      if ($scope.bb.basket.items && $scope.bb.basket.items.length > 0) {
        return $scope.decideNextPage();
      } else {
        return AlertService.add('danger', {
          msg: 'You need to select at least one Gift Certificate to continue'
        });
      }
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbDeals
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = function() {
      if ($scope.bb.basket.items && $scope.bb.basket.items.length > 0) {
        return true;
      } else {
        return AlertService.add('danger', {
          msg: 'You need to select at least one Gift Certificate to continue'
        });
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbDurations
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of durations for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} duration The duration list
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbDurations', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'DurationList'
    };
  });

  angular.module('BB.Controllers').controller('DurationList', function($scope, $attrs, $rootScope, PageControllerService, $q, AlertService, $filter) {
    var options;
    $scope.controller = "public.controllers.DurationList";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    options = $scope.$eval($attrs.bbDurations) || {};
    $rootScope.connection_started.then(function() {
      return $scope.loadData();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.loadData = (function(_this) {
      return function() {
        var d, duration, i, id, initial_duration, len, ref, service;
        id = $scope.bb.company_id;
        service = $scope.bb.current_item.service;
        if (service && !$scope.durations) {
          $scope.durations = (function() {
            var i, len, ref, results;
            ref = _.zip(service.durations, service.prices);
            results = [];
            for (i = 0, len = ref.length; i < len; i++) {
              d = ref[i];
              results.push({
                value: d[0],
                price: d[1]
              });
            }
            return results;
          })();
          initial_duration = $scope.$eval($attrs.bbInitialDuration);
          ref = $scope.durations;
          for (i = 0, len = ref.length; i < len; i++) {
            duration = ref[i];
            if ($scope.bb.current_item.duration && duration.value === $scope.bb.current_item.duration) {
              $scope.duration = duration;
            } else if (initial_duration && initial_duration === duration.value) {
              $scope.duration = duration;
              $scope.bb.current_item.setDuration(duration.value);
            }
            duration.pretty = $filter('time_period')(duration.value);
            if (options.show_prices) {
              duration.pretty += " (" + ($filter('currency')(duration.price)) + ")";
            }
          }
          if ($scope.durations.length === 1) {
            $scope.skipThisStep();
            $scope.selectDuration($scope.durations[0], $scope.nextRoute);
          }
        }
        return $scope.setLoaded($scope);
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbDurations
    * @description
    * Select duration of the list in according of dur and route parameter
    *
    * @param {object} dur The duration list
    * @param {string=} route A specific route to load
     */
    $scope.selectDuration = (function(_this) {
      return function(dur, route) {
        if ($scope.$parent.$has_page_control) {
          $scope.duration = dur;
        } else {
          $scope.bb.current_item.setDuration(dur.value);
          $scope.decideNextPage(route);
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name durationChanged
    * @methodOf BB.Directives:bbDurations
    * @description
    * Change the list duration and update item
     */
    $scope.durationChanged = (function(_this) {
      return function() {
        $scope.bb.current_item.setDuration($scope.duration.value);
        return $scope.broadcastItemUpdate();
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbDurations
    * @description
    * Set this page section as ready
     */
    $scope.setReady = (function(_this) {
      return function() {
        if ($scope.duration) {
          $scope.bb.current_item.setDuration($scope.duration.value);
          return true;
        } else {
          AlertService.clear();
          AlertService.add("danger", {
            msg: "You need to select a duration"
          });
          return false;
        }
      };
    })(this);
    return $scope.$on("currentItemUpdate", function(event) {
      return $scope.loadData();
    });
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbEvent
  * @restrict AE
  * @scope true
  *
  * @description
  * Loads a list of event for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {integer} total_entries The total entries of the event
  * @property {array} events The events array
  * @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
   */
  angular.module('BB.Directives').directive('bbEvent', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Event'
    };
  });

  angular.module('BB.Controllers').controller('Event', function($scope, $attrs, $rootScope, EventService, $q, PageControllerService, BBModel, ValidatorService, FormDataStoreService) {
    var init, initImage, initTickets;
    $scope.controller = "public.controllers.Event";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $scope.validator = ValidatorService;
    $scope.event_options = $scope.$eval($attrs.bbEvent) || {};
    FormDataStoreService.init('ItemDetails', $scope, ['selected_tickets', 'event_options']);
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        return init($scope.bb.company);
      }
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    init = function(comp) {
      var promises;
      if ($scope.bb.stacked_items && $scope.bb.stacked_items.length === 0) {
        delete $scope.selected_tickets;
      }
      $scope.event = $scope.bb.current_item.event;
      $scope.event_options.use_my_details = $scope.event_options.use_my_details == null ? true : $scope.event_options.use_my_details;
      promises = [$scope.current_item.event_group.getImagesPromise(), $scope.event.prepEvent()];
      if ($scope.client) {
        promises.push($scope.getPrePaidsForEvent($scope.client, $scope.event));
      }
      return $q.all(promises).then(function(result) {
        var event, images, prepaids;
        if (result[0] && result[0].length > 0) {
          images = result[0];
        }
        event = result[1];
        if (result[2] && result[2].length > 0) {
          prepaids = result[2];
        }
        $scope.event = event;
        if (images) {
          initImage(images);
        }
        initTickets();
        $scope.$broadcast("bbEvent:initialised");
        return $scope.setLoaded($scope);
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name selectTickets
    * @methodOf BB.Directives:bbEvent
    * @description
    * Processes the selected tickets and adds them to the basket
     */
    $scope.selectTickets = function() {
      var base_item, c, i, item, j, len, ref, ref1, ticket;
      $scope.notLoaded($scope);
      $scope.bb.emptyStackedItems();
      base_item = $scope.current_item;
      ref = $scope.event.tickets;
      for (i = 0, len = ref.length; i < len; i++) {
        ticket = ref[i];
        if (ticket.qty) {
          switch ($scope.event.chain.ticket_type) {
            case "single_space":
              for (c = j = 1, ref1 = ticket.qty; 1 <= ref1 ? j <= ref1 : j >= ref1; c = 1 <= ref1 ? ++j : --j) {
                item = new BBModel.BasketItem();
                angular.extend(item, base_item);
                delete item.id;
                item.tickets = angular.copy(ticket);
                item.tickets.qty = 1;
                $scope.bb.stackItem(item);
              }
              break;
            case "multi_space":
              item = new BBModel.BasketItem();
              angular.extend(item, base_item);
              item.tickets = angular.copy(ticket);
              delete item.id;
              item.tickets.qty = ticket.qty;
              $scope.bb.stackItem(item);
          }
        }
      }
      if ($scope.bb.stacked_items.length === 0) {
        $scope.setLoaded($scope);
        return;
      }
      $scope.bb.pushStackToBasket();
      return $scope.updateBasket().then((function(_this) {
        return function() {
          $scope.setLoaded($scope);
          $scope.selected_tickets = true;
          $scope.stopTicketWatch();
          $scope.tickets = (function() {
            var k, len1, ref2, results;
            ref2 = $scope.bb.basket.items;
            results = [];
            for (k = 0, len1 = ref2.length; k < len1; k++) {
              item = ref2[k];
              results.push(item.tickets);
            }
            return results;
          })();
          return $scope.$watch('bb.basket.items', function(items, olditems) {
            $scope.bb.basket.total_price = $scope.bb.basket.totalPrice();
            return item.tickets.price = item.totalPrice();
          }, true);
        };
      })(this), function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbEvent
    * @description
    * Select an item event in according of item and route parameter
    *
    * @param {array} item The Event or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = (function(_this) {
      return function(item, route) {
        if ($scope.$parent.$has_page_control) {
          $scope.event = item;
          return false;
        } else {
          $scope.bb.current_item.setEvent(item);
          $scope.bb.current_item.ready = false;
          $scope.decideNextPage(route);
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbEvent
    * @description
    * Set this page section as ready
     */
    $scope.setReady = (function(_this) {
      return function() {
        $scope.bb.current_item.setEvent($scope.event);
        $scope.bb.event_details = {
          name: $scope.event.chain.name,
          image: $scope.event.image,
          address: $scope.event.chain.address,
          datetime: $scope.event.date,
          end_datetime: $scope.event.end_datetime,
          duration: $scope.event.duration,
          tickets: $scope.event.tickets
        };
        if ($scope.event_options.suppress_basket_update) {
          return true;
        } else {
          return $scope.updateBasket();
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name getPrePaidsForEvent
    * @methodOf BB.Directives:bbEvent
    * @description
    * Get pre paids for event in according of client and event parameter
    *
    * @param {array} client The client 
    * @param {array} event The event
     */
    $scope.getPrePaidsForEvent = function(client, event) {
      var defer, params;
      defer = $q.defer();
      params = {
        event_id: event.id
      };
      client.getPrePaidBookingsPromise(params).then(function(prepaids) {
        $scope.pre_paid_bookings = prepaids;
        return defer.resolve(prepaids);
      }, function(err) {
        return defer.reject(err);
      });
      return defer.promise;
    };
    initImage = function(images) {
      var image;
      image = images[0];
      if (image) {
        image.background_css = {
          'background-image': 'url(' + image.url + ')'
        };
        return $scope.event.image = image;
      }
    };
    return initTickets = function() {
      var i, len, ref, ticket;
      if ($scope.selected_tickets) {
        return;
      }
      $scope.event.tickets[0].qty = $scope.event_options.default_num_tickets ? $scope.event_options.default_num_tickets : 0;
      if ($scope.event.tickets.length > 1) {
        ref = $scope.event.tickets.slice(1);
        for (i = 0, len = ref.length; i < len; i++) {
          ticket = ref[i];
          ticket.qty = 0;
        }
      }
      if ($scope.event_options.default_num_tickets && $scope.event_options.auto_select_tickets && $scope.event.tickets.length === 1 && $scope.event.tickets[0].max_num_bookings === 1) {
        $scope.selectTickets();
      }
      $scope.tickets = $scope.event.tickets;
      $scope.bb.basket.total_price = $scope.bb.basket.totalPrice();
      return $scope.stopTicketWatch = $scope.$watch('tickets', function(tickets, oldtickets) {
        $scope.bb.basket.total_price = $scope.bb.basket.totalPrice();
        return $scope.event.updatePrice();
      }, true);
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbEventGroups
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of event groups for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {integer} total_entries The event total entries
  * @property {array} events The events array
  * @property {hash} filters A hash of filters
  * @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
   */
  angular.module('BB.Directives').directive('bbEventGroups', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'EventGroupList',
      link: function(scope, element, attrs) {
        if (attrs.bbItem) {
          scope.booking_item = scope.$eval(attrs.bbItem);
        }
        if (attrs.bbShowAll) {
          scope.show_all = true;
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('EventGroupList', function($scope, $rootScope, $q, $attrs, ItemService, FormDataStoreService, ValidatorService, PageControllerService, halClient) {
    var setEventGroupItem;
    $scope.controller = "public.controllers.EventGroupList";
    FormDataStoreService.init('EventGroupList', $scope, ['event_group']);
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $scope.validator = ValidatorService;
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.company) {
          return $scope.init($scope.bb.company);
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = function(comp) {
      var ppromise;
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      ppromise = comp.getEventGroupsPromise();
      return ppromise.then(function(items) {
        var filterItems, i, item, j, len, len1;
        filterItems = $attrs.filterServices === 'false' ? false : true;
        if (filterItems) {
          if ($scope.booking_item.service_ref && !$scope.show_all) {
            items = items.filter(function(x) {
              return x.api_ref === $scope.booking_item.service_ref;
            });
          } else if ($scope.booking_item.category && !$scope.show_all) {
            items = items.filter(function(x) {
              return x.$has('category') && x.$href('category') === $scope.booking_item.category.self;
            });
          }
        }
        if (items.length === 1 && !$scope.allowSinglePick) {
          if (!$scope.selectItem(items[0], $scope.nextRoute)) {
            setEventGroupItem(items);
          } else {
            $scope.skipThisStep();
          }
        } else {
          setEventGroupItem(items);
        }
        if ($scope.booking_item.defaultService()) {
          for (i = 0, len = items.length; i < len; i++) {
            item = items[i];
            if (item.self === $scope.booking_item.defaultService().self) {
              $scope.selectItem(item, $scope.nextRoute);
            }
          }
        }
        if ($scope.booking_item.event_group) {
          for (j = 0, len1 = items.length; j < len1; j++) {
            item = items[j];
            item.selected = false;
            if (item.self === $scope.booking_item.event_group.self) {
              $scope.event_group = item;
              item.selected = true;
              $scope.booking_item.setEventGroup($scope.event_group);
            }
          }
        }
        $scope.setLoaded($scope);
        if ($scope.booking_item.event_group || (!$scope.booking_item.person && !$scope.booking_item.resource)) {
          return $scope.bookable_services = $scope.items;
        }
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name setEventGroupItem
    * @methodOf BB.Directives:bbEventGroups
    * @description
    * Set event group item in accroding of items parameter
    *
    * @param {array} items Items of event group
     */
    setEventGroupItem = function(items) {
      $scope.items = items;
      if ($scope.event_group) {
        return _.each(items, function(item) {
          if (item.id === $scope.event_group.id) {
            return $scope.event_group = item;
          }
        });
      }
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbEventGroups
    * @description
    * Select an item from event group in according of item and route parameters
    *
    * @param {array} item The event group or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = (function(_this) {
      return function(item, route) {
        if ($scope.$parent.$has_page_control) {
          $scope.event_group = item;
          return false;
        } else {
          $scope.booking_item.setEventGroup(item);
          $scope.decideNextPage(route);
          return true;
        }
      };
    })(this);
    $scope.$watch('event_group', (function(_this) {
      return function(newval, oldval) {
        if ($scope.event_group) {
          if (!$scope.booking_item.event_group || $scope.booking_item.event_group.self !== $scope.event_group.self) {
            $scope.booking_item.setEventGroup($scope.event_group);
            return $scope.broadcastItemUpdate();
          }
        }
      };
    })(this));

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbEventGroups
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = (function(_this) {
      return function() {
        if ($scope.event_group) {
          $scope.booking_item.setEventGroup($scope.event_group);
          return true;
        } else {
          return false;
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbEvents
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of events for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbEvents A hash of options
  * @property {integer} total_entries The event total entries
  * @property {array} events The events array
   */
  angular.module('BB.Directives').directive('bbEvents', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'EventList',
      link: function(scope, element, attrs) {
        var options;
        scope.summary = attrs.summary != null;
        options = scope.$eval(attrs.bbEvents) || {};
        scope.mode = options && options.mode ? options.mode : 0;
        if (scope.summary) {
          scope.mode = 0;
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('EventList', function($scope, $rootScope, EventService, EventChainService, $q, PageControllerService, FormDataStoreService, $filter, PaginationService, $timeout) {
    var buildDynamicFilters, filterEventsWithDynamicFilters, sort;
    $scope.controller = "public.controllers.EventList";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $scope.pick = {};
    $scope.start_date = moment();
    $scope.end_date = moment().add(1, 'year');
    $scope.filters = {};
    $scope.pagination = PaginationService.initialise({
      page_size: 10,
      max_size: 5
    });
    $scope.events = {};
    $scope.fully_booked = false;
    FormDataStoreService.init('EventList', $scope, ['selected_date', 'event_group_id', 'event_group_manually_set']);
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        if ($scope.bb.item_defaults.event) {
          $scope.skipThisStep();
          $scope.decideNextPage();
        } else if ($scope.bb.company.$has('parent') && !$scope.bb.company.$has('company_questions')) {
          return $scope.bb.company.getParentPromise().then(function(parent) {
            $scope.company_parent = parent;
            return $scope.initialise();
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.initialise();
        }
      }
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.initialise = function() {
      var event_group, promises;
      $scope.notLoaded($scope);
      if ($scope.mode !== 0) {
        delete $scope.selected_date;
      }
      if (!$scope.event_group_manually_set && ($scope.current_item.event_group == null)) {
        $scope.event_group_manually_set = ($scope.event_group_manually_set == null) && ($scope.current_item.event_group != null) ? true : false;
      }
      if ($scope.bb.current_item.event) {
        event_group = $scope.current_item.event_group;
        $scope.clearBasketItem();
        $scope.emptyBasket();
        if ($scope.event_group_manually_set) {
          $scope.current_item.setEventGroup(event_group);
        }
      }
      promises = [];
      if ($scope.bb.company.$has('company_questions')) {
        promises.push($scope.bb.company.getCompanyQuestionsPromise());
      } else if (($scope.company_parent != null) && $scope.company_parent.$has('company_questions')) {
        promises.push($scope.company_parent.getCompanyQuestionsPromise());
      } else {
        promises.push($q.when([]));
        $scope.has_company_questions = false;
      }
      if (!$scope.current_item.event_group && $scope.bb.company.$has('event_groups')) {
        promises.push($scope.bb.company.getEventGroupsPromise());
      } else {
        promises.push($q.when([]));
      }
      if ($scope.mode === 0 || $scope.mode === 2) {
        promises.push($scope.loadEventSummary());
      } else {
        promises.push($q.when([]));
      }
      if ($scope.mode === 1 || $scope.mode === 2) {
        promises.push($scope.loadEventData());
      } else {
        promises.push($q.when([]));
      }
      return $q.all(promises).then(function(result) {
        var company_questions, event_data, event_groups, event_groups_collection, event_summary, item, j, len, ref;
        company_questions = result[0];
        event_groups = result[1];
        event_summary = result[2];
        event_data = result[3];
        $scope.has_company_questions = (company_questions != null) && company_questions.length > 0;
        if (company_questions) {
          buildDynamicFilters(company_questions);
        }
        $scope.event_groups = event_groups;
        event_groups_collection = _.indexBy(event_groups, 'id');
        if ($scope.items) {
          ref = $scope.items;
          for (j = 0, len = ref.length; j < len; j++) {
            item = ref[j];
            item.group = event_groups_collection[item.service_id];
          }
        }
        return $scope.setLoaded($scope);
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name loadEventSummary
    * @methodOf BB.Directives:bbEvents
    * @description
    * Load event summary
     */
    $scope.loadEventSummary = function() {
      var comp, current_event, deferred, params;
      deferred = $q.defer();
      current_event = $scope.current_item.event;
      if ($scope.bb.current_item && ($scope.bb.current_item.event_chain_id || $scope.bb.current_item.event_chain)) {
        delete $scope.bb.current_item.event_chain;
        delete $scope.bb.current_item.event_chain_id;
      }
      comp = $scope.bb.company;
      params = {
        item: $scope.bb.current_item,
        start_date: $scope.start_date.toISODate(),
        end_date: $scope.end_date.toISODate()
      };
      if ($scope.bb.item_defaults.event_chain) {
        params.event_chain_id = $scope.bb.item_defaults.event_chain;
      }
      EventService.summary(comp, params).then(function(items) {
        var d, item, item_dates, j, len;
        if (items && items.length > 0) {
          item_dates = [];
          for (j = 0, len = items.length; j < len; j++) {
            item = items[j];
            d = moment(item);
            item_dates.push({
              date: d,
              idate: parseInt(d.format("YYYYDDDD")),
              count: 1,
              spaces: 1
            });
          }
          $scope.item_dates = item_dates.sort(function(a, b) {
            return a.idate - b.idate;
          });
          if ($scope.mode === 0) {
            if ($scope.selected_date && ($scope.selected_date.isAfter($scope.item_dates[0].date) || $scope.selected_date.isSame($scope.item_dates[0].date)) && ($scope.selected_date.isBefore($scope.item_dates[$scope.item_dates.length - 1].date) || $scope.selected_date.isSame($scope.item_dates[$scope.item_dates.length - 1].date))) {
              $scope.showDay($scope.selected_date);
            } else {
              $scope.showDay($scope.item_dates[0].date);
            }
          }
        }
        return deferred.resolve($scope.item_dates);
      }, function(err) {
        return deferred.reject();
      });
      return deferred.promise;
    };

    /***
    * @ngdoc method
    * @name loadEventChainData
    * @methodOf BB.Directives:bbEvents
    * @description
    * Load event chain data in according of comp parameter
    *
    * @param {array} comp The company
     */
    $scope.loadEventChainData = function(comp) {
      var deferred, params;
      deferred = $q.defer();
      if ($scope.bb.item_defaults.event_chain) {
        deferred.resolve([]);
      } else {
        $scope.notLoaded($scope);
        comp || (comp = $scope.bb.company);
        params = {
          item: $scope.bb.current_item,
          start_date: $scope.start_date.toISODate(),
          end_date: $scope.end_date.toISODate()
        };
        EventChainService.query(comp, params).then(function(event_chains) {
          $scope.setLoaded($scope);
          return deferred.resolve(event_chains);
        }, function(err) {
          return deferred.reject();
        });
      }
      return deferred.promise;
    };

    /***
    * @ngdoc method
    * @name loadEventData
    * @methodOf BB.Directives:bbEvents
    * @description
    * Load event data. De-select the event chain if there's one already picked - as it's hiding other events in the same group
    *
    * @param {array} comp The company parameter
     */
    $scope.loadEventData = function(comp) {
      var chains, current_event, deferred, params;
      if ($scope.mode === 0) {
        delete $scope.items;
      }
      deferred = $q.defer();
      current_event = $scope.current_item.event;
      $scope.notLoaded($scope);
      comp || (comp = $scope.bb.company);
      if ($scope.bb.current_item && ($scope.bb.current_item.event_chain_id || $scope.bb.current_item.event_chain)) {
        delete $scope.bb.current_item.event_chain;
        delete $scope.bb.current_item.event_chain_id;
      }
      params = {
        item: $scope.bb.current_item,
        start_date: $scope.start_date.toISODate(),
        end_date: $scope.end_date.toISODate()
      };
      if ($scope.bb.item_defaults.event_chain) {
        params.event_chain_id = $scope.bb.item_defaults.event_chain;
      }
      chains = $scope.loadEventChainData(comp);
      $scope.events = {};
      EventService.query(comp, params).then(function(events) {
        var item, j, len, ref;
        $scope.items = _.flatten(events);
        ref = $scope.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          item.spaces_left = item.getSpacesLeft();
        }
        $scope.bb.company.getAddressPromise().then(function(address) {
          var k, len1, ref1, results;
          ref1 = $scope.items;
          results = [];
          for (k = 0, len1 = ref1.length; k < len1; k++) {
            item = ref1[k];
            results.push(item.address = address);
          }
          return results;
        });
        return chains.then(function() {
          var idate, item_dates, k, l, len1, len2, ref1, x, y;
          ref1 = $scope.items;
          for (k = 0, len1 = ref1.length; k < len1; k++) {
            item = ref1[k];
            item.prepEvent();
            if ($scope.mode === 0 && current_event && current_event.self === item.self) {
              item.select();
              $scope.event = item;
            }
          }
          if ($scope.mode === 1) {
            item_dates = {};
            if (items.length > 0) {
              for (l = 0, len2 = items.length; l < len2; l++) {
                item = items[l];
                item.getDuration();
                idate = parseInt(item.date.format("YYYYDDDD"));
                item.idate = idate;
                if (!item_dates[idate]) {
                  item_dates[idate] = {
                    date: item.date,
                    idate: idate,
                    count: 0,
                    spaces: 0
                  };
                }
                item_dates[idate].count += 1;
                item_dates[idate].spaces += item.num_spaces;
              }
              $scope.item_dates = [];
              for (x in item_dates) {
                y = item_dates[x];
                $scope.item_dates.push(y);
              }
              $scope.item_dates = $scope.item_dates.sort(function(a, b) {
                return a.idate - b.idate;
              });
            } else {
              idate = parseInt($scope.start_date.format("YYYYDDDD"));
              $scope.item_dates = [
                {
                  date: $scope.start_date,
                  idate: idate,
                  count: 0,
                  spaces: 0
                }
              ];
            }
          }
          $scope.isFullyBooked();
          $scope.filtered_items = $scope.items;
          $scope.filterChanged();
          PaginationService.update($scope.pagination, $scope.filtered_items.length);
          $scope.setLoaded($scope);
          return deferred.resolve($scope.items);
        }, function(err) {
          return deferred.reject();
        });
      }, function(err) {
        return deferred.reject();
      });
      return deferred.promise;
    };

    /***
    * @ngdoc method
    * @name isFullyBooked
    * @methodOf BB.Directives:bbEvents
    * @description
    * Verify if the items from event list are be fully booked
     */
    $scope.isFullyBooked = function() {
      var full_events, item, j, len, ref;
      full_events = [];
      ref = $scope.items;
      for (j = 0, len = ref.length; j < len; j++) {
        item = ref[j];
        if (item.num_spaces === item.spaces_booked) {
          full_events.push(item);
        }
      }
      if (full_events.length === $scope.items.length) {
        return $scope.fully_booked = true;
      }
    };

    /***
    * @ngdoc method
    * @name showDay
    * @methodOf BB.Directives:bbEvents
    * @description
    * Selects a day or filters events by day selected
    *
    * @param {moment} the day to select or filter by
     */
    $scope.showDay = function(date) {
      var new_date;
      if (!moment.isMoment(date)) {
        return;
      }
      if ($scope.mode === 0) {
        if ($scope.event && !$scope.selected_date.isSame(date, 'day')) {
          delete $scope.event;
        }
        new_date = date;
        $scope.start_date = moment(date);
        $scope.end_date = moment(date);
        $scope.loadEventData();
      } else {
        if (!$scope.selected_date || !date.isSame($scope.selected_date, 'day')) {
          new_date = date;
        }
      }
      if (new_date) {
        $scope.selected_date = new_date;
        $scope.filters.date = new_date.toDate();
      } else {
        delete $scope.selected_date;
        delete $scope.filters.date;
      }
      return $scope.filterChanged();
    };
    $scope.$watch('pick.date', (function(_this) {
      return function(new_val, old_val) {
        if (new_val) {
          $scope.start_date = moment(new_val);
          $scope.end_date = moment(new_val);
          return $scope.loadEventData();
        }
      };
    })(this));

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbEvents
    * @description
    * Select an item into the current event list in according of item and route parameters
    *
    * @param {array} item The Event or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = (function(_this) {
      return function(item, route) {
        var i, j, len, ref;
        if (!((item.getSpacesLeft() <= 0 && $scope.bb.company.settings.has_waitlists) || item.hasSpace())) {
          return false;
        }
        $scope.notLoaded($scope);
        if ($scope.$parent.$has_page_control) {
          if ($scope.event) {
            $scope.event.unselect();
          }
          $scope.event = item;
          $scope.event.select();
          $scope.setLoaded($scope);
          return false;
        } else {
          if ($scope.bb.moving_purchase) {
            ref = $scope.bb.basket.items;
            for (j = 0, len = ref.length; j < len; j++) {
              i = ref[j];
              i.setEvent(item);
            }
          }
          $scope.bb.current_item.setEvent(item);
          $scope.bb.current_item.ready = false;
          $q.all($scope.bb.current_item.promises).then(function() {
            return $scope.decideNextPage(route);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbEvents
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    $scope.setReady = function() {
      if (!$scope.event) {
        return false;
      }
      $scope.bb.current_item.setEvent($scope.event);
      return true;
    };

    /***
    * @ngdoc method
    * @name filterEvents
    * @methodOf BB.Directives:bbEvents
    * @description
    * Filter events from the event list in according of item parameter
    *
    * @param {array} item The Event or BookableItem to select
     */
    $scope.filterEvents = function(item) {
      var result;
      result = (item.date.isSame(moment($scope.filters.date), 'day') || ($scope.filters.date == null)) && (($scope.filters.event_group && item.service_id === $scope.filters.event_group.id) || ($scope.filters.event_group == null)) && ((($scope.filters.price != null) && (item.price_range.from <= $scope.filters.price)) || ($scope.filters.price == null)) && (($scope.filters.hide_sold_out_events && item.getSpacesLeft() !== 0) || !$scope.filters.hide_sold_out_events) && filterEventsWithDynamicFilters(item);
      return result;
    };
    filterEventsWithDynamicFilters = function(item) {
      var dynamic_filter, filter, i, j, k, l, len, len1, len2, len3, m, name, ref, ref1, ref2, ref3, result, type;
      if (!$scope.has_company_questions || !$scope.dynamic_filters) {
        return true;
      }
      result = true;
      ref = $scope.dynamic_filters.question_types;
      for (j = 0, len = ref.length; j < len; j++) {
        type = ref[j];
        if (type === 'check') {
          ref1 = $scope.dynamic_filters['check'];
          for (k = 0, len1 = ref1.length; k < len1; k++) {
            dynamic_filter = ref1[k];
            name = dynamic_filter.name.parameterise('_');
            filter = false;
            if (item.chain && item.chain.extra[name]) {
              ref2 = item.chain.extra[name];
              for (l = 0, len2 = ref2.length; l < len2; l++) {
                i = ref2[l];
                filter = ($scope.dynamic_filters.values[dynamic_filter.name] && i === $scope.dynamic_filters.values[dynamic_filter.name].name) || ($scope.dynamic_filters.values[dynamic_filter.name] == null);
                if (filter) {
                  break;
                }
              }
            } else if (item.chain.extra[name] === void 0 && (_.isEmpty($scope.dynamic_filters.values) || ($scope.dynamic_filters.values[dynamic_filter.name] == null))) {
              filter = true;
            }
            result = result && filter;
          }
        } else {
          ref3 = $scope.dynamic_filters[type];
          for (m = 0, len3 = ref3.length; m < len3; m++) {
            dynamic_filter = ref3[m];
            name = dynamic_filter.name.parameterise('_');
            filter = ($scope.dynamic_filters.values[dynamic_filter.name] && item.chain.extra[name] === $scope.dynamic_filters.values[dynamic_filter.name].name) || ($scope.dynamic_filters.values[dynamic_filter.name] == null);
            result = result && filter;
          }
        }
      }
      return result;
    };

    /***
    * @ngdoc method
    * @name filterDateChanged
    * @methodOf BB.Directives:bbEvents
    * @description
    * Filtering data exchanged from the list of events
     */
    $scope.filterDateChanged = function(options) {
      var date;
      if (options == null) {
        options = {
          reset: false
        };
      }
      if ($scope.filters.date) {
        date = moment($scope.filters.date);
        $scope.$broadcast("event_list_filter_date:changed", date);
        $scope.showDay(date);
        if (options.reset === true || ($scope.selected_date == null)) {
          return $timeout(function() {
            return delete $scope.filters.date;
          }, 250);
        }
      }
    };

    /***
    * @ngdoc method
    * @name resetFilters
    * @methodOf BB.Directives:bbEvents
    * @description
    * Reset the filters
     */
    $scope.resetFilters = function() {
      $scope.filters = {};
      if ($scope.has_company_questions) {
        $scope.dynamic_filters.values = {};
      }
      return $scope.filterChanged();
    };
    buildDynamicFilters = function(questions) {
      $scope.dynamic_filters = _.groupBy(questions, 'question_type');
      $scope.dynamic_filters.question_types = _.uniq(_.pluck(questions, 'question_type'));
      return $scope.dynamic_filters.values = {};
    };
    sort = function() {};

    /***
    * @ngdoc method
    * @name filterChanged
    * @methodOf BB.Directives:bbEvents
    * @description
    * Change filter of the event list
     */
    $scope.filterChanged = function() {
      if ($scope.items) {
        $scope.filtered_items = $filter('filter')($scope.items, $scope.filterEvents);
        $scope.pagination.num_items = $scope.filtered_items.length;
        $scope.filter_active = $scope.filtered_items.length !== $scope.items.length;
        return PaginationService.update($scope.pagination, $scope.filtered_items.length);
      }
    };

    /***
    * @ngdoc method
    * @name pageChanged
    * @methodOf BB.Directives:bbEvents
    * @description
    * Change page of the event list
     */
    return $scope.pageChanged = function() {
      PaginationService.update($scope.pagination, $scope.filtered_items.length);
      return $rootScope.$broadcast("page:changed");
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbGetAvailability
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of availability for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} earliest_day The availability of earliest day
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbGetAvailability', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'GetAvailability',
      link: function(scope, element, attrs) {
        if (attrs.bbGetAvailability) {
          scope.loadAvailability(scope.$eval(attrs.bbGetAvailability));
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('GetAvailability', function($scope, $element, $attrs, $rootScope, $q, TimeService, AlertService, BBModel, halClient) {

    /***
    * @ngdoc method
    * @name loadAvailability
    * @methodOf BB.Directives:bbGetAvailability
    * @description
    * Load availability of the services in according of prms parameter
    *
    * @param {array} prms The parameters of availability
     */
    return $scope.loadAvailability = (function(_this) {
      return function(prms) {
        var service;
        service = halClient.$get($scope.bb.api_url + '/api/v1/' + prms.company_id + '/services/' + prms.service);
        return service.then(function(serv) {
          var eday, sday;
          $scope.earliest_day = null;
          sday = moment();
          eday = moment().add(30, 'days');
          return serv.$get('days', {
            date: sday.toISOString(),
            edate: eday.toISOString()
          }).then(function(res) {
            var day, i, len, ref, results;
            ref = res.days;
            results = [];
            for (i = 0, len = ref.length; i < len; i++) {
              day = ref[i];
              if (day.spaces > 0 && !$scope.earliest_day) {
                $scope.earliest_day = moment(day.date);
                if (day.first) {
                  results.push($scope.earliest_day.add(day.first, "minutes"));
                } else {
                  results.push(void 0);
                }
              } else {
                results.push(void 0);
              }
            }
            return results;
          });
        });
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbItemDetails
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of item details for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} item An array of all item details
  * @property {array} product The product
  * @property {array} booking The booking
  * @property {array} upload_progress The item upload progress
  * @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbItemDetails', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'ItemDetails',
      link: function(scope, element, attrs) {
        var item;
        if (attrs.bbItemDetails) {
          item = scope.$eval(attrs.bbItemDetails);
          scope.item_from_param = item;
          if (scope.item_details) {
            delete scope.item_details;
          }
          scope.loadItem(item);
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('ItemDetails', function($scope, $attrs, $rootScope, ItemDetailsService, PurchaseBookingService, AlertService, BBModel, FormDataStoreService, ValidatorService, QuestionService, $modal, $location, $upload, $translate, SettingsService, PurchaseService) {
    var confirming, setItemDetails;
    $scope.controller = "public.controllers.ItemDetails";
    $scope.suppress_basket_update = $attrs.bbSuppressBasketUpdate != null;
    $scope.item_details_id = $scope.$eval($attrs.bbSuppressBasketUpdate);
    if ($scope.suppress_basket_update) {
      FormDataStoreService.init('ItemDetails' + $scope.item_details_id, $scope, ['item_details']);
    } else {
      FormDataStoreService.init('ItemDetails', $scope, ['item_details']);
    }
    QuestionService.addAnswersByName($scope.client, ['first_name', 'last_name', 'email', 'mobile']);
    $scope.validator = ValidatorService;
    confirming = false;
    $rootScope.connection_started.then(function() {
      if (!confirming) {
        return $scope.loadItem($scope.bb.current_item);
      }
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name loadItem
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Load item in according of item parameter
    *
    * @param {array} item The item loaded
     */
    $scope.loadItem = function(item) {
      var params;
      $scope.notLoaded($scope);
      confirming = true;
      $scope.item = item;
      if ($scope.bb.private_note) {
        $scope.item.private_note = $scope.bb.private_note;
      }
      $scope.product = item.product;
      if ($scope.item.item_details) {
        setItemDetails($scope.item.item_details);
        QuestionService.addDynamicAnswersByName($scope.item_details.questions);
        if ($scope.bb.item_defaults.answers) {
          QuestionService.addAnswersFromDefaults($scope.item_details.questions, $scope.bb.item_defaults.answers);
        }
        $scope.recalc_price();
        $scope.setLoaded($scope);
        return $scope.$emit("item_details:loaded", $scope.item_details);
      } else {
        params = {
          company: $scope.bb.company,
          cItem: $scope.item
        };
        return ItemDetailsService.query(params).then(function(details) {
          if (details) {
            setItemDetails(details);
            $scope.item.item_details = $scope.item_details;
            QuestionService.addDynamicAnswersByName($scope.item_details.questions);
            if ($scope.bb.item_defaults.answers) {
              QuestionService.addAnswersFromDefaults($scope.item_details.questions, $scope.bb.item_defaults.answers);
            }
            $scope.recalc_price();
            $scope.$emit("item_details:loaded", $scope.item_details);
          }
          return $scope.setLoaded($scope);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
    };

    /***
    * @ngdoc method
    * @name setItemDetails
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Set item details in according of details parameter
    *
    * @param {array} details The details parameter
     */
    setItemDetails = function(details) {
      var oldQuestions;
      if ($scope.item && $scope.item.defaults) {
        _.each(details.questions, function(item) {
          var n;
          n = "q_" + item.name;
          if ($scope.item.defaults[n]) {
            return item.answer = $scope.item.defaults[n];
          }
        });
      }
      if ($scope.hasOwnProperty('item_details')) {
        oldQuestions = $scope.item_details.questions;
        _.each(details.questions, function(item) {
          var search;
          search = _.findWhere(oldQuestions, {
            name: item.name
          });
          if (search) {
            return item.answer = search.answer;
          }
        });
      }
      return $scope.item_details = details;
    };
    $scope.$on('currentItemUpdate', function(event) {
      if ($scope.item_from_param) {
        return $scope.loadItem($scope.item_from_param);
      } else {
        return $scope.loadItem($scope.bb.current_item);
      }
    });

    /***
    * @ngdoc method
    * @name recalc_price
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Recalculate item price in function of quantity
     */
    $scope.recalc_price = function() {
      var bprice, qprice;
      qprice = $scope.item_details.questionPrice($scope.item.getQty());
      bprice = $scope.item.base_price;
      return $scope.item.setPrice(qprice + bprice);
    };

    /***
    * @ngdoc method
    * @name confirm
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Confirm the question
    *
    * @param {object} form The form where question are introduced
    * @param {string=} route A specific route to load
     */
    $scope.confirm = function(form, route) {
      if (!ValidatorService.validateForm(form)) {
        return;
      }
      if ($scope.bb.moving_booking) {
        return $scope.confirm_move(form, route);
      }
      $scope.item.setAskedQuestions();
      if ($scope.$parent.$has_page_control) {
        return true;
      }
      if ($scope.item.ready) {
        $scope.notLoaded($scope);
        return $scope.addItemToBasket().then(function() {
          $scope.setLoaded($scope);
          return $scope.decideNextPage(route);
        }, function(err) {
          return $scope.setLoaded($scope);
        });
      } else {
        return $scope.decideNextPage(route);
      }
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    $scope.setReady = (function(_this) {
      return function() {
        $scope.item.setAskedQuestions();
        if ($scope.item.ready && !$scope.suppress_basket_update) {
          return $scope.addItemToBasket();
        } else {
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name confirm_move
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Confirm move question information has been correctly entered here
    *
    * @param {string=} route A specific route to load
     */
    $scope.confirm_move = function(route) {
      var params;
      confirming = true;
      $scope.item || ($scope.item = $scope.bb.current_item);
      $scope.item.moved_booking = false;
      $scope.item.setAskedQuestions();
      if ($scope.item.ready) {
        $scope.notLoaded($scope);
        if ($scope.bb.moving_purchase) {
          params = {
            purchase: $scope.bb.moving_purchase,
            bookings: $scope.bb.basket.items
          };
          return PurchaseService.update(params).then(function(purchase) {
            $scope.bb.purchase = purchase;
            return $scope.bb.purchase.getBookingsPromise().then(function(bookings) {
              $scope.purchase = purchase;
              $scope.setLoaded($scope);
              $scope.item.move_done = true;
              $scope.item.moved_booking = true;
              $rootScope.$broadcast("booking:moved");
              $scope.decideNextPage(route);
              return $scope.showMoveMessage(bookings[0].datetime);
            });
          }, function(err) {
            $scope.setLoaded($scope);
            return AlertService.add("danger", {
              msg: "Failed to move booking. Please try again."
            });
          });
        } else {
          return PurchaseBookingService.update($scope.item).then(function(booking) {
            var _i, b, i, len, oldb, ref;
            b = new BBModel.Purchase.Booking(booking);
            if ($scope.bb.purchase) {
              ref = $scope.bb.purchase.bookings;
              for (_i = i = 0, len = ref.length; i < len; _i = ++i) {
                oldb = ref[_i];
                if (oldb.id === b.id) {
                  $scope.bb.purchase.bookings[_i] = b;
                }
              }
            }
            $scope.setLoaded($scope);
            $scope.item.move_done = true;
            $rootScope.$broadcast("booking:moved");
            $scope.decideNextPage(route);
            return $scope.showMoveMessage(b.datetime);
          }, (function(_this) {
            return function(err) {
              $scope.setLoaded($scope);
              return AlertService.add("danger", {
                msg: "Failed to move booking. Please try again."
              });
            };
          })(this));
        }
      } else {
        return $scope.decideNextPage(route);
      }
    };
    $scope.showMoveMessage = function(datetime) {
      if (SettingsService.isInternationalizatonEnabled()) {
        return $translate('MOVE_BOOKINGS_MSG', {
          datetime: datetime.format('LLLL')
        }).then(function(translated_text) {
          return AlertService.add("info", {
            msg: translated_text
          });
        });
      } else {
        return AlertService.add("info", {
          msg: "Your booking has been moved to " + (datetime.format('LLLL'))
        });
      }
    };

    /***
    * @ngdoc method
    * @name openTermsAndConditions
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Display terms and conditions view
     */
    $scope.openTermsAndConditions = function() {
      var modalInstance;
      return modalInstance = $modal.open({
        templateUrl: $scope.getPartial("terms_and_conditions"),
        scope: $scope
      });
    };

    /***
    * @ngdoc method
    * @name getQuestion
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Get question by id
    *
    * @param {integer} id The id of the question
     */
    $scope.getQuestion = function(id) {
      var i, len, question, ref;
      ref = $scope.item_details.questions;
      for (i = 0, len = ref.length; i < len; i++) {
        question = ref[i];
        if (question.id === id) {
          return question;
        }
      }
      return null;
    };

    /***
    * @ngdoc method
    * @name updateItem
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Update item
     */
    $scope.updateItem = function() {
      $scope.item.setAskedQuestions();
      if ($scope.item.ready) {
        $scope.notLoaded($scope);
        return PurchaseBookingService.update($scope.item).then(function(booking) {
          var _i, b, i, len, oldb, ref;
          b = new BBModel.Purchase.Booking(booking);
          if ($scope.bookings) {
            ref = $scope.bookings;
            for (_i = i = 0, len = ref.length; i < len; _i = ++i) {
              oldb = ref[_i];
              if (oldb.id === b.id) {
                $scope.bookings[_i] = b;
              }
            }
          }
          $scope.purchase.bookings = $scope.bookings;
          $scope.item_details_updated = true;
          return $scope.setLoaded($scope);
        }, (function(_this) {
          return function(err) {
            return $scope.setLoaded($scope);
          };
        })(this));
      }
    };

    /***
    * @ngdoc method
    * @name editItem
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Edit item
     */
    $scope.editItem = function() {
      return $scope.item_details_updated = false;
    };

    /***
    * @ngdoc method
    * @name onFileSelect
    * @methodOf BB.Directives:bbItemDetails
    * @description
    * Select file to upload in according of item, $file and existing parameters
    *
    * @param {array} item The item for uploading
    * @param {boolean} existing Checks if file item exist or not
     */
    return $scope.onFileSelect = function(item, $file, existing) {
      var att_id, file, method, url;
      $scope.upload_progress = 0;
      file = $file;
      att_id = null;
      if (existing) {
        att_id = existing;
      }
      method = "POST";
      if (att_id) {
        method = "PUT";
      }
      url = item.$href('add_attachment');
      return $scope.upload = $upload.upload({
        url: url,
        method: method,
        data: {
          attachment_id: att_id
        },
        file: file
      }).progress(function(evt) {
        if ($scope.upload_progress < 100) {
          return $scope.upload_progress = parseInt(99.0 * evt.loaded / evt.total);
        }
      }).success(function(data, status, headers, config) {
        $scope.upload_progress = 100;
        if (data && item) {
          item.attachment = data;
          return item.attachment_id = data.id;
        }
      });
    };
  });

}).call(this);


/***
* @ngdoc directive
* @name BB.Directives:bbLogin
* @restrict AE
* @scope true
*
* @description
*
* Loads a list of logins for the currently in scope company
*
* <pre>
* restrict: 'AE'
* replace: true
* scope: true
* </pre>
*
* @property {boolean} password_updated The user password updated
* @property {boolean} password_error The user password error
* @property {boolean} email_sent The email sent
* @property {boolean} success If user are log in with success
* @property {boolean} login_error If user have some errors when try to log in
* @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
 */

(function() {
  angular.module('BB.Directives').directive('bbLogin', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Login'
    };
  });

  angular.module('BB.Controllers').controller('Login', function($scope, $rootScope, LoginService, $q, ValidatorService, BBModel, $location, AlertService) {
    $scope.controller = "public.controllers.Login";
    $scope.validator = ValidatorService;
    $scope.login_form = {};

    /***
    * @ngdoc method
    * @name login_sso
    * @methodOf BB.Directives:bbLogin
    * @description
    * Login to application
    *
    * @param {object} token The token to use for login
    * @param {string=} route A specific route to load
     */
    $scope.login_sso = function(token, route) {
      return $rootScope.connection_started.then((function(_this) {
        return function() {
          return LoginService.ssoLogin({
            company_id: $scope.bb.company.id,
            root: $scope.bb.api_url
          }, {
            token: token
          }).then(function(member) {
            if (route) {
              return $scope.showPage(route);
            }
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        };
      })(this), function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name login_with_password
    * @methodOf BB.Directives:bbLogin
    * @description
    * Login with password
    *
    * @param {string} email The email address that use for the login 
    * @param {string} password The password use for the login
     */
    $scope.login_with_password = function(email, password) {
      return LoginService.companyLogin($scope.bb.company, {}, {
        email: email,
        password: password
      }).then((function(_this) {
        return function(member) {
          return $scope.member = new BBModel.Member.Member(member);
        };
      })(this), (function(_this) {
        return function(err) {
          return AlertService.raise('LOGIN_FAILED');
        };
      })(this));
    };

    /***
    * @ngdoc method
    * @name showEmailPasswordReset
    * @methodOf BB.Directives:bbLogin
    * @description
    * Display email reset password page
     */
    $scope.showEmailPasswordReset = (function(_this) {
      return function() {
        return $scope.showPage('email_reset_password');
      };
    })(this);

    /***
    * @ngdoc method
    * @name isLoggedIn
    * @methodOf BB.Directives:bbLogin
    * @description
    * Verify if user are logged in
     */
    $scope.isLoggedIn = function() {
      return LoginService.isLoggedIn();
    };

    /***
    * @ngdoc method
    * @name sendPasswordReset
    * @methodOf BB.Directives:bbLogin
    * @description
    * Send password reset via email
    *
    * @param {string} email The email address use for the send new password
     */
    $scope.sendPasswordReset = function(email) {
      return LoginService.sendPasswordReset($scope.bb.company, {
        email: email,
        custom: true
      }).then(function() {
        return AlertService.raise('PASSWORD_RESET_REQ_SUCCESS');
      }, (function(_this) {
        return function(err) {
          return AlertService.raise('PASSWORD_RESET_REQ_FAILED');
        };
      })(this));
    };

    /***
    * @ngdoc method
    * @name updatePassword
    * @methodOf BB.Directives:bbLogin
    * @description
    * Update password
    *
    * @param {string} new_password The new password has been set
    * @param {string} confirm_new_password The new password has been confirmed
     */
    return $scope.updatePassword = function(new_password, confirm_new_password) {
      AlertService.clear();
      if ($rootScope.member && new_password && confirm_new_password && (new_password === confirm_new_password)) {
        return LoginService.updatePassword($rootScope.member, {
          new_password: new_password,
          confirm_new_password: confirm_new_password,
          persist_login: $scope.login_form.persist_login
        }).then((function(_this) {
          return function(member) {
            if (member) {
              $scope.setClient(member);
              $scope.password_updated = true;
              return AlertService.raise('PASSWORD_RESET_SUCESS');
            }
          };
        })(this), (function(_this) {
          return function(err) {
            $scope.error = err;
            return AlertService.raise('PASSWORD_RESET_FAILED');
          };
        })(this));
      } else {
        return AlertService.raise('PASSWORD_MISMATCH');
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbMap
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of maps for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbMap A hash of options
  * @property {object} mapLoaded The map has been loaded
  * @property {object} mapReady The maps has been ready
  * @property {object} map_init The initialization the map
  * @property {object} numSearchResults The number of search results
  * @property {object} range_limit The range limit
  * @property {boolean} showAllMarkers Display or not all markers
  * @property {array} mapMarkers The map markers
  * @property {array} shownMarkers Display the markers
  * @property {integer} numberedPin The numbered pin
  * @property {integer} defaultPin The default pin
  * @proeprty {boolean} hide_not_live_stores Hide or not the live stores
  * @property {object} address The address
  * @property {object} error_msg The error message
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbMap', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'MapCtrl'
    };
  });

  angular.module('BB.Controllers').controller('MapCtrl', function($scope, $element, $attrs, $rootScope, AlertService, FormDataStoreService, $q, $window, $timeout) {
    var checkDataStore, geolocateFail, map_ready_def, options, reverseGeocode, searchFailed, searchPlaces, searchSuccess;
    $scope.controller = "public.controllers.MapCtrl";
    FormDataStoreService.init('MapCtrl', $scope, ['address', 'selectedStore', 'search_prms']);
    options = $scope.$eval($attrs.bbMap) || {};
    map_ready_def = $q.defer();
    $scope.mapLoaded = $q.defer();
    $scope.mapReady = map_ready_def.promise;
    $scope.map_init = $scope.mapLoaded.promise;
    $scope.numSearchResults = options.num_search_results || 6;
    $scope.range_limit = options.range_limit || Infinity;
    $scope.showAllMarkers = false;
    $scope.mapMarkers = [];
    $scope.shownMarkers = $scope.shownMarkers || [];
    $scope.numberedPin || ($scope.numberedPin = null);
    $scope.defaultPin || ($scope.defaultPin = null);
    $scope.hide_not_live_stores = options.hide_not_live_stores != null ? options.hide_not_live_stores : false;
    if (!$scope.address && $attrs.bbAddress) {
      $scope.address = $scope.$eval($attrs.bbAddress);
    }
    $scope.error_msg = options.error_msg || "You need to select a store";
    $scope.notLoaded($scope);
    webshim.setOptions({
      'waitReady': false,
      'loadStyles': false
    });
    webshim.polyfill("geolocation");
    $rootScope.connection_started.then(function() {
      var comp, i, key, latlong, len, ref, ref1, value;
      if (!$scope.selectedStore) {
        $scope.setLoaded($scope);
      }
      if ($scope.bb.company.companies) {
        $rootScope.parent_id = $scope.bb.company.id;
      } else if ($rootScope.parent_id) {
        $scope.initWidget({
          company_id: $rootScope.parent_id,
          first_page: $scope.bb.current_page,
          keep_basket: true
        });
        return;
      } else {
        $scope.initWidget({
          company_id: $scope.bb.company.id,
          first_page: null
        });
        return;
      }
      $scope.companies = $scope.bb.company.companies;
      if (!$scope.companies || $scope.companies.length === 0) {
        $scope.companies = [$scope.bb.company];
      }
      $scope.mapBounds = new google.maps.LatLngBounds();
      ref = $scope.companies;
      for (i = 0, len = ref.length; i < len; i++) {
        comp = ref[i];
        if (comp.address && comp.address.lat && comp.address.long) {
          latlong = new google.maps.LatLng(comp.address.lat, comp.address.long);
          $scope.mapBounds.extend(latlong);
        }
      }
      $scope.mapOptions = {
        center: $scope.mapBounds.getCenter(),
        zoom: 6,
        mapTypeId: google.maps.MapTypeId.ROADMAP,
        mapTypeControl: true,
        mapTypeControlOptions: {
          style: window.google.maps.MapTypeControlStyle.DROPDOWN_MENU
        }
      };
      if (options && options.map_options) {
        ref1 = options.map_options;
        for (key in ref1) {
          value = ref1[key];
          $scope.mapOptions[key] = value;
        }
      }
      return map_ready_def.resolve(true);
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.map_init.then(function() {
      var comp, i, latlong, len, marker, ref;
      ref = $scope.companies;
      for (i = 0, len = ref.length; i < len; i++) {
        comp = ref[i];
        if (comp.address && comp.address.lat && comp.address.long) {
          latlong = new google.maps.LatLng(comp.address.lat, comp.address.long);
          marker = new google.maps.Marker({
            map: $scope.myMap,
            position: latlong,
            visible: $scope.showAllMarkers,
            icon: $scope.defaultPin
          });
          marker.company = comp;
          if (!($scope.hide_not_live_stores && !comp.live)) {
            $scope.mapMarkers.push(marker);
          }
        }
      }
      $timeout(function() {
        $scope.myMap.fitBounds($scope.mapBounds);
        return $scope.myMap.setZoom(15);
      });
      return checkDataStore();
    });
    $scope.init = function(options) {
      if (options) {
        return $scope.hide_not_live_stores = options.hide_not_live_stores;
      }
    };

    /***
    * @ngdoc method
    * @name checkDataStore
    * @methodOf BB.Directives:bbMap
    * @description
    * If the user has clicked back to the map then display it.
     */
    checkDataStore = function() {
      if ($scope.selectedStore) {
        $scope.notLoaded($scope);
        if ($scope.search_prms) {
          $scope.searchAddress($scope.search_prms);
        } else {
          $scope.geolocate();
        }
        return google.maps.event.addListenerOnce($scope.myMap, 'idle', function() {
          return _.each($scope.mapMarkers, function(marker) {
            if ($scope.selectedStore.id === marker.company.id) {
              return google.maps.event.trigger(marker, 'click');
            }
          });
        });
      }
    };

    /***
    * @ngdoc method
    * @name title
    * @methodOf BB.Directives:bbMap
    * @description
    * Create title for the map selection step
     */
    $scope.title = function() {
      var ci, p1;
      ci = $scope.bb.current_item;
      if (ci.category && ci.category.description) {
        p1 = ci.category.description;
      } else {
        p1 = $scope.bb.company.extra.department;
      }
      return p1 + ' - ' + $scope.$eval('getCurrentStepTitle()');
    };

    /***
    * @ngdoc method
    * @name searchAddress
    * @methodOf BB.Directives:bbMap
    * @description
    * Search address in according of prms parameter
    *
    * @param {object} prms The parameters of the address
     */
    $scope.searchAddress = function(prms) {
      if ($scope.reverse_geocode_address && $scope.reverse_geocode_address === $scope.address) {
        return false;
      }
      delete $scope.geocoder_result;
      if (!prms) {
        prms = {};
      }
      $scope.search_prms = prms;
      $scope.map_init.then(function() {
        var address, ne, req, sw;
        address = $scope.address;
        if (prms.address) {
          address = prms.address;
        }
        if (address) {
          req = {
            address: address
          };
          if (prms.region) {
            req.region = prms.region;
          }
          if (prms.componentRestrictions) {
            req.componentRestrictions = prms.componentRestrictions;
          }
          if (prms.bounds) {
            sw = new google.maps.LatLng(prms.bounds.sw.x, prms.bounds.sw.y);
            ne = new google.maps.LatLng(prms.bounds.ne.x, prms.bounds.ne.y);
            req.bounds = new google.maps.LatLngBounds(sw, ne);
          }
          return new google.maps.Geocoder().geocode(req, function(results, status) {
            if (results.length > 0 && status === 'OK') {
              $scope.geocoder_result = results[0];
            }
            if (!$scope.geocoder_result || ($scope.geocoder_result && $scope.geocoder_result.partial_match)) {
              searchPlaces(req);
              return;
            } else if ($scope.geocoder_result) {
              searchSuccess($scope.geocoder_result);
            } else {
              searchFailed();
            }
            return $scope.setLoaded($scope);
          });
        }
      });
      return $scope.setLoaded($scope);
    };

    /***
    * @ngdoc method
    * @name searchPlaces
    * @methodOf BB.Directives:bbMap
    * @description
    * Search places in according of prms parameter
    *
    * @param {object} prms The parameters of the places
     */
    searchPlaces = function(prms) {
      var req, service;
      req = {
        query: prms.address,
        types: ['shopping_mall', 'store', 'embassy']
      };
      if (prms.bounds) {
        req.bounds = prms.bounds;
      }
      service = new google.maps.places.PlacesService($scope.myMap);
      return service.textSearch(req, function(results, status) {
        if (results.length > 0 && status === 'OK') {
          return searchSuccess(results[0]);
        } else if ($scope.geocoder_result) {
          return searchSuccess($scope.geocoder_result);
        } else {
          return searchFailed();
        }
      });
    };

    /***
    * @ngdoc method
    * @name searchSuccess
    * @methodOf BB.Directives:bbMap
    * @description
    * Search has been succeeded, and return 
    *
    * @param {object} result The result of the search
     */
    searchSuccess = function(result) {
      AlertService.clear();
      $scope.search_failed = false;
      $scope.loc = result.geometry.location;
      $scope.myMap.setCenter($scope.loc);
      $scope.myMap.setZoom(15);
      $scope.showClosestMarkers($scope.loc);
      return $rootScope.$broadcast("map:search_success");
    };

    /***
    * @ngdoc method
    * @name searchFailed
    * @methodOf BB.Directives:bbMap
    * @description
    * Search failed and displayed an error
     */
    searchFailed = function() {
      $scope.search_failed = true;
      AlertService.raise('LOCATION_NOT_FOUND');
      return $rootScope.$apply();
    };

    /***
    * @ngdoc method
    * @name validateAddress
    * @methodOf BB.Directives:bbMap
    * @description
    * Validate the address using form
    *
    * @param {object} form The form where address has been validate
     */
    $scope.validateAddress = function(form) {
      if (!form) {
        return false;
      }
      if (form.$error.required) {
        AlertService.clear();
        AlertService.raise('MISSING_LOCATION');
        return false;
      } else {
        return true;
      }
    };

    /***
    * @ngdoc method
    * @name showClosestMarkers
    * @methodOf BB.Directives:bbMap
    * @description
    * Display the closest markers
    *
    * @param {array} latlong Using for determinate the closest markers
     */
    $scope.showClosestMarkers = function(latlong) {
      var R, a, c, chLat, chLon, d, dLat, dLon, distances, distances_kilometres, i, iconPath, index, item, items, j, k, l, lat1, lat2, len, len1, len2, localBounds, lon1, lon2, marker, pi, rLat1, rLat2, ref, ref1;
      pi = Math.PI;
      R = 6371;
      distances = [];
      distances_kilometres = [];
      lat1 = latlong.lat();
      lon1 = latlong.lng();
      ref = $scope.mapMarkers;
      for (i = 0, len = ref.length; i < len; i++) {
        marker = ref[i];
        lat2 = marker.position.lat();
        lon2 = marker.position.lng();
        chLat = lat2 - lat1;
        chLon = lon2 - lon1;
        dLat = chLat * (pi / 180);
        dLon = chLon * (pi / 180);
        rLat1 = lat1 * (pi / 180);
        rLat2 = lat2 * (pi / 180);
        a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(rLat1) * Math.cos(rLat2);
        c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        d = R * c;
        k = d;
        d = d * 0.621371192;
        if (!$scope.showAllMarkers) {
          marker.setVisible(false);
        }
        marker.distance = d;
        marker.distance_kilometres = k;
        if (d < $scope.range_limit) {
          distances.push(marker);
        }
        if (k < $scope.range_limit) {
          distances_kilometres.push(marker);
        }
        items = [distances, distances_kilometres];
        for (j = 0, len1 = items.length; j < len1; j++) {
          item = items[j];
          item.sort(function(a, b) {
            a.distance - b.distance;
            return a.distance_kilometres - b.distance_kilometres;
          });
        }
      }
      $scope.shownMarkers = distances.slice(0, $scope.numSearchResults);
      localBounds = new google.maps.LatLngBounds();
      localBounds.extend(latlong);
      index = 1;
      ref1 = $scope.shownMarkers;
      for (l = 0, len2 = ref1.length; l < len2; l++) {
        marker = ref1[l];
        if ($scope.numberedPin) {
          iconPath = $window.sprintf($scope.numberedPin, index);
          marker.setIcon(iconPath);
        }
        marker.setVisible(true);
        localBounds.extend(marker.position);
        index += 1;
      }
      $scope.$emit('map:shown_markers_updated', $scope.shownMarkers);
      google.maps.event.trigger($scope.myMap, 'resize');
      return $scope.myMap.fitBounds(localBounds);
    };

    /***
    * @ngdoc method
    * @name openMarkerInfo
    * @methodOf BB.Directives:bbMap
    * @description
    * Display marker information on the map
    *
    * @param {object} marker The marker
     */
    $scope.openMarkerInfo = function(marker) {
      $scope.currentMarker = marker;
      return $scope.myInfoWindow.open($scope.myMap, marker);
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbMap
    * @description
    * Select an item from map
    *
    * @param {array} item The Map or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = function(item, route) {
      if (!$scope.$debounce(1000)) {
        return;
      }
      if (!item) {
        AlertService.warning({
          msg: $scope.error_msg
        });
        return;
      }
      $scope.notLoaded($scope);
      if ($scope.selectedStore && $scope.selectedStore.id !== item.id) {
        $scope.$emit('change:storeLocation');
      }
      $scope.selectedStore = item;
      return $scope.initWidget({
        company_id: item.id,
        first_page: route
      });
    };

    /***
    * @ngdoc method
    * @name roundNumberUp
    * @methodOf BB.Directives:bbMap
    * @description
    * Calculate the round number up 
    *
    * @param {integer} num The number of places
    * @param {object} places The places
     */
    $scope.roundNumberUp = function(num, places) {
      return Math.round(num * Math.pow(10, places)) / Math.pow(10, places);
    };

    /***
    * @ngdoc method
    * @name geolocate
    * @methodOf BB.Directives:bbMap
    * @description
    * Get geolocation information
     */
    $scope.geolocate = function() {
      if (!navigator.geolocation || ($scope.reverse_geocode_address && $scope.reverse_geocode_address === $scope.address)) {
        return false;
      }
      $scope.notLoaded($scope);
      return webshim.ready('geolocation', function() {
        options = {
          timeout: 5000,
          maximumAge: 3600000
        };
        return navigator.geolocation.getCurrentPosition(reverseGeocode, geolocateFail, options);
      });
    };

    /***
    * @ngdoc method
    * @name geolocateFail
    * @methodOf BB.Directives:bbMap
    * @description
    * Geolocation fail and display an error message
    *
    * @param {object} error The error
     */
    geolocateFail = function(error) {
      switch (error.code) {
        case 2:
        case 3:
          $scope.setLoaded($scope);
          AlertService.raise('GEOLOCATION_ERROR');
          break;
        default:
          $scope.setLoaded($scope);
      }
      return $scope.$apply();
    };

    /***
    * @ngdoc method
    * @name reverseGeocode
    * @methodOf BB.Directives:bbMap
    * @description
    * Reverse geocode in according of position parameter
    *
    * @param {object} positon The postion get latitude and longitude from google maps api
     */
    reverseGeocode = function(position) {
      var lat, latlng, long;
      lat = parseFloat(position.coords.latitude);
      long = parseFloat(position.coords.longitude);
      latlng = new google.maps.LatLng(lat, long);
      return new google.maps.Geocoder().geocode({
        'latLng': latlng
      }, function(results, status) {
        var ac, i, len, ref;
        if (results.length > 0 && status === 'OK') {
          $scope.geocoder_result = results[0];
          ref = $scope.geocoder_result.address_components;
          for (i = 0, len = ref.length; i < len; i++) {
            ac = ref[i];
            if (ac.types.indexOf("route") >= 0) {
              $scope.reverse_geocode_address = ac.long_name;
            }
            if (ac.types.indexOf("locality") >= 0) {
              $scope.reverse_geocode_address += ', ' + ac.long_name;
            }
            $scope.address = $scope.reverse_geocode_address;
          }
          searchSuccess($scope.geocoder_result);
        }
        return $scope.setLoaded($scope);
      });
    };

    /***
    * @ngdoc method
    * @name increaseRange
    * @methodOf BB.Directives:bbMap
    * @description
    * Increase range, the range limit is infinity
     */
    $scope.increaseRange = function() {
      $scope.range_limit = Infinity;
      return $scope.searchAddress($scope.search_prms);
    };
    $scope.$watch('display.xs', (function(_this) {
      return function(new_value, old_value) {
        if (new_value !== old_value && $scope.loc) {
          $scope.myInfoWindow.close();
          $scope.myMap.setCenter($scope.loc);
          $scope.myMap.setZoom(15);
          return $scope.showClosestMarkers($scope.loc);
        }
      };
    })(this));
    return $rootScope.$on('widget:restart', function() {
      $scope.loc = null;
      $scope.reverse_geocode_address = null;
      return $scope.address = null;
    });
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbMembershipLevels', function($rootScope, MembershipLevelsService) {
    var controller;
    ({
      restrict: 'AE',
      replace: true,
      scope: true
    });
    return controller = function($scope, $element, $attrs) {
      var checkClientDefaults;
      $rootScope.connection_started.then(function() {
        return $scope.initialise();
      });
      $scope.initialise = function() {
        if ($scope.bb.company && $scope.bb.company.$has('member_levels')) {
          $scope.notLoaded($scope);
          return MembershipLevelsService.getMembershipLevels($scope.bb.company).then(function(member_levels) {
            $scope.setLoaded($scope);
            return $scope.membership_levels = member_levels;
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        }
      };
      $scope.selectMemberLevel = function(level) {
        if (level && $scope.client) {
          $scope.client.member_level_id = level.id;
          if ($scope.$parent.$has_page_control) {

          } else {
            return $scope.decideNextPage();
          }
        }
      };
      checkClientDefaults = function() {
        var i, len, membership_level, ref, results;
        if (!$scope.bb.client_defaults.membership_ref) {
          return;
        }
        ref = $scope.membership_levels;
        results = [];
        for (i = 0, len = ref.length; i < len; i++) {
          membership_level = ref[i];
          if (membership_level.name === $scope.bb.client_defaults.membership_ref) {
            results.push($scope.selectMemberLevel(membership_level));
          } else {
            results.push(void 0);
          }
        }
        return results;
      };
      $scope.setReady = function() {
        if (!$scope.client.member_level_id) {
          return false;
        }
        return true;
      };
      return $scope.getMembershipLevel = function(member_level_id) {
        return _.find($scope.membership_levels, function(level) {
          return level.id === member_level_id;
        });
      };
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbMultiServiceSelect
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of multi service selected for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * scope: true
  * </pre>
  *
  * @param {hash}  bbMultiServiceSelect A hash of options
  * @property {object} options The options of service
  * @property {object} max_services The max services
  * @property {boolean} ordered_categories Verify if categories are ordered or not
  * @property {array} services The services
  * @property {array} company The company
  * @property {array} items An array of items service
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  var hasProp = {}.hasOwnProperty;

  angular.module('BB.Directives').directive('bbMultiServiceSelect', function() {
    return {
      restrict: 'AE',
      scope: true,
      controller: 'MultiServiceSelect'
    };
  });

  angular.module('BB.Controllers').controller('MultiServiceSelect', function($scope, $rootScope, $q, $attrs, BBModel, AlertService, CategoryService, FormDataStoreService, $modal) {
    var checkItemDefaults, initialise, initialiseCategories;
    FormDataStoreService.init('MultiServiceSelect', $scope, ['selected_category_name']);
    $scope.options = $scope.$eval($attrs.bbMultiServiceSelect) || {};
    $scope.options.max_services = $scope.options.max_services || Infinity;
    $scope.options.ordered_categories = $scope.options.ordered_categories || false;
    $scope.options.services = $scope.options.services || 'items';
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company.$has('parent') && !$scope.bb.company.$has('company_questions')) {
        $scope.bb.company.getParentPromise().then(function(parent) {
          $scope.company = parent;
          return initialise();
        });
      } else {
        $scope.company = $scope.bb.company;
      }
      return $scope.$watch($scope.options.services, function(newval, oldval) {
        if (newval && angular.isArray(newval)) {
          $scope.items = newval;
          return initialise();
        }
      });
    });
    initialise = function() {
      var promises;
      if (!$scope.items || !$scope.company) {
        return;
      }
      $scope.initialised = true;
      promises = [];
      promises.push(CategoryService.query($scope.bb.company));
      if ($scope.company.$has('company_questions')) {
        promises.push($scope.company.getCompanyQuestionsPromise());
      }
      return $q.all(promises).then(function(result) {
        var item, j, k, len, len1, ref, ref1, stacked_item;
        $scope.company_questions = result[1];
        initialiseCategories(result[0]);
        if ($scope.bb.stacked_items && $scope.bb.stacked_items.length > 0) {
          ref = $scope.bb.stacked_items;
          for (j = 0, len = ref.length; j < len; j++) {
            stacked_item = ref[j];
            ref1 = $scope.items;
            for (k = 0, len1 = ref1.length; k < len1; k++) {
              item = ref1[k];
              if (item.self === stacked_item.service.self) {
                stacked_item.service = item;
                stacked_item.service.selected = true;
                break;
              }
            }
          }
        } else {
          checkItemDefaults();
        }
        if ($scope.bb.moving_booking) {
          $scope.nextStep();
        }
        $scope.$broadcast("multi_service_select:loaded");
        return $scope.setLoaded($scope);
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name checkItemDefaults
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Check item defaults
     */
    checkItemDefaults = function() {
      var j, len, ref, service;
      if (!$scope.bb.item_defaults.service) {
        return;
      }
      ref = $scope.items;
      for (j = 0, len = ref.length; j < len; j++) {
        service = ref[j];
        if (service.self === $scope.bb.item_defaults.service.self) {
          $scope.addItem(service);
          return;
        }
      }
    };

    /***
    * @ngdoc method
    * @name initialiseCategories
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Initialize the categories in according of categories parameter
    *
    * @param {array} categories The categories of service
     */
    initialiseCategories = function(categories) {
      var all_categories, category, category_details, category_id, grouped_sub_categories, grouped_sub_category, j, k, key, len, len1, results, services, sub_categories, sub_category, value;
      if ($scope.options.ordered_categories) {
        for (j = 0, len = categories.length; j < len; j++) {
          category = categories[j];
          category.order = parseInt(category.name.slice(0, 2));
          category.name = category.name.slice(3);
        }
      }
      $scope.all_categories = _.indexBy(categories, 'id');
      all_categories = _.groupBy($scope.items, function(item) {
        return item.category_id;
      });
      sub_categories = _.findWhere($scope.company_questions, {
        name: 'Extra Category'
      });
      if (sub_categories) {
        sub_categories = _.map(sub_categories.question_items, function(sub_category) {
          return sub_category.name;
        });
      }
      categories = {};
      for (key in all_categories) {
        if (!hasProp.call(all_categories, key)) continue;
        value = all_categories[key];
        if (value.length > 0) {
          categories[key] = value;
        }
      }
      $scope.categories = [];
      results = [];
      for (category_id in categories) {
        services = categories[category_id];
        category = {};
        grouped_sub_categories = [];
        if (sub_categories) {
          for (k = 0, len1 = sub_categories.length; k < len1; k++) {
            sub_category = sub_categories[k];
            grouped_sub_category = {
              name: sub_category,
              services: _.filter(services, function(service) {
                return service.extra.extra_category === sub_category;
              })
            };
            if (grouped_sub_category.services.length > 0) {
              grouped_sub_categories.push(grouped_sub_category);
            }
          }
          category.sub_categories = grouped_sub_categories;
        } else {
          category.services = services;
        }
        if ($scope.all_categories[category_id]) {
          category_details = {
            name: $scope.all_categories[category_id].name,
            description: $scope.all_categories[category_id].description
          };
        }
        category.name = category_details.name;
        category.description = category_details.description;
        if ($scope.options.ordered_categories && $scope.all_categories[category_id]) {
          category.order = $scope.all_categories[category_id].order;
        }
        $scope.categories.push(category);
        if ($scope.selected_category_name && $scope.selected_category_name === category_details.name) {
          results.push($scope.selected_category = $scope.categories[$scope.categories.length - 1]);
        } else if ($scope.bb.item_defaults.category && $scope.bb.item_defaults.category.name === category_details.name && !$scope.selected_category) {
          $scope.selected_category = $scope.categories[$scope.categories.length - 1];
          results.push($scope.selected_category_name = $scope.selected_category.name);
        } else {
          results.push(void 0);
        }
      }
      return results;
    };

    /***
    * @ngdoc method
    * @name changeCategory
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Change category in according of category name and services parameres
    *
    * @param {string} category_name The category name
    * @param {array} services The services array
     */
    $scope.changeCategory = function(category_name, services) {
      if (category_name && services) {
        $scope.selected_category = {
          name: category_name,
          sub_categories: services
        };
        $scope.selected_category_name = $scope.selected_category.name;
        return $rootScope.$broadcast("multi_service_select:category_changed");
      }
    };

    /***
    * @ngdoc method
    * @name changeCategoryName
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Change the category name
     */
    $scope.changeCategoryName = function() {
      $scope.selected_category_name = $scope.selected_category.name;
      return $rootScope.$broadcast("multi_service_select:category_changed");
    };

    /***
    * @ngdoc method
    * @name addItem
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Add item in according of item and duration parameters
    *
    * @param {array} item The item that been added
    * @param {date} duration The duration
     */
    $scope.addItem = function(item, duration) {
      var i, iitem, j, len, ref, results;
      if ($scope.bb.stacked_items.length < $scope.options.max_services) {
        $scope.bb.clearStackedItemsDateTime();
        item.selected = true;
        iitem = new BBModel.BasketItem(null, $scope.bb);
        iitem.setDefaults($scope.bb.item_defaults);
        iitem.setService(item);
        if (duration) {
          iitem.setDuration(duration);
        }
        iitem.setGroup(item.group);
        $scope.bb.stackItem(iitem);
        $rootScope.$broadcast("multi_service_select:item_added");
        if ($scope.options.raise_alerts) {
          return AlertService.info({
            msg: item.name + " added to your treatment selection",
            persist: false
          });
        }
      } else {
        ref = $scope.items;
        results = [];
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          i.popover = "Sorry, you can only book a maximum of " + $scope.options.max_services + " treatments";
          results.push(i.popoverText = i.popover);
        }
        return results;
      }
    };

    /***
    * @ngdoc method
    * @name removeItem
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Remove item in according of item and options parameters
    *
    * @params {array} item The item that been removed
    * @params {array} options The options remove
     */
    $scope.removeItem = function(item, options) {
      var i, j, len, ref, results;
      item.selected = false;
      if (options && options.type === 'BasketItem') {
        $scope.bb.deleteStackedItem(item);
      } else {
        $scope.bb.deleteStackedItemByService(item);
      }
      $scope.bb.clearStackedItemsDateTime();
      $rootScope.$broadcast("multi_service_select:item_removed");
      ref = $scope.items;
      results = [];
      for (j = 0, len = ref.length; j < len; j++) {
        i = ref[j];
        if (i.self === item.self) {
          i.selected = false;
          break;
        } else {
          results.push(void 0);
        }
      }
      return results;
    };

    /***
    * @ngdoc method
    * @name removeStackedItem
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Removed stacked item whose type is 'BasketItem'
    *
    * @params {array} item The item that been removed
     */
    $scope.removeStackedItem = function(item) {
      return $scope.removeItem(item, {
        type: 'BasketItem'
      });
    };

    /***
    * @ngdoc method
    * @name nextStep
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Next step to selected an basket item, if basket item is not selected she display an error message
     */
    $scope.nextStep = function() {
      if ($scope.bb.stacked_items.length > 1) {
        return $scope.decideNextPage();
      } else if ($scope.bb.stacked_items.length === 1) {
        if ($scope.bb.basket && $scope.bb.basket.items.length > 0) {
          $scope.quickEmptybasket({
            preserve_stacked_items: true
          });
        }
        $scope.setBasketItem($scope.bb.stacked_items[0]);
        return $scope.decideNextPage();
      } else {
        AlertService.clear();
        return AlertService.add("danger", {
          msg: "You need to select at least one treatment to continue"
        });
      }
    };

    /***
    * @ngdoc method
    * @name addService
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Add service which add a new item
     */
    $scope.addService = function() {
      return $rootScope.$broadcast("multi_service_select:add_item");
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Set this page section as ready
     */
    $scope.setReady = function() {
      if ($scope.bb.stacked_items.length > 1) {
        return true;
      } else if ($scope.bb.stacked_items.length === 1) {
        if ($scope.bb.basket && $scope.bb.basket.items.length > 0) {
          $scope.quickEmptybasket({
            preserve_stacked_items: true
          });
        }
        $scope.setBasketItem($scope.bb.stacked_items[0]);
        return true;
      } else {
        AlertService.clear();
        AlertService.add("danger", {
          msg: "You need to select at least one treatment to continue"
        });
        return false;
      }
    };

    /***
    * @ngdoc method
    * @name selectDuration
    * @methodOf BB.Directives:bbMultiServiceSelect
    * @description
    * Select duration in according of service parameter and display the modal
    *
    * @params {object} service The service
     */
    return $scope.selectDuration = function(service) {
      var modalInstance;
      if (service.durations.length === 1) {
        return $scope.addItem(service);
      } else {
        modalInstance = $modal.open({
          templateUrl: $scope.getPartial('_select_duration_modal'),
          scope: $scope,
          controller: function($scope, $modalInstance, service) {
            $scope.durations = service.durations;
            $scope.duration = $scope.durations[0];
            $scope.service = service;
            $scope.cancel = function() {
              return $modalInstance.dismiss('cancel');
            };
            return $scope.setDuration = function() {
              return $modalInstance.close({
                service: $scope.service,
                duration: $scope.duration
              });
            };
          },
          resolve: {
            service: function() {
              return service;
            }
          }
        });
        return modalInstance.result.then(function(result) {
          return $scope.addItem(result.service, result.duration);
        });
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbTimeRangeStacked
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of time range stacked for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbTimeRangeStacked A hash of options
  * @property {date} start_date The start date of time range list
  * @property {date} end_date The end date of time range list
  * @property {integer} available_times The available times of range list
  * @property {object} day_of_week The day of week
  * @property {object} selected_day The selected day from the multi time range list
  * @property {object} original_start_date The original start date of range list
  * @property {object} start_at_week_start The start at week start of range list
  * @property {object} selected_slot The selected slot from multi time range list
  * @property {object} selected_date The selected date from multi time range list
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  var hasProp = {}.hasOwnProperty;

  angular.module('BB.Directives').directive('bbTimeRangeStacked', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'TimeRangeListStackedController'
    };
  });

  angular.module('BB.Controllers').controller('TimeRangeListStackedController', function($scope, $element, $attrs, $rootScope, $q, TimeService, AlertService, BBModel, FormDataStoreService, PersonService, PurchaseService, DateTimeUlititiesService) {
    var isSubtractValid, setEnabledSlots, setTimeRange, spliceExistingDateTimes, updateHideStatus;
    $scope.controller = "public.controllers.TimeRangeListStacked";
    FormDataStoreService.init('TimeRangeListStacked', $scope, ['selected_slot', 'original_start_date', 'start_at_week_start']);
    $scope.notLoaded($scope);
    $scope.available_times = 0;
    $rootScope.connection_started.then(function() {
      var diff, selected_day, start_date;
      $scope.options = $scope.$eval($attrs.bbTimeRangeStacked) || {};
      if (!$scope.time_range_length) {
        if ($attrs.bbTimeRangeLength != null) {
          $scope.time_range_length = $scope.$eval($attrs.bbTimeRangeLength);
        } else if ($scope.options && $scope.options.time_range_length) {
          $scope.time_range_length = $scope.options.time_range_length;
        } else {
          $scope.time_range_length = 7;
        }
      }
      if (($attrs.bbDayOfWeek != null) || ($scope.options && $scope.options.day_of_week)) {
        $scope.day_of_week = $attrs.bbDayOfWeek != null ? $scope.$eval($attrs.bbDayOfWeek) : $scope.options.day_of_week;
      }
      if (($attrs.bbSelectedDay != null) || ($scope.options && $scope.options.selected_day)) {
        selected_day = $attrs.bbSelectedDay != null ? moment($scope.$eval($attrs.bbSelectedDay)) : moment($scope.options.selected_day);
        if (moment.isMoment(selected_day)) {
          $scope.selected_day = selected_day;
        }
      }
      if (!$scope.start_date && $scope.last_selected_date) {
        if ($scope.original_start_date) {
          diff = $scope.last_selected_date.diff($scope.original_start_date, 'days');
          diff = diff % $scope.time_range_length;
          diff = diff === 0 ? diff : diff + 1;
          start_date = $scope.last_selected_date.clone().subtract(diff, 'days');
          setTimeRange($scope.last_selected_date, start_date);
        } else {
          setTimeRange($scope.last_selected_date);
        }
      } else if ($scope.bb.stacked_items[0].date) {
        setTimeRange($scope.bb.stacked_items[0].date.date);
      } else if ($scope.selected_day) {
        $scope.original_start_date = $scope.original_start_date || moment($scope.selected_day);
        setTimeRange($scope.selected_day);
      } else {
        $scope.start_at_week_start = true;
        setTimeRange(moment());
      }
      return $scope.loadData();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name setTimeRange
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Set time range in according of selected_date 
    *
    * @param {date} selected_date The selected date from multi time range list
    * @param {date} start_date The start date of range list
     */
    setTimeRange = function(selected_date, start_date) {
      if (start_date) {
        $scope.start_date = start_date;
      } else if ($scope.day_of_week) {
        $scope.start_date = selected_date.clone().day($scope.day_of_week);
      } else if ($scope.start_at_week_start) {
        $scope.start_date = selected_date.clone().startOf('week');
      } else {
        $scope.start_date = selected_date.clone();
      }
      $scope.selected_day = selected_date;
      $scope.selected_date = $scope.selected_day.toDate();
      return isSubtractValid();
    };

    /***
    * @ngdoc method
    * @name add
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Add date
    *
    * @param {object} amount The selected amount
    * @param {array} type The start type
     */
    $scope.add = function(amount, type) {
      $scope.selected_day = moment($scope.selected_date);
      switch (type) {
        case 'days':
          setTimeRange($scope.selected_day.add(amount, 'days'));
          break;
        case 'weeks':
          $scope.start_date.add(amount, 'weeks');
          setTimeRange($scope.start_date);
      }
      return $scope.loadData();
    };

    /***
    * @ngdoc method
    * @name subtract
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Subtract in according of amount and type parameters
    *
    * @param {object} amount The selected amount
    * @param {object} type The start type
     */
    $scope.subtract = function(amount, type) {
      return $scope.add(-amount, type);
    };

    /***
    * @ngdoc method
    * @name isSubtractValid
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Verify if the subtract is valid or not
     */
    isSubtractValid = function() {
      var diff;
      $scope.is_subtract_valid = true;
      diff = Math.ceil($scope.selected_day.diff(moment(), 'day', true));
      $scope.subtract_length = diff < $scope.time_range_length ? diff : $scope.time_range_length;
      if (diff <= 0) {
        $scope.is_subtract_valid = false;
      }
      if ($scope.subtract_length > 1) {
        return $scope.subtract_string = "Prev " + $scope.subtract_length + " days";
      } else if ($scope.subtract_length === 1) {
        return $scope.subtract_string = "Prev day";
      } else {
        return $scope.subtract_string = "Prev";
      }
    };

    /***
    * @ngdoc method
    * @name selectedDateChanged
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Called on datepicker date change
     */
    $scope.selectedDateChanged = function() {
      setTimeRange(moment($scope.selected_date));
      $scope.selected_slot = null;
      return $scope.loadData();
    };

    /***
    * @ngdoc method
    * @name updateHideStatus
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Update the hidden status
     */
    updateHideStatus = function() {
      var day, key, ref, results;
      ref = $scope.days;
      results = [];
      for (key in ref) {
        day = ref[key];
        results.push($scope.days[key].hide = !day.date.isSame($scope.selected_day, 'day'));
      }
      return results;
    };

    /***
    * @ngdoc method
    * @name isPast
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Calculate if the current earliest date is in the past - in which case we. Might want to disable going backwards
     */
    $scope.isPast = function() {
      if (!$scope.start_date) {
        return true;
      }
      return moment().isAfter($scope.start_date);
    };

    /***
    * @ngdoc method
    * @name status
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Check the status of the slot to see if it has been selected
    *
    * @param {date} day The day
    * @param {object} slot The slot of day in multi time range list
     */
    $scope.status = function(day, slot) {
      var status;
      if (!slot) {
        return;
      }
      status = slot.status();
      return status;
    };

    /***
    * @ngdoc method
    * @name highlightSlot
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Check the highlight slot
    *
    * @param {date} day The day
    * @param {object} slot The slot of day in multi time range list
     */
    $scope.highlightSlot = function(day, slot) {
      var i, item, len, ref;
      if (day && slot && slot.availability() > 0) {
        $scope.bb.clearStackedItemsDateTime();
        if ($scope.selected_slot) {
          $scope.selected_slot.selected = false;
        }
        $scope.setLastSelectedDate(day.date);
        $scope.selected_slot = angular.copy(slot);
        $scope.selected_day = day.date;
        $scope.selected_date = day.date.toDate();
        $scope.$broadcast('slotChanged', day, slot);
        while (slot) {
          ref = $scope.bb.stacked_items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            if (item.service.self === slot.service.self && !item.date && !item.time) {
              item.setDate(day);
              item.setTime(slot);
              slot = slot.next;
              break;
            }
          }
        }
        updateHideStatus();
        return $rootScope.$broadcast("time:selected");
      }
    };

    /***
    * @ngdoc method
    * @name loadData
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Load the time data
     */
    $scope.loadData = function() {
      var edate, grouped_items, i, items, len, pslots;
      $scope.notLoaded($scope);
      if ($scope.request && $scope.request.start.twix($scope.request.end).contains($scope.selected_day)) {
        updateHideStatus();
        $scope.setLoaded($scope);
        return;
      }
      $scope.start_date = moment($scope.start_date);
      edate = moment($scope.start_date).add($scope.time_range_length, 'days');
      $scope.end_date = moment(edate).add(-1, 'days');
      $scope.request = {
        start: moment($scope.start_date),
        end: moment($scope.end_date)
      };
      pslots = [];
      grouped_items = _.groupBy($scope.bb.stacked_items, function(item) {
        return item.service.id;
      });
      grouped_items = _.toArray(grouped_items);
      for (i = 0, len = grouped_items.length; i < len; i++) {
        items = grouped_items[i];
        pslots.push(TimeService.query({
          company: $scope.bb.company,
          cItem: items[0],
          date: $scope.start_date,
          end_date: $scope.end_date,
          client: $scope.client,
          available: 1
        }));
      }
      return $q.all(pslots).then(function(res) {
        var _i, day, item, j, k, l, len1, len2, ref, slots, times, v;
        $scope.data_valid = true;
        $scope.days = {};
        for (_i = j = 0, len1 = grouped_items.length; j < len1; _i = ++j) {
          items = grouped_items[_i];
          slots = res[_i];
          if (!slots || slots.length === 0) {
            $scope.data_valid = false;
          }
          for (l = 0, len2 = items.length; l < len2; l++) {
            item = items[l];
            spliceExistingDateTimes(item, slots);
            item.slots = {};
            for (day in slots) {
              if (!hasProp.call(slots, day)) continue;
              times = slots[day];
              item.slots[day] = _.indexBy(times, 'time');
            }
          }
        }
        if ($scope.data_valid) {
          ref = res[0];
          for (k in ref) {
            v = ref[k];
            $scope.days[k] = {
              date: moment(k)
            };
          }
          setEnabledSlots();
          updateHideStatus();
          $rootScope.$broadcast("TimeRangeListStacked:loadFinished");
          $scope.$broadcast("dataReloaded");
        } else {

        }
        return $scope.setLoaded($scope);
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name spliceExistingDateTimes
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Splice existing date and times
    *
    * @param {array} stacked_item The stacked item
    * @param {object} slots The slots of stacked_item from the multi_time_range_list
     */
    spliceExistingDateTimes = function(stacked_item, slots) {
      var datetime, time, time_slot;
      if (!stacked_item.datetime && !stacked_item.date) {
        return;
      }
      datetime = stacked_item.datetime || DateTimeUlititiesService.convertTimeSlotToMoment(stacked_item.date, stacked_item.time);
      if ($scope.start_date <= datetime && $scope.end_date >= datetime) {
        time = DateTimeUlititiesService.convertMomentToTime(datetime);
        time_slot = _.findWhere(slots[datetime.toISODate()], {
          time: time
        });
        if (!time_slot) {
          time_slot = stacked_item.time;
          slots[datetime.toISODate()].splice(0, 0, time_slot);
        }
        return time_slot.selected = stacked_item.self === $scope.bb.stacked_items[0].self;
      }
    };

    /***
    * @ngdoc method
    * @name setEnabledSlots
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Set the enabled slots
     */
    setEnabledSlots = function() {
      var day, day_data, isSlotValid, ref, results, slot, time;
      ref = $scope.days;
      results = [];
      for (day in ref) {
        day_data = ref[day];
        day_data.slots = {};
        if ($scope.bb.stacked_items.length > 1) {
          results.push((function() {
            var ref1, results1;
            ref1 = $scope.bb.stacked_items[0].slots[day];
            results1 = [];
            for (time in ref1) {
              slot = ref1[time];
              slot = angular.copy(slot);
              isSlotValid = function(slot) {
                var duration, i, index, next, ref2, valid;
                valid = false;
                time = slot.time;
                duration = $scope.bb.stacked_items[0].service.duration;
                next = time + duration;
                for (index = i = 1, ref2 = $scope.bb.stacked_items.length - 1; 1 <= ref2 ? i <= ref2 : i >= ref2; index = 1 <= ref2 ? ++i : --i) {
                  if (!_.isEmpty($scope.bb.stacked_items[index].slots[day]) && $scope.bb.stacked_items[index].slots[day][next]) {
                    slot.next = angular.copy($scope.bb.stacked_items[index].slots[day][next]);
                    slot = slot.next;
                    next = next + $scope.bb.stacked_items[index].service.duration;
                  } else {
                    return false;
                  }
                }
                return true;
              };
              if (isSlotValid(slot)) {
                results1.push(day_data.slots[slot.time] = slot);
              } else {
                results1.push(void 0);
              }
            }
            return results1;
          })());
        } else {
          results.push((function() {
            var ref1, results1;
            ref1 = $scope.bb.stacked_items[0].slots[day];
            results1 = [];
            for (time in ref1) {
              slot = ref1[time];
              results1.push(day_data.slots[slot.time] = slot);
            }
            return results1;
          })());
        }
      }
      return results;
    };

    /***
    * @ngdoc method
    * @name pretty_month_title
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Display pretty month title in according of month format and year format parameters
    *
    * @param {date} month_format The month format
    * @param {date} year_format The year format
    * @param {string} separator The separator is '-'
     */
    $scope.pretty_month_title = function(month_format, year_format, seperator) {
      var month_year_format, start_date;
      if (seperator == null) {
        seperator = '-';
      }
      if (!$scope.start_date) {
        return;
      }
      month_year_format = month_format + ' ' + year_format;
      if ($scope.start_date && $scope.end_date && $scope.end_date.isAfter($scope.start_date, 'month')) {
        start_date = $scope.start_date.format(month_format);
        if ($scope.start_date.month() === 11) {
          start_date = $scope.start_date.format(month_year_format);
        }
        return start_date + ' ' + seperator + ' ' + $scope.end_date.format(month_year_format);
      } else {
        return $scope.start_date.format(month_year_format);
      }
    };

    /***
    * @ngdoc method
    * @name confirm
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Confirm the time range stacked
    *
    * @param {string =} route A specific route to load
    * @param {object} options The options
     */
    $scope.confirm = function(route, options) {
      var booking, different, found, i, item, j, l, len, len1, len2, prom, ref, ref1, ref2;
      if (options == null) {
        options = {};
      }
      ref = $scope.bb.stacked_items;
      for (i = 0, len = ref.length; i < len; i++) {
        item = ref[i];
        if (!item.time) {
          AlertService.add("danger", {
            msg: "Select a time to continue your booking"
          });
          return false;
        }
      }
      if (($scope.bb.moving_booking != null) && ($scope.bb.moving_booking.bookings != null)) {
        different = false;
        ref1 = $scope.bb.moving_booking.bookings;
        for (j = 0, len1 = ref1.length; j < len1; j++) {
          booking = ref1[j];
          found = false;
          ref2 = $scope.bb.stacked_items;
          for (l = 0, len2 = ref2.length; l < len2; l++) {
            item = ref2[l];
            if (booking.getDateString() === item.date.string_date && booking.getTimeInMins() === item.time.time && booking.category_name === item.category_name) {
              found = true;
            }
          }
          if (!found) {
            different = true;
            break;
          }
        }
        if (!different) {
          AlertService.add("danger", {
            msg: "Your treatments are already booked for this time."
          });
          return false;
        }
      }
      $scope.bb.basket.clear();
      $scope.bb.pushStackToBasket();
      if ($scope.bb.moving_booking) {
        $scope.notLoaded($scope);
        prom = PurchaseService.update({
          purchase: $scope.bb.moving_booking,
          bookings: $scope.bb.basket.items
        });
        prom.then(function(purchase) {
          purchase.getBookingsPromise().then(function(bookings) {
            var _i, len3, m, oldb, results;
            results = [];
            for (m = 0, len3 = bookings.length; m < len3; m++) {
              booking = bookings[m];
              if ($scope.bookings) {
                results.push((function() {
                  var len4, n, ref3, results1;
                  ref3 = $scope.bookings;
                  results1 = [];
                  for (_i = n = 0, len4 = ref3.length; n < len4; _i = ++n) {
                    oldb = ref3[_i];
                    if (oldb.id === booking.id) {
                      results1.push($scope.bookings[_i] = booking);
                    } else {
                      results1.push(void 0);
                    }
                  }
                  return results1;
                })());
              } else {
                results.push(void 0);
              }
            }
            return results;
          });
          $scope.setLoaded($scope);
          $scope.bb.current_item.move_done = true;
          return $scope.decideNextPage();
        }, function(err) {
          $scope.setLoaded($scope);
          return AlertService.add("danger", {
            msg: "Failed to move booking"
          });
        });
        return;
      }
      $scope.notLoaded($scope);
      if (options.do_not_route) {
        return $scope.updateBasket();
      } else {
        return $scope.updateBasket().then(function() {
          $scope.setLoaded($scope);
          return $scope.decideNextPage(route);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbTimeRangeStacked
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = function() {
      return $scope.confirm('', {
        do_not_route: true
      });
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPackageItems
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of packages for the currently in scroe company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbPackgeItems   A hash of options
  * @property {array} packages An array of all services
  * @property {array} bookable_items An array of all BookableItems - used if the current_item has already selected a resource or person
  * @property {array} bookable_services An array of Services - used if the current_item has already selected a resource or person
  * @property {package} package The currectly selected package
  * @property {hash} filters A hash of filters
  * @example
  *  <example module="BB"> 
  *    <file name="index.html">
  *   <div bb-api-url='https://uk.bookingbug.com'>
  *   <div  bb-widget='{company_id:21}'>
  *     <div bb-package-items>
  *        <ul>
  *          <li ng-repeat='package in packages'> {{package.name}}</li>
  *        </ul>
  *     </div>
  *     </div>
  *     </div>
  *   </file> 
  *  </example>
  *
   */
  angular.module('BB.Directives').directive('bbPackageItems', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PackageItem'
    };
  });

  angular.module('BB.Controllers').controller('PackageItem', function($scope, $rootScope, PackageItemService) {
    $scope.controller = "public.controllers.PackageItem";
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        return $scope.init($scope.bb.company);
      }
    });
    $scope.init = function(company) {
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      return PackageItemService.query(company).then(function(package_items) {
        return $scope.packages = package_items;
      });
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbPackageItems
    * @description
    * Select a package into the current booking journey and route on to the next page dpending on the current page control
    *
    * @param {object} package The Service or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = function(item, route) {
      if ($scope.$parent.$has_page_control) {
        $scope["package"] = item;
        return false;
      } else {
        $scope.booking_item.setPackageItem(item);
        $scope.decideNextPage(route);
        return true;
      }
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbPackageItems
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    $scope.setReady = function() {
      if ($scope["package"]) {
        $scope.booking_item.setPackageItem($scope["package"]);
        return true;
      } else {
        return false;
      }
    };

    /***
    * @ngdoc method
    * @name getPackageServices
    * @methodOf BB.Directives:bbPackageItems
    * @description
    * Query all of the services included in the package
    * @params {array} item.service_list an array of services within the item
     */
    return $scope.getPackageServices = function(item) {
      var promise;
      if (item && !item.service_list) {
        item.service_list = [];
        promise = PackageItemService.getPackageServices(item);
        promise.then(function(services) {
          return item.service_list = services;
        });
        return true;
      } else {
        return false;
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPackagePicker
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of package pickers for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {date} sel_date The sel date
  * @property {date} selected_date The selected date
  * @property {boolean} picked_time The picked time
  * @property {array} timeSlots The time slots
  * @property {boolean} data_valid The valid data
   */
  angular.module('BB.Directives').directive('bbPackagePicker', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PackagePicker'
    };
  });

  angular.module('BB.Controllers').controller('PackagePicker', function($scope, $rootScope, $q, TimeService, BBModel) {
    $scope.controller = "public.controllers.PackagePicker";
    $scope.sel_date = moment().add(1, 'days');
    $scope.selected_date = $scope.sel_date.toDate();
    $scope.picked_time = false;
    $scope.$watch('selected_date', (function(_this) {
      return function(newv, oldv) {
        $scope.sel_date = moment(newv);
        return $scope.loadDay();
      };
    })(this));

    /***
    * @ngdoc method
    * @name loadDay
    * @methodOf BB.Directives:bbPackagePicker
    * @description
    * Load day
     */
    $scope.loadDay = (function(_this) {
      return function() {
        var i, item, len, pslots, ref;
        $scope.timeSlots = [];
        $scope.notLoaded($scope);
        pslots = [];
        ref = $scope.stackedItems;
        for (i = 0, len = ref.length; i < len; i++) {
          item = ref[i];
          pslots.push(TimeService.query({
            company: $scope.bb.company,
            cItem: item,
            date: $scope.sel_date,
            client: $scope.client
          }));
        }
        return $q.all(pslots).then(function(res) {
          var _i, earliest, j, k, l, latest, len1, len2, len3, len4, len5, m, n, next_earliest, next_latest, ref1, ref2, ref3, ref4, ref5, results, slot;
          $scope.setLoaded($scope);
          $scope.data_valid = true;
          $scope.timeSlots = [];
          ref1 = $scope.stackedItems;
          for (_i = j = 0, len1 = ref1.length; j < len1; _i = ++j) {
            item = ref1[_i];
            item.slots = res[_i];
            if (!item.slots || item.slots.length === 0) {
              $scope.data_valid = false;
            }
            item.order = _i;
          }
          if ($scope.data_valid) {
            $scope.timeSlots = res;
            earliest = null;
            ref2 = $scope.stackedItems;
            for (k = 0, len2 = ref2.length; k < len2; k++) {
              item = ref2[k];
              next_earliest = null;
              ref3 = item.slots;
              for (l = 0, len3 = ref3.length; l < len3; l++) {
                slot = ref3[l];
                if (earliest && slot.time < earliest) {
                  slot.disable();
                } else if (!next_earliest) {
                  next_earliest = slot.time + item.service.duration;
                }
              }
              earliest = next_earliest;
            }
            latest = null;
            ref4 = $scope.bb.stacked_items.slice(0).reverse();
            results = [];
            for (m = 0, len4 = ref4.length; m < len4; m++) {
              item = ref4[m];
              next_latest = null;
              ref5 = item.slots;
              for (n = 0, len5 = ref5.length; n < len5; n++) {
                slot = ref5[n];
                if (latest && slot.time > latest) {
                  slot.disable();
                } else {
                  next_latest = slot.time - item.service.duration;
                }
              }
              results.push(latest = next_latest);
            }
            return results;
          }
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectSlot
    * @methodOf BB.Directives:bbPackagePicker
    * @description
    * Select slot in according of sel_item and slot parameters
    *
    * @param {array} sel_item The sel item
    * @param {object} slot The slot
     */
    $scope.selectSlot = (function(_this) {
      return function(sel_item, slot) {
        var count, current, i, item, j, k, latest, len, len1, len2, next, ref, ref1, slots, time;
        ref = $scope.stackedItems;
        for (count = i = 0, len = ref.length; i < len; count = ++i) {
          item = ref[count];
          if (count === sel_item.order) {
            item.setDate(new BBModel.Day({
              date: $scope.sel_date.format(),
              spaces: 1
            }));
            item.setTime(slot);
            next = slot.time + item.service.duration;
            time = slot.time;
            slot = null;
            if (count > 0) {
              current = count - 1;
              while (current >= 0) {
                item = $scope.bb.stacked_items[current];
                latest = time - item.service.duration;
                if (!item.time || item.time.time > latest) {
                  item.setDate(new BBModel.Day({
                    date: $scope.sel_date.format(),
                    spaces: 1
                  }));
                  item.setTime(null);
                  ref1 = item.slots;
                  for (j = 0, len1 = ref1.length; j < len1; j++) {
                    slot = ref1[j];
                    if (slot.time < latest) {
                      item.setTime(slot);
                    }
                  }
                }
                time = item.time.time;
                current -= 1;
              }
            }
          } else if (count > sel_item.order) {
            slots = item.slots;
            item.setDate(new BBModel.Day({
              date: $scope.sel_date.format(),
              spaces: 1
            }));
            if (slots) {
              item.setTime(null);
              for (k = 0, len2 = slots.length; k < len2; k++) {
                slot = slots[k];
                if (slot.time >= next && !item.time) {
                  item.setTime(slot);
                  next = slot.time + item.service.duration;
                }
              }
            }
          }
        }
        return $scope.picked_time = true;
      };
    })(this);

    /***
    * @ngdoc method
    * @name hasAvailability
    * @methodOf BB.Directives:bbPackagePicker
    * @description
    * Checks if picker have the start time and the end time available
    *
    * @param {object} slots The slots of the package picker
    * @param {date} start_time The start time of the picker
    * @param {date} end_time The end time of the picker
     */
    $scope.hasAvailability = (function(_this) {
      return function(slots, start_time, end_time) {
        var i, j, k, l, len, len1, len2, len3, slot;
        if (!slots) {
          return false;
        }
        if (start_time && end_time) {
          for (i = 0, len = slots.length; i < len; i++) {
            slot = slots[i];
            if (slot.time >= start_time && slot.time < end_time && slot.availability() > 0) {
              return true;
            }
          }
        } else if (end_time) {
          for (j = 0, len1 = slots.length; j < len1; j++) {
            slot = slots[j];
            if (slot.time < end_time && slot.availability() > 0) {
              return true;
            }
          }
        } else if (start_time) {
          for (k = 0, len2 = slots.length; k < len2; k++) {
            slot = slots[k];
            if (slot.time >= start_time && slot.availability() > 0) {
              return true;
            }
          }
        } else {
          for (l = 0, len3 = slots.length; l < len3; l++) {
            slot = slots[l];
            if (slot.availability() > 0) {
              return true;
            }
          }
        }
      };
    })(this);
    return $scope.confirm = (function(_this) {
      return function() {};
    })(this);
  });

}).call(this);

(function() {
  'use strict';
  var BBBasicPageCtrl;

  BBBasicPageCtrl = function($scope, $q, ValidatorService) {
    var isScopeReady;
    $scope.controllerClass = "public.controllers.PageController";
    $scope.$has_page_control = true;
    $scope.validator = ValidatorService;
    isScopeReady = (function(_this) {
      return function(cscope) {
        var child, children, i, len, ready, ready_list;
        ready_list = [];
        children = [];
        child = cscope.$$childHead;
        while (child) {
          children.push(child);
          child = child.$$nextSibling;
        }
        children.sort(function(a, b) {
          if ((a.ready_order || 0) >= (b.ready_order || 0)) {
            return 1;
          } else {
            return -1;
          }
        });
        for (i = 0, len = children.length; i < len; i++) {
          child = children[i];
          ready = isScopeReady(child);
          if (angular.isArray(ready)) {
            Array.prototype.push.apply(ready_list, ready);
          } else {
            ready_list.push(ready);
          }
        }
        if (cscope.hasOwnProperty('setReady')) {
          ready_list.push(cscope.setReady());
        }
        return ready_list;
      };
    })(this);

    /***
    * @ngdoc method
    * @name checkReady
    * @methodOf BB.Directives:bbPage
    * @description
    * Check the page ready
     */
    $scope.checkReady = function() {
      var checkread, i, len, ready_list, v;
      ready_list = isScopeReady($scope);
      checkread = $q.defer();
      $scope.$checkingReady = checkread.promise;
      ready_list = ready_list.filter(function(v) {
        return !((typeof v === 'boolean') && v);
      });
      if (!ready_list || ready_list.length === 0) {
        checkread.resolve();
        return true;
      }
      for (i = 0, len = ready_list.length; i < len; i++) {
        v = ready_list[i];
        if ((typeof value === 'boolean') || !v) {
          checkread.reject();
          return false;
        }
      }
      $scope.notLoaded($scope);
      $q.all(ready_list).then(function() {
        $scope.setLoaded($scope);
        return checkread.resolve();
      }, function(err) {
        return $scope.setLoaded($scope);
      });
      return true;
    };

    /***
    * @ngdoc method
    * @name routeReady
    * @methodOf BB.Directives:bbPage
    * @description
    * Check the page route ready
    *
    * @param {string=} route A specific route to load
     */
    return $scope.routeReady = function(route) {
      if (!$scope.$checkingReady) {
        return $scope.decideNextPage(route);
      } else {
        return $scope.$checkingReady.then((function(_this) {
          return function() {
            return $scope.decideNextPage(route);
          };
        })(this));
      }
    };
  };


  /***
  * @ngdoc directive
  * @name BB.Directives:bbPage
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of page for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
   */

  angular.module('BB.Directives').directive('bbPage', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PageController'
    };
  });

  angular.module('BB.Controllers').controller('PageController', BBBasicPageCtrl);

  angular.module('BB.Services').value("PageControllerService", BBBasicPageCtrl);

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPayment
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of payments for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} total The total of payment
   */
  angular.module('BB.Directives').directive('bbPayment', function($window, $location, $sce, SettingsService, AlertService) {
    var error, getHost, linker, sendLoadEvent;
    error = function(scope, message) {
      return scope.error(message);
    };
    getHost = function(url) {
      var a;
      a = document.createElement('a');
      a.href = url;
      return a['protocol'] + '//' + a['host'];
    };
    sendLoadEvent = function(element, origin, scope) {
      var custom_stylesheet, payload, referrer;
      referrer = $location.protocol() + "://" + $location.host();
      if ($location.port()) {
        referrer += ":" + $location.port();
      }
      if (scope.payment_options.custom_stylesheet) {
        custom_stylesheet = scope.payment_options.custom_stylesheet;
      }
      payload = JSON.stringify({
        'type': 'load',
        'message': referrer,
        'custom_partial_url': scope.bb.custom_partial_url,
        'custom_stylesheet': custom_stylesheet,
        'scroll_offset': SettingsService.getScrollOffset()
      });
      return element.find('iframe')[0].contentWindow.postMessage(payload, origin);
    };
    linker = function(scope, element, attributes) {
      scope.payment_options = scope.$eval(attributes.bbPayment) || {};
      scope.route_to_next_page = scope.payment_options.route_to_next_page != null ? scope.payment_options.route_to_next_page : true;
      element.find('iframe').bind('load', (function(_this) {
        return function(event) {
          var origin, url;
          if (scope.bb && scope.bb.total && scope.bb.total.$href('new_payment')) {
            url = scope.bb.total.$href('new_payment');
          }
          origin = getHost(url);
          sendLoadEvent(element, origin, scope);
          return scope.$apply(function() {
            return scope.callSetLoaded();
          });
        };
      })(this));
      return $window.addEventListener('message', (function(_this) {
        return function(event) {
          var data;
          if (angular.isObject(event.data)) {
            data = event.data;
          } else if (!event.data.match(/iFrameSizer/)) {
            data = JSON.parse(event.data);
          }
          return scope.$apply(function() {
            if (data) {
              switch (data.type) {
                case "submitting":
                  return scope.callNotLoaded();
                case "error":
                  scope.$emit("payment:failed");
                  scope.callNotLoaded();
                  AlertService.raise('PAYMENT_FAILED');
                  return document.getElementsByTagName("iframe")[0].src += '';
                case "payment_complete":
                  scope.callSetLoaded();
                  return scope.paymentDone();
              }
            }
          });
        };
      })(this), false);
    };
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Payment',
      link: linker
    };
  });

  angular.module('BB.Controllers').controller('Payment', function($scope, $rootScope, $q, $location, $window, $sce, $log, $timeout) {
    $scope.controller = "public.controllers.Payment";
    $scope.notLoaded($scope);
    if ($scope.purchase) {
      $scope.bb.total = $scope.purchase;
    }
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.total) {
          $scope.bb.total = $scope.total;
        }
        if ($scope.bb && $scope.bb.total && $scope.bb.total.$href('new_payment')) {
          return $scope.url = $sce.trustAsResourceUrl($scope.bb.total.$href('new_payment'));
        }
      };
    })(this));

    /***
    * @ngdoc method
    * @name callNotLoaded
    * @methodOf BB.Directives:bbPayment
    * @description
    * Call not loaded
     */
    $scope.callNotLoaded = (function(_this) {
      return function() {
        return $scope.notLoaded($scope);
      };
    })(this);

    /***
    * @ngdoc method
    * @name callSetLoaded
    * @methodOf BB.Directives:bbPayment
    * @description
    * Call set loaded
     */
    $scope.callSetLoaded = (function(_this) {
      return function() {
        return $scope.setLoaded($scope);
      };
    })(this);

    /***
    * @ngdoc method
    * @name paymentDone
    * @methodOf BB.Directives:bbPayment
    * @description
    * Payment done
     */
    $scope.paymentDone = function() {
      $scope.bb.payment_status = "complete";
      $scope.$emit('payment:complete');
      if ($scope.route_to_next_page) {
        return $scope.decideNextPage();
      }
    };
    return $scope.error = function(message) {
      return $log.warn("Payment Failure: " + message);
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPayForm
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of pay forms for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} total The total pay_form price
  * @property {array} card The card is used to payment
   */
  angular.module('BB.Directives').directive('bbPayForm', function($window, $timeout, $sce, $http, $compile, $document, $location, SettingsService) {

    /***
    * @ngdoc method
    * @name applyCustomPartials
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Apply the custom partials in according of custom partial url, scope and element parameters
    *
    * @param {string} custom_partial_url The custom partial url
     */
    var applyCustomPartials, applyCustomStylesheet, linker;
    applyCustomPartials = function(custom_partial_url, scope, element) {
      if (custom_partial_url != null) {
        $document.domain = "bookingbug.com";
        return $http.get(custom_partial_url).then(function(custom_templates) {
          return $compile(custom_templates.data)(scope, function(custom, scope) {
            var custom_form, e, i, len;
            for (i = 0, len = custom.length; i < len; i++) {
              e = custom[i];
              if (e.tagName === "STYLE") {
                element.after(e.outerHTML);
              }
            }
            custom_form = (function() {
              var j, len1, results;
              results = [];
              for (j = 0, len1 = custom.length; j < len1; j++) {
                e = custom[j];
                if (e.id === 'payment_form') {
                  results.push(e);
                }
              }
              return results;
            })();
            if (custom_form && custom_form[0]) {
              return $compile(custom_form[0].innerHTML)(scope, function(compiled_form, scope) {
                var action, form;
                form = element.find('form')[0];
                action = form.action;
                compiled_form.attr('action', action);
                return $(form).replaceWith(compiled_form);
              });
            }
          });
        });
      }
    };

    /***
    * @ngdoc method
    * @name applyCustomStylesheet
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Apply the custom stylesheet from href
    *
    * @param {string} href The href of the stylesheet
     */
    applyCustomStylesheet = function(href) {
      var css_id, head, link;
      css_id = 'custom_css';
      if (!document.getElementById(css_id)) {
        head = document.getElementsByTagName('head')[0];
        link = document.createElement('link');
        link.id = css_id;
        link.rel = 'stylesheet';
        link.type = 'text/css';
        link.href = href;
        link.media = 'all';
        head.appendChild(link);
        return link.onload = function() {
          if ('parentIFrame' in $window) {
            return parentIFrame.size();
          }
        };
      }
    };
    linker = function(scope, element, attributes) {
      return $window.addEventListener('message', (function(_this) {
        return function(event) {
          var data;
          if (angular.isObject(event.data)) {
            data = event.data;
          } else if (angular.isString(event.data) && !event.data.match(/iFrameSizer/)) {
            data = JSON.parse(event.data);
          }
          if (data) {
            switch (data.type) {
              case "load":
                return scope.$apply(function() {
                  scope.referrer = data.message;
                  if (data.custom_partial_url) {
                    applyCustomPartials(event.data.custom_partial_url, scope, element);
                  }
                  if (data.custom_stylesheet) {
                    applyCustomStylesheet(data.custom_stylesheet);
                  }
                  if (data.scroll_offset) {
                    return SettingsService.setScrollOffset(data.scroll_offset);
                  }
                });
            }
          }
        };
      })(this), false);
    };
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PayForm',
      link: linker
    };
  });

  angular.module('BB.Controllers').controller('PayForm', function($scope, $location) {
    var sendSubmittingEvent, submitPaymentForm;
    $scope.controller = "public.controllers.PayForm";

    /***
    * @ngdoc method
    * @name setTotal
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Set total price
    *
    * @param {array} total The total price
     */
    $scope.setTotal = function(total) {
      return $scope.total = total;
    };

    /***
    * @ngdoc method
    * @name setCard
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Set card used to payment
    *
    * @param {array} card The card used to payment
     */
    $scope.setCard = function(card) {
      return $scope.card = card;
    };

    /***
    * @ngdoc method
    * @name sendSubmittingEvent
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Send submitting event
     */
    sendSubmittingEvent = (function(_this) {
      return function() {
        var payload, referrer, target_origin;
        referrer = $location.protocol() + "://" + $location.host();
        if ($location.port()) {
          referrer += ":" + $location.port();
        }
        target_origin = $scope.referrer;
        payload = JSON.stringify({
          'type': 'submitting',
          'message': referrer
        });
        return parent.postMessage(payload, target_origin);
      };
    })(this);

    /***
    * @ngdoc method
    * @name submitPaymentForm
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Submit payment form
     */
    submitPaymentForm = (function(_this) {
      return function() {
        var payment_form;
        payment_form = angular.element.find('form');
        return payment_form[0].submit();
      };
    })(this);

    /***
    * @ngdoc method
    * @name submitAndSendMessage
    * @methodOf BB.Directives:bbPayForm
    * @description
    * Submit and send message in according of event paramenter
    *
    * @param {object} event The event
     */
    return $scope.submitAndSendMessage = (function(_this) {
      return function(event) {
        var payment_form;
        event.preventDefault();
        event.stopPropagation();
        payment_form = $scope.$eval('payment_form');
        if (payment_form.$invalid) {
          payment_form.submitted = true;
          return false;
        } else {
          sendSubmittingEvent();
          return submitPaymentForm();
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPeople
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of peoples for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} items The items of the person list
  * @property {array} bookable_people The bookable people from the person list
  * @property {array} bookable_items The bookable items from the person list
  * @property {array} booking_item The booking item from the person list
   */
  angular.module('BB.Directives').directive('bbPeople', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PersonList',
      link: function(scope, element, attrs) {
        if (attrs.bbItem) {
          scope.booking_item = scope.$eval(attrs.bbItem);
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('PersonList', function($scope, $rootScope, PageControllerService, PersonService, ItemService, $q, BBModel, PersonModel, FormDataStoreService) {
    var getItemFromPerson, loadData, setPerson;
    $scope.controller = "public.controllers.PersonList";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $rootScope.connection_started.then(function() {
      return loadData();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    loadData = function() {
      var bi, ppromise;
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      bi = $scope.booking_item;
      if (!bi.service || bi.service === $scope.change_watch_item) {
        if (!bi.service) {
          $scope.setLoaded($scope);
        }
        return;
      }
      $scope.change_watch_item = bi.service;
      $scope.notLoaded($scope);
      ppromise = PersonService.query($scope.bb.company);
      ppromise.then(function(people) {
        if (bi.group) {
          people = people.filter(function(x) {
            return !x.group_id || x.group_id === bi.group;
          });
        }
        return $scope.all_people = people;
      });
      return ItemService.query({
        company: $scope.bb.company,
        cItem: bi,
        wait: ppromise,
        item: 'person'
      }).then(function(items) {
        var i, j, len, promises;
        if (bi.group) {
          items = items.filter(function(x) {
            return !x.group_id || x.group_id === bi.group;
          });
        }
        promises = [];
        for (j = 0, len = items.length; j < len; j++) {
          i = items[j];
          promises.push(i.promise);
        }
        return $q.all(promises).then((function(_this) {
          return function(res) {
            var k, len1, people;
            people = [];
            for (k = 0, len1 = items.length; k < len1; k++) {
              i = items[k];
              people.push(i.item);
              if (bi && bi.person && bi.person.self === i.item.self) {
                $scope.person = i.item;
                $scope.selected_bookable_items = [i];
              }
              if (bi && bi.selected_person && bi.selected_person.item.self === i.item.self) {
                bi.selected_person = i;
              }
            }
            if (items.length === 1 && $scope.bb.company.settings && $scope.bb.company.settings.merge_people) {
              if (!$scope.selectItem(items[0], $scope.nextRoute)) {
                setPerson(people);
                $scope.bookable_items = items;
                $scope.selected_bookable_items = items;
              } else {
                $scope.skipThisStep();
              }
            } else {
              setPerson(people);
              $scope.bookable_items = items;
              if (!$scope.selected_bookable_items) {
                $scope.selected_bookable_items = items;
              }
            }
            return $scope.setLoaded($scope);
          };
        })(this));
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };

    /***
    * @ngdoc method
    * @name setPerson
    * @methodOf BB.Directives:bbPeople
    * @description
    * Storing the person property in the form store
    *
    * @param {array} people The people
     */
    setPerson = function(people) {
      $scope.bookable_people = people;
      if ($scope.person) {
        return _.each(people, function(person) {
          if (person.id === $scope.person.id) {
            return $scope.person = person;
          }
        });
      }
    };

    /***
    * @ngdoc method
    * @name getItemFromPerson
    * @methodOf BB.Directives:bbPeople
    * @description
    * Get item from person
    *
    * @param {array} person The person
     */
    getItemFromPerson = (function(_this) {
      return function(person) {
        var item, j, len, ref;
        if (person instanceof PersonModel) {
          if ($scope.bookable_items) {
            ref = $scope.bookable_items;
            for (j = 0, len = ref.length; j < len; j++) {
              item = ref[j];
              if (item.item.self === person.self) {
                return item;
              }
            }
          }
        }
        return person;
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbPeople
    * @description
    * Select an item into the current person list in according of item and route parameters
    *
    * @param {array} item Selected item from the list of current people
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = (function(_this) {
      return function(item, route) {
        if ($scope.$parent.$has_page_control) {
          $scope.person = item;
          return false;
        } else {
          $scope.booking_item.setPerson(getItemFromPerson(item));
          $scope.decideNextPage(route);
          return true;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectAndRoute
    * @methodOf BB.Directives:bbPeople
    * @description
    * Select and route person from list in according of item and route parameters
    *
    * @param {array} item Selected item from the list of current people
    * @param {string=} route A specific route to load
     */
    $scope.selectAndRoute = (function(_this) {
      return function(item, route) {
        $scope.booking_item.setPerson(getItemFromPerson(item));
        $scope.decideNextPage(route);
        return true;
      };
    })(this);
    $scope.$watch('person', (function(_this) {
      return function(newval, oldval) {
        if ($scope.person && $scope.booking_item) {
          if (!$scope.booking_item.person || $scope.booking_item.person.self !== $scope.person.self) {
            $scope.booking_item.setPerson(getItemFromPerson($scope.person));
            return $scope.broadcastItemUpdate();
          }
        } else if (newval !== oldval) {
          $scope.booking_item.setPerson(null);
          return $scope.broadcastItemUpdate();
        }
      };
    })(this));
    $scope.$on("currentItemUpdate", function(event) {
      return loadData();
    });

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbPeople
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = (function(_this) {
      return function() {
        if ($scope.person) {
          $scope.booking_item.setPerson(getItemFromPerson($scope.person));
          return true;
        } else {
          $scope.booking_item.setPerson(null);
          return true;
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbProductList
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of product for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} products The products from the list
  * @property {array} item The item of the product list
  * @property {array} booking_item The booking item
  * @property {product} product The currectly selected product
   */
  angular.module('BB.Directives').directive('bbProductList', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'ProductList',
      link: function(scope, element, attrs) {
        if (attrs.bbItem) {
          scope.booking_item = scope.$eval(attrs.bbItem);
        }
        if (attrs.bbShowAll) {
          scope.show_all = true;
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('ProductList', function($scope, $rootScope, $q, $attrs, ItemService, FormDataStoreService, ValidatorService, PageControllerService, halClient) {
    $scope.controller = "public.controllers.ProductList";
    $scope.notLoaded($scope);
    $scope.validator = ValidatorService;
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        return $scope.init($scope.bb.company);
      }
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = function(company) {
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      return company.$get('products').then(function(products) {
        return products.$get('products').then(function(products) {
          $scope.products = products;
          return $scope.setLoaded($scope);
        });
      });
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbProductList
    * @description
    * Select an item from the product list in according of item and route parameter
    *
    * @param {array} item The array items
    * @param {string=} route A specific route to load
     */
    return $scope.selectItem = function(item, route) {
      if ($scope.$parent.$has_page_control) {
        $scope.product = item;
        return false;
      } else {
        $scope.booking_item.setProduct(item);
        $scope.decideNextPage(route);
        return true;
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbPurchaseTotal
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of purchase total for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} total The total purchase
   */
  angular.module('BB.Directives').directive('bbPurchaseTotal', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'PurchaseTotal'
    };
  });

  angular.module('BB.Controllers').controller('PurchaseTotal', function($scope, $rootScope, $window, PurchaseTotalService, $q) {
    $scope.controller = "public.controllers.PurchaseTotal";
    angular.extend(this, new $window.PageController($scope, $q));

    /***
    * @ngdoc method
    * @name load
    * @methodOf BB.Directives:bbPurchaseTotal
    * @description
    * Load the total purchase by id
    *
    * @param {integer} total_id The total id of the total purchase
     */
    return $scope.load = (function(_this) {
      return function(total_id) {
        return $rootScope.connection_started.then(function() {
          $scope.loadingTotal = PurchaseTotalService.query({
            company: $scope.bb.company,
            total_id: total_id
          });
          return $scope.loadingTotal.then(function(total) {
            return $scope.total = total;
          });
        });
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbResources
  * @restrict AE
  * @scope true
  *
  * @description
  * Loads a list of resources for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbResources   A hash of options
  * @property {array} items An array of all resources
  * @property {array} bookable_items An array of all BookableItems - used if the current_item has already selected a services or person
  * @property {array} bookable_resources An array of Resources - used if the current_item has already selected a services or person
  * @property {resource} resource The currectly selected resource
   */
  angular.module('BB.Directives').directive('bbResources', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'ResourceList'
    };
  });

  angular.module('BB.Controllers').controller('ResourceList', function($scope, $rootScope, $attrs, PageControllerService, ResourceService, ItemService, $q, BBModel, ResourceModel) {
    var getItemFromResource, loadData;
    $scope.controller = "public.controllers.ResourceList";
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $scope.options = $scope.$eval($attrs.bbResources) || {};
    $rootScope.connection_started.then((function(_this) {
      return function() {
        return loadData();
      };
    })(this));
    loadData = (function(_this) {
      return function() {
        var params, rpromise;
        if (!(($scope.bb.steps && $scope.bb.steps[0].page === "resource_list") || $scope.options.resource_first)) {
          if (!$scope.bb.current_item.service || $scope.bb.current_item.service === $scope.change_watch_item) {
            if (!$scope.bb.current_item.service) {
              $scope.setLoaded($scope);
            }
            return;
          }
        }
        $scope.change_watch_item = $scope.bb.current_item.service;
        $scope.notLoaded($scope);
        rpromise = ResourceService.query($scope.bb.company);
        rpromise.then(function(resources) {
          if ($scope.bb.current_item.group) {
            resources = resources.filter(function(x) {
              return !x.group_id || x.group_id === $scope.bb.current_item.group;
            });
          }
          return $scope.all_resources = resources;
        });
        params = {
          company: $scope.bb.company,
          cItem: $scope.bb.current_item,
          wait: rpromise,
          item: 'resource'
        };
        return ItemService.query(params).then(function(items) {
          var i, j, len, promises;
          promises = [];
          if ($scope.bb.current_item.group) {
            items = items.filter(function(x) {
              return !x.group_id || x.group_id === $scope.bb.current_item.group;
            });
          }
          for (j = 0, len = items.length; j < len; j++) {
            i = items[j];
            promises.push(i.promise);
          }
          return $q.all(promises).then(function(res) {
            var k, len1, resources;
            resources = [];
            for (k = 0, len1 = items.length; k < len1; k++) {
              i = items[k];
              resources.push(i.item);
              if ($scope.bb.current_item && $scope.bb.current_item.resource && $scope.bb.current_item.resource.self === i.item.self) {
                $scope.resource = i.item;
              }
            }
            if (resources.length === 1 && !$scope.options.allow_single_pick) {
              if (!$scope.selectItem(items[0].item, $scope.nextRoute, {
                skip_step: true
              })) {
                $scope.bookable_resources = resources;
                $scope.bookable_items = items;
              }
            } else {
              $scope.bookable_resources = resources;
              $scope.bookable_items = items;
            }
            return $scope.setLoaded($scope);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        }, function(err) {
          if (!(err === "No service link found" && (($scope.bb.steps && $scope.bb.steps[0].page === 'resource_list') || $scope.options.resource_first))) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          } else {
            return $scope.setLoaded($scope);
          }
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name getItemFromResource
    * @methodOf BB.Directives:bbResources
    * @description
    * Get item from resource in according of resource parameter
    *
    * @param {object} resource The resource
     */
    getItemFromResource = (function(_this) {
      return function(resource) {
        var item, j, len, ref;
        if (resource instanceof ResourceModel) {
          if ($scope.bookable_items) {
            ref = $scope.bookable_items;
            for (j = 0, len = ref.length; j < len; j++) {
              item = ref[j];
              if (item.item.self === resource.self) {
                return item;
              }
            }
          }
        }
        return resource;
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbResources
    * @description
    * Select an item into the current booking journey and route on to the next page dpending on the current page control
    *
    * @param {array} item The Service or BookableItem to select
    * @param {string=} route A specific route to load
    * @param {string=} skip_step The skip_step has been set to false
     */
    $scope.selectItem = (function(_this) {
      return function(item, route, options) {
        if (options == null) {
          options = {};
        }
        if ($scope.$parent.$has_page_control) {
          $scope.resource = item;
          return false;
        } else {
          $scope.bb.current_item.setResource(getItemFromResource(item));
          if (options.skip_step) {
            $scope.skipThisStep();
          }
          $scope.decideNextPage(route);
          return true;
        }
      };
    })(this);
    $scope.$watch('resource', (function(_this) {
      return function(newval, oldval) {
        if ($scope.resource) {
          $scope.bb.current_item.setResource(getItemFromResource($scope.resource));
          return $scope.broadcastItemUpdate();
        } else if (newval !== oldval) {
          $scope.bb.current_item.setResource(null);
          return $scope.broadcastItemUpdate();
        }
      };
    })(this));
    $scope.$on("currentItemUpdate", function(event) {
      return loadData();

      /***
      * @ngdoc method
      * @name setReady
      * @methodOf BB.Directives:bbResources
      * @description
      * Set this page section as ready
       */
    });
    return $scope.setReady = (function(_this) {
      return function() {
        if ($scope.resource) {
          $scope.bb.current_item.setResource(getItemFromResource($scope.resource));
          return true;
        } else {
          $scope.bb.current_item.setResource(null);
          return true;
        }
      };
    })(this);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbServices
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of services for the currently in scroe company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbServices   A hash of options
  * @property {array} items An array of all services
  * @property {array} filtered_items A filtered list according to a filter setting
  * @property {array} bookable_items An array of all BookableItems - used if the current_item has already selected a resource or person
  * @property {array} bookable_services An array of Services - used if the current_item has already selected a resource or person
  * @property {service} service The currectly selected service
  * @property {hash} filters A hash of filters
  * @example
  *  <example module="BB"> 
  *    <file name="index.html">
  *   <div bb-api-url='https://uk.bookingbug.com'>
  *   <div  bb-widget='{company_id:21}'>
  *     <div bb-services>
  *        <ul>
  *          <li ng-repeat='service in items'> {{service.name}}</li>
  *        </ul>
  *     </div>
  *     </div>
  *     </div>
  *   </file> 
  *  </example>
  *
   */
  angular.module('BB.Directives').directive('bbServices', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'ServiceList'
    };
  });

  angular.module('BB.Controllers').controller('ServiceList', function($scope, $rootScope, $q, $attrs, $modal, $sce, ItemService, FormDataStoreService, ValidatorService, PageControllerService, halClient, AlertService, ErrorService, $filter, CategoryService) {
    var setServiceItem;
    $scope.controller = "public.controllers.ServiceList";
    FormDataStoreService.init('ServiceList', $scope, ['service']);
    $scope.notLoaded($scope);
    angular.extend(this, new PageControllerService($scope, $q));
    $scope.validator = ValidatorService;
    $scope.filters = {
      category_name: null,
      service_name: null,
      price: {
        min: 0,
        max: 100
      },
      custom_array_value: null
    };
    $scope.show_custom_array = false;
    $scope.options = $scope.$eval($attrs.bbServices) || {};
    if ($attrs.bbItem) {
      $scope.booking_item = $scope.$eval($attrs.bbItem);
    }
    if ($attrs.bbShowAll || $scope.options.show_all) {
      $scope.show_all = true;
    }
    if ($scope.options.allow_single_pick) {
      $scope.allowSinglePick = true;
    }
    if ($scope.options.hide_disabled) {
      $scope.hide_disabled = true;
    }
    $scope.price_options = {
      min: 0,
      max: 100
    };
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.company) {
          return $scope.init($scope.bb.company);
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = function(comp) {
      var ppromise;
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      if ($scope.bb.company.$has('named_categories')) {
        CategoryService.query($scope.bb.company).then((function(_this) {
          return function(items) {
            return $scope.all_categories = items;
          };
        })(this), function(err) {
          return $scope.all_categories = [];
        });
      } else {
        $scope.all_categories = [];
      }
      if ($scope.service && $scope.service.company_id !== $scope.bb.company.id) {
        $scope.service = null;
      }
      ppromise = comp.getServicesPromise();
      ppromise.then((function(_this) {
        return function(items) {
          var filterItems, item, j, k, len, len1;
          if ($scope.hide_disabled) {
            items = items.filter(function(x) {
              return !x.disabled && !x.deleted;
            });
          }
          filterItems = $attrs.filterServices === 'false' ? false : true;
          if (filterItems) {
            if ($scope.booking_item.service_ref && !$scope.show_all) {
              items = items.filter(function(x) {
                return x.api_ref === $scope.booking_item.service_ref;
              });
            } else if ($scope.booking_item.category && !$scope.show_all) {
              items = items.filter(function(x) {
                return x.$has('category') && x.$href('category') === $scope.booking_item.category.self;
              });
            }
          }
          if (!$scope.options.show_event_groups) {
            items = items.filter(function(x) {
              return !x.is_event_group;
            });
          }
          if (items.length === 1 && !$scope.allowSinglePick) {
            if (!$scope.selectItem(items[0], $scope.nextRoute, {
              skip_step: true
            })) {
              setServiceItem(items);
            }
          } else {
            setServiceItem(items);
          }
          if ($scope.booking_item.defaultService()) {
            for (j = 0, len = items.length; j < len; j++) {
              item = items[j];
              if (item.self === $scope.booking_item.defaultService().self || (item.name === $scope.booking_item.defaultService().name && !item.deleted)) {
                $scope.selectItem(item, $scope.nextRoute, {
                  skip_step: true
                });
              }
            }
          }
          if ($scope.booking_item.service) {
            for (k = 0, len1 = items.length; k < len1; k++) {
              item = items[k];
              item.selected = false;
              if (item.self === $scope.booking_item.service.self) {
                $scope.service = item;
                item.selected = true;
                $scope.booking_item.setService($scope.service);
              }
            }
          }
          $scope.setLoaded($scope);
          if ($scope.booking_item.service || !(($scope.booking_item.person && !$scope.booking_item.anyPerson()) || ($scope.booking_item.resource && !$scope.booking_item.anyResource()))) {
            return $scope.bookable_services = $scope.items;
          }
        };
      })(this), function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
      if (($scope.booking_item.person && !$scope.booking_item.anyPerson()) || ($scope.booking_item.resource && !$scope.booking_item.anyResource())) {
        return ItemService.query({
          company: $scope.bb.company,
          cItem: $scope.booking_item,
          wait: ppromise,
          item: 'service'
        }).then((function(_this) {
          return function(items) {
            var i, item, j, len, services;
            if ($scope.booking_item.service_ref) {
              items = items.filter(function(x) {
                return x.api_ref === $scope.booking_item.service_ref;
              });
            }
            if ($scope.booking_item.group) {
              items = items.filter(function(x) {
                return !x.group_id || x.group_id === $scope.booking_item.group;
              });
            }
            if ($scope.hide_disabled) {
              items = items.filter(function(x) {
                return (x.item == null) || (!x.item.disabled && !x.item.deleted);
              });
            }
            services = (function() {
              var j, len, results;
              results = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                if (i.item != null) {
                  results.push(i.item);
                }
              }
              return results;
            })();
            for (j = 0, len = services.length; j < len; j++) {
              item = services[j];
              if (item.listed_durations && item.listed_durations.length === 1) {
                item.display_name = item.name + ' - ' + $filter('time_period')(item.duration);
              } else {
                item.display_name = item.name;
              }
            }
            $scope.bookable_services = services;
            $scope.bookable_items = items;
            if (services.length === 1 && !$scope.allowSinglePick) {
              if (!$scope.selectItem(services[0], $scope.nextRoute, {
                skip_step: true
              })) {
                setServiceItem(services);
              }
            } else {
              setServiceItem(services);
            }
            return $scope.setLoaded($scope);
          };
        })(this), function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
    };
    setServiceItem = function(items) {
      $scope.items = items;
      $scope.filtered_items = $scope.items;
      if ($scope.service) {
        return _.each(items, function(item) {
          if (item.id === $scope.service.id) {
            return $scope.service = item;
          }
        });
      }
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbServices
    * @description
    * Select an item into the current booking journey and route on to the next page dpending on the current page control
    *
    * @param {object} item The Service or BookableItem to select
    * @param {string=} route A specific route to load
     */
    $scope.selectItem = (function(_this) {
      return function(item, route, options) {
        if (options == null) {
          options = {};
        }
        if ($scope.routed) {
          return true;
        }
        if ($scope.$parent.$has_page_control) {
          $scope.service = item;
          return false;
        } else if (item.is_event_group) {
          $scope.booking_item.setEventGroup(item);
          if (options.skip_step) {
            $scope.skipThisStep();
          }
          $scope.decideNextPage(route);
          return $scope.routed = true;
        } else {
          $scope.booking_item.setService(item);
          if (options.skip_step) {
            $scope.skipThisStep();
          }
          $scope.decideNextPage(route);
          $scope.routed = true;
          return true;
        }
      };
    })(this);
    $scope.$watch('service', (function(_this) {
      return function(newval, oldval) {
        if ($scope.service && $scope.booking_item) {
          if (!$scope.booking_item.service || $scope.booking_item.service.self !== $scope.service.self) {
            $scope.booking_item.setService($scope.service);
            return $scope.broadcastItemUpdate();
          }
        }
      };
    })(this));

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbServices
    * @description
    * Set this page section as ready - see {@link BB.Directives:bbPage Page Control}
     */
    $scope.setReady = (function(_this) {
      return function() {
        if ($scope.service) {
          $scope.booking_item.setService($scope.service);
          return true;
        } else if ($scope.bb.stacked_items && $scope.bb.stacked_items.length > 0) {
          return true;
        } else {
          return false;
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name errorModal
    * @methodOf BB.Directives:bbServices
    * @description
    * Display error message in modal
     */
    $scope.errorModal = function() {
      var error_modal;
      return error_modal = $modal.open({
        templateUrl: $scope.getPartial('_error_modal'),
        controller: function($scope, $modalInstance) {
          $scope.message = ErrorService.getError('GENERIC').msg;
          return $scope.ok = function() {
            return $modalInstance.close();
          };
        }
      });
    };

    /***
    * @ngdoc method
    * @name filterFunction
    * @methodOf BB.Directives:bbServices
    * @description
    * Filter service
     */
    $scope.filterFunction = function(service) {
      if (!service) {
        return false;
      }
      $scope.service_array = [];
      $scope.custom_array = function(match) {
        var item, j, len, ref;
        if (!match) {
          return false;
        }
        if ($scope.options.custom_filter) {
          match = match.toLowerCase();
          ref = service.extra[$scope.options.custom_filter];
          for (j = 0, len = ref.length; j < len; j++) {
            item = ref[j];
            item = item.toLowerCase();
            if (item === match) {
              $scope.show_custom_array = true;
              return true;
            }
          }
          return false;
        }
      };
      $scope.service_name_include = function(match) {
        var item;
        if (!match) {
          return false;
        }
        if (match) {
          match = match.toLowerCase();
          item = service.name.toLowerCase();
          if (item.includes(match)) {
            return true;
          } else {
            return false;
          }
        }
      };
      return (!$scope.filters.category_name || service.category_id === $scope.filters.category_name.id) && (!$scope.filters.service_name || $scope.service_name_include($scope.filters.service_name)) && (!$scope.filters.custom_array_value || $scope.custom_array($scope.filters.custom_array_value)) && (!service.price || (service.price >= $scope.filters.price.min * 100 && service.price <= $scope.filters.price.max * 100));
    };

    /***
    * @ngdoc method
    * @name resetFilters
    * @methodOf BB.Directives:bbServices
    * @description
    * Clear the filters
     */
    $scope.resetFilters = function() {
      if ($scope.options.clear_results) {
        $scope.show_custom_array = false;
      }
      $scope.filters.category_name = null;
      $scope.filters.service_name = null;
      $scope.filters.price.min = 0;
      $scope.filters.price.max = 100;
      $scope.filters.custom_array_value = null;
      return $scope.filterChanged();
    };

    /***
    * @ngdoc method
    * @name filterChanged
    * @methodOf BB.Directives:bbServices
    * @description
    * Filter changed
     */
    return $scope.filterChanged = function() {
      return $scope.filtered_items = $filter('filter')($scope.items, $scope.filterFunction);
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbTimeSlots
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of time slots for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} booking_item The booking item 
  * @property {date} start_date The start date
  * @property {date} end_date The end date
  * @property {array} slots The slots
  * @property {object} validator The validator service - see {@link BB.Services:Validator validator Service}
  *
   */
  angular.module('BB.Directives').directive('bbTimeSlots', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'TimeSlots',
      link: function(scope, element, attrs) {
        if (attrs.bbItem) {
          scope.booking_item = scope.$eval(attrs.bbItem);
        }
        if (attrs.bbShowAll) {
          scope.show_all = true;
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('TimeSlots', function($scope, $rootScope, $q, $attrs, SlotService, FormDataStoreService, ValidatorService, PageControllerService, halClient, BBModel) {
    var setItem;
    $scope.controller = "public.controllers.SlotList";
    $scope.notLoaded($scope);
    $rootScope.connection_started.then(function() {
      if ($scope.bb.company) {
        return $scope.init($scope.bb.company);
      }
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = function(company) {
      $scope.booking_item || ($scope.booking_item = $scope.bb.current_item);
      $scope.start_date = moment();
      $scope.end_date = moment().add(1, 'month');
      return SlotService.query($scope.bb.company, {
        item: $scope.booking_item,
        start_date: $scope.start_date.toISODate(),
        end_date: $scope.end_date.toISODate()
      }).then(function(slots) {
        $scope.slots = slots;
        return $scope.setLoaded($scope);
      }, function(err) {
        return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
      });
    };
    setItem = function(slot) {
      return $scope.booking_item.setSlot(slot);
    };

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbTimeSlots
    * @description
    * Select an item into the current booking journey and route on to the next page dpending on the current page control
    *
    * @param {object} slot The slot from list
    * @param {string=} route A specific route to load
     */
    return $scope.selectItem = function(slot, route) {
      if ($scope.$parent.$has_page_control) {
        setItem(slot);
        return false;
      } else {
        setItem(slot);
        $scope.decideNextPage(route);
        return true;
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbSpaces
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of spaces for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @property {array} items An array of all services
  * @property {space} space The currectly selected space
   */
  angular.module('BB.Directives').directive('bbSpaces', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'SpaceList'
    };
  });

  angular.module('BB.Controllers').controller('SpaceList', function($scope, $rootScope, ServiceService, SpaceService, $q) {
    $scope.controller = "public.controllers.SpaceList";
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.company) {
          return $scope.init($scope.bb.company);
        }
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    $scope.init = (function(_this) {
      return function(comp) {
        return SpaceService.query(comp).then(function(items) {
          if ($scope.currentItem.category) {
            items = items.filter(function(x) {
              return x.$has('category') && x.$href('category') === $scope.currentItem.category.self;
            });
          }
          $scope.items = items;
          if (items.length === 1 && !$scope.allowSinglePick) {
            $scope.skipThisStep();
            $rootScope.services = items;
            return $scope.selectItem(items[0], $scope.nextRoute);
          } else {
            return $scope.listLoaded = true;
          }
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectItem
    * @methodOf BB.Directives:bbSpaces
    * @description
    * Select the current item in according of item and route parameters
    *
    * @param {array} item The Space or BookableItem to select
    * @param {string=} route A specific route to load
     */
    return $scope.selectItem = (function(_this) {
      return function(item, route) {
        $scope.currentItem.setService(item);
        return $scope.decide_next_page(route);
      };
    })(this);
  });

}).call(this);


/***
* @ngdoc directive
* @name BB.Directives:bbSummary
* @restrict AE
* @scope true
*
* @description
* Loads a summary of the booking
*
*
 */

(function() {
  angular.module('BB.Directives').directive('bbSummary', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Summary'
    };
  });

  angular.module('BB.Controllers').controller('Summary', function($scope, $rootScope, ClientService, $q) {
    $scope.controller = "public.controllers.Summary";
    $rootScope.connection_started.then((function(_this) {
      return function() {
        $scope.item = $scope.bb.current_item;
        return $scope.items = $scope.bb.basket.timeItems();
      };
    })(this));

    /***
    * @ngdoc method
    * @name confirm
    * @methodOf BB.Directives:bbSummary
    * @description
    * Submits the client and BasketItem to the API
     */
    return $scope.confirm = (function(_this) {
      return function() {
        var promises;
        $scope.notLoaded($scope);
        promises = [ClientService.create_or_update($scope.bb.company, $scope.client)];
        if ($scope.bb.current_item.service) {
          promises.push($scope.addItemToBasket());
        }
        return $q.all(promises).then(function(result) {
          var client;
          client = result[0];
          $scope.setClient(client);
          if (client.waitingQuestions) {
            client.gotQuestions.then(function() {
              return $scope.client_details = client.client_details;
            });
          }
          $scope.setLoaded($scope);
          return $scope.decideNextPage();
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);
  });

}).call(this);


/***
* @ngdoc directive
* @name BB.Directives:bbSurveyQuestions
* @restrict AE
* @scope true
*
* @description
*
* Loads a list of survey questions for the currently in scope company
*
* <pre>
* restrict: 'AE'
* replace: true
* scope: true
* </pre>
*
* @property {integer} company_id The company id
* @property {array} questions An array with questions
* @property {object} validator The validator service - see {@link BB.Services:Validator Validator Service}
* @property {object} widget The widget service - see {@link BB.Models:BBWidget Widget Service}
* @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
 */

(function() {
  angular.module('BB.Directives').directive('bbSurveyQuestions', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'SurveyQuestions'
    };
  });

  angular.module('BB.Controllers').controller('SurveyQuestions', function($scope, $rootScope, CompanyService, PurchaseService, ClientService, $modal, $location, $timeout, BBWidget, BBModel, $q, QueryStringService, SSOService, AlertService, LoginService, $window, $upload, ServiceService, ValidatorService, PurchaseBookingService, $sessionStorage) {
    var getBookingAndSurvey, getBookingRef, getMember, getPurchaseID, init, setPurchaseCompany, showLoginError;
    $scope.controller = "SurveyQuestions";
    $scope.completed = false;
    $scope.login = {
      email: "",
      password: ""
    };
    $scope.login_error = false;
    $scope.booking_ref = "";
    $scope.notLoaded($scope);
    $rootScope.connection_started.then(function() {
      return init();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });
    init = (function(_this) {
      return function() {
        if ($scope.company) {
          if ($scope.company.settings.requires_login) {
            $scope.checkIfLoggedIn();
            if ($rootScope.member) {
              return getBookingAndSurvey();
            } else {

            }
          } else {
            return getBookingAndSurvey();
          }
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name checkIfLoggedIn
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Check if logged in
     */
    $scope.checkIfLoggedIn = (function(_this) {
      return function() {
        return LoginService.checkLogin();
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadSurvey
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Load Survey in according of purchase parameter
    *
    * @param {array} purchase The purchase
     */
    $scope.loadSurvey = (function(_this) {
      return function(purchase) {
        if (!$scope.company) {
          $scope.purchase.$get('company').then(function(company) {
            return setPurchaseCompany(company);
          });
        }
        if ($scope.purchase.$has('client')) {
          $scope.purchase.$get('client').then(function(client) {
            return $scope.setClient(new BBModel.Client(client));
          });
        }
        return $scope.purchase.getBookingsPromise().then(function(bookings) {
          var address, booking, i, len, params, pretty_address, ref, results;
          params = {};
          $scope.bookings = bookings;
          ref = $scope.bookings;
          results = [];
          for (i = 0, len = ref.length; i < len; i++) {
            booking = ref[i];
            if (booking.datetime) {
              booking.pretty_date = moment(booking.datetime).format("dddd, MMMM Do YYYY");
            }
            if (booking.address) {
              address = new BBModel.Address(booking.address);
              pretty_address = address.addressSingleLine();
              booking.pretty_address = pretty_address;
            }
            if ($rootScope.user) {
              params.admin_only = true;
            }
            results.push(booking.$get("survey_questions", params).then(function(details) {
              var item_details;
              item_details = new BBModel.ItemDetails(details);
              booking.survey_questions = item_details.survey_questions;
              return booking.getSurveyAnswersPromise().then(function(answers) {
                var answer, j, k, len1, len2, question, ref1, ref2;
                booking.survey_answers = answers;
                ref1 = booking.survey_questions;
                for (j = 0, len1 = ref1.length; j < len1; j++) {
                  question = ref1[j];
                  if (booking.survey_answers) {
                    ref2 = booking.survey_answers;
                    for (k = 0, len2 = ref2.length; k < len2; k++) {
                      answer = ref2[k];
                      if (answer.question_text === question.name && answer.value) {
                        question.answer = answer.value;
                      }
                    }
                  }
                }
                return $scope.setLoaded($scope);
              });
            }));
          }
          return results;
        }, function(err) {
          $scope.setLoaded($scope);
          return failMsg();
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name submitSurveyLogin
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Submit survey login in according of form parameter else display an error message
    *
    * @param {object} form The survey login form
     */
    $scope.submitSurveyLogin = (function(_this) {
      return function(form) {
        if (!ValidatorService.validateForm(form)) {
          return;
        }
        return LoginService.companyLogin($scope.company, {}, {
          email: $scope.login.email,
          password: $scope.login.password,
          id: $scope.company.id
        }).then(function(member) {
          LoginService.setLogin(member);
          return getBookingAndSurvey();
        }, function(err) {
          showLoginError();
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadSurveyFromPurchaseID
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Load survey from purchase id in according of id parameter else display an error message
    *
    * @param {object} id The id of purchase
     */
    $scope.loadSurveyFromPurchaseID = (function(_this) {
      return function(id) {
        var auth_token, params;
        params = {
          purchase_id: id,
          url_root: $scope.bb.api_url
        };
        auth_token = $sessionStorage.getItem('auth_token');
        if (auth_token) {
          params.auth_token = auth_token;
        }
        return PurchaseService.query(params).then(function(purchase) {
          $scope.purchase = purchase;
          $scope.total = $scope.purchase;
          return $scope.loadSurvey($scope.purchase);
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadSurveyFromBookingRef
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Load survey from booking ref in according of id else display an error message
    *
    * @param {object} id The id of booking
     */
    $scope.loadSurveyFromBookingRef = (function(_this) {
      return function(id) {
        var auth_token, params;
        params = {
          booking_ref: id,
          url_root: $scope.bb.api_url,
          raw: true
        };
        auth_token = $sessionStorage.getItem('auth_token');
        if (auth_token) {
          params.auth_token = auth_token;
        }
        return PurchaseService.bookingRefQuery(params).then(function(purchase) {
          $scope.purchase = purchase;
          $scope.total = $scope.purchase;
          return $scope.loadSurvey($scope.purchase);
        }, function(err) {
          showLoginError();
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name submitSurvey
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Submit survey in according of form parameter
    *
    * @param {object} form The survey form
     */
    $scope.submitSurvey = (function(_this) {
      return function(form) {
        var booking, i, len, params, ref, results;
        if (!ValidatorService.validateForm(form)) {
          return;
        }
        ref = $scope.bookings;
        results = [];
        for (i = 0, len = ref.length; i < len; i++) {
          booking = ref[i];
          booking.checkReady();
          if (booking.ready) {
            $scope.notLoaded($scope);
            booking.client_id = $scope.client.id;
            params = booking;
            results.push(PurchaseBookingService.addSurveyAnswersToBooking(params).then(function(booking) {
              $scope.setLoaded($scope);
              return $scope.completed = true;
            }, function(err) {
              return $scope.setLoaded($scope);
            }));
          } else {
            results.push($scope.decideNextPage(route));
          }
        }
        return results;
      };
    })(this);

    /***
    * @ngdoc method
    * @name submitBookingRef
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Submit booking in according of form parameter
    *
    * @param {object} form The submit booking form
     */
    $scope.submitBookingRef = (function(_this) {
      return function(form) {
        var auth_token, params;
        if (!ValidatorService.validateForm(form)) {
          return;
        }
        $scope.notLoaded($scope);
        params = {
          booking_ref: $scope.booking_ref,
          url_root: $scope.bb.api_url,
          raw: true
        };
        auth_token = $sessionStorage.getItem('auth_token');
        if (auth_token) {
          params.auth_token = auth_token;
        }
        return PurchaseService.bookingRefQuery(params).then(function(purchase) {
          $scope.purchase = purchase;
          $scope.total = $scope.purchase;
          return $scope.loadSurvey($scope.purchase);
        }, function(err) {
          showLoginError();
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name storeBookingCookie
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Store booking cookie
     */
    $scope.storeBookingCookie = function() {
      return document.cookie = "bookingrefsc=" + $scope.booking_ref;
    };

    /***
    * @ngdoc method
    * @name showLoginError
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Show login error
     */
    showLoginError = (function(_this) {
      return function() {
        return $scope.login_error = true;
      };
    })(this);

    /***
    * @ngdoc method
    * @name getMember
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Get member
     */
    getMember = (function(_this) {
      return function() {
        var params;
        params = {
          member_id: $scope.member_id,
          company_id: $scope.company_id
        };
        return LoginService.memberQuery(params).then(function(member) {
          return $scope.member = member;
        });
      };
    })(this);

    /***
    * @ngdoc method
    * @name setPurchaseCompany
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Set purchase company in according of company parameter
    *
    * @param {object} company The company
     */
    setPurchaseCompany = function(company) {
      $scope.bb.company_id = company.id;
      $scope.bb.company = new BBModel.Company(company);
      $scope.company = $scope.bb.company;
      $scope.bb.item_defaults.company = $scope.bb.company;
      if (company.settings) {
        if (company.settings.merge_resources) {
          $scope.bb.item_defaults.merge_resources = true;
        }
        if (company.settings.merge_people) {
          return $scope.bb.item_defaults.merge_people = true;
        }
      }
    };

    /***
    * @ngdoc method
    * @name getBookingRef
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Get booking references
     */
    getBookingRef = function() {
      var booking_ref, matches;
      matches = /^.*(?:\?|&)booking_ref=(.*?)(?:&|$)/.exec($location.absUrl());
      if (matches) {
        booking_ref = matches[1];
      }
      return booking_ref;
    };

    /***
    * @ngdoc method
    * @name getPurchaseID
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Get purchase Id
     */
    getPurchaseID = function() {
      var matches, purchase_id;
      matches = /^.*(?:\?|&)id=(.*?)(?:&|$)/.exec($location.absUrl());
      if (matches) {
        purchase_id = matches[1];
      }
      return purchase_id;
    };

    /***
    * @ngdoc method
    * @name getBookingAndSurvey
    * @methodOf BB.Directives:bbSurveyQuestions
    * @description
    * Get booking and survey
     */
    return getBookingAndSurvey = function() {
      var id;
      id = getBookingRef();
      if (id) {
        return $scope.loadSurveyFromBookingRef(id);
      } else {
        id = getPurchaseID();
        if (id) {
          return $scope.loadSurveyFromPurchaseID(id);
        } else {
          if ($scope.bb.total) {
            return $scope.loadSurveyFromPurchaseID($scope.bb.total.long_id);
          } else {

          }
        }
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbTimes
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of times for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbTimes A hash of options
  * @property {array} selected_day The selected day
  * @property {date} selected_date The selected date
  * @property {array} data_source The data source
  * @property {array} item_link_source The item link source
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbTimes', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'TimeList'
    };
  });

  angular.module('BB.Controllers').controller('TimeList', function($attrs, $element, $scope, $rootScope, $q, TimeService, AlertService, BBModel) {
    $scope.controller = "public.controllers.TimeList";
    $scope.notLoaded($scope);
    if (!$scope.data_source) {
      $scope.data_source = $scope.bb.current_item;
    }
    $scope.options = $scope.$eval($attrs.bbTimes) || {};
    $rootScope.connection_started.then((function(_this) {
      return function() {
        if ($scope.bb.current_item.requested_date) {
          $scope.setDate($scope.bb.current_item.requested_date);
          $scope.bb.current_item.setDate($scope.selected_day);
        }
        return $scope.loadDay();
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name setDate
    * @methodOf BB.Directives:bbTimes
    * @description
    * Set a date of time list
    *
    * @param {date} date The date of time list
     */
    $scope.setDate = (function(_this) {
      return function(date) {
        var day;
        day = new BBModel.Day({
          date: date,
          spaces: 1
        });
        return $scope.setDay(day);
      };
    })(this);

    /***
    * @ngdoc method
    * @name setDay
    * @methodOf BB.Directives:bbTimes
    * @description
    * Set based on a day model
    *
    * @param {object} dayItem The dayItem
     */
    $scope.setDay = (function(_this) {
      return function(dayItem) {
        $scope.selected_day = dayItem;
        return $scope.selected_date = dayItem.date;
      };
    })(this);

    /***
    * @ngdoc method
    * @name setDataSource
    * @methodOf BB.Directives:bbTimes
    * @description
    * Set data source model of time list
    *
    * @param {object} source The source
     */
    $scope.setDataSource = (function(_this) {
      return function(source) {
        return $scope.data_source = source;
      };
    })(this);

    /***
    * @ngdoc method
    * @name setItemLinkSource
    * @methodOf BB.Directives:bbTimes
    * @description
    * Set item link source model
    *
    * @param {object} source The source
     */
    $scope.setItemLinkSource = (function(_this) {
      return function(source) {
        return $scope.item_link_source = source;
      };
    })(this);
    $scope.$on('dateChanged', (function(_this) {
      return function(event, newdate) {
        $scope.setDate(newdate);
        return $scope.loadDay();
      };
    })(this));
    $scope.$on("currentItemUpdate", function(event) {
      return $scope.loadDay();
    });

    /***
    * @ngdoc method
    * @name format_date
    * @methodOf BB.Directives:bbTimes
    * @description
    * Format data source date of the time list
    *
    * @param {date} fmt The format data
     */
    $scope.format_date = (function(_this) {
      return function(fmt) {
        if ($scope.data_source.date) {
          return $scope.data_source.date.date.format(fmt);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name selectSlot
    * @methodOf BB.Directives:bbTimes
    * @description
    * Select the slot from time list in according of slot and route parameters
    *
    * @param {date} slot The slot
    * @param {string=} A specific route to load
     */
    $scope.selectSlot = (function(_this) {
      return function(slot, route) {
        if (slot && slot.availability() > 0) {
          if ($scope.item_link_source) {
            $scope.data_source.setItem($scope.item_link_source);
          }
          if ($scope.selected_day) {
            $scope.setLastSelectedDate($scope.selected_day.date);
            $scope.data_source.setDate($scope.selected_day);
          }
          $scope.data_source.setTime(slot);
          if ($scope.$parent.$has_page_control) {

          } else {
            if ($scope.data_source.ready) {
              return $scope.addItemToBasket().then(function() {
                return $scope.decideNextPage(route);
              });
            } else {
              return $scope.decideNextPage(route);
            }
          }
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name highlightSlot
    * @methodOf BB.Directives:bbTimes
    * @description
    * The highlight slot from time list 
    *
    * @param {date} slot The slot
     */
    $scope.highlightSlot = (function(_this) {
      return function(slot) {
        if (slot && slot.availability() > 0) {
          if ($scope.selected_day) {
            $scope.setLastSelectedDate($scope.selected_day.date);
            $scope.data_source.setDate($scope.selected_day);
          }
          $scope.data_source.setTime(slot);
          return $scope.$broadcast('slotChanged');
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name status
    * @methodOf BB.Directives:bbTimes
    * @description
    * Check the status of the slot to see if it has been selected
    *
    * @param {date} slot The slot
     */
    $scope.status = function(slot) {
      var status;
      if (!slot) {
        return;
      }
      status = slot.status();
      return status;
    };

    /***
    * @ngdoc method
    * @name add
    * @methodOf BB.Directives:bbTimes
    * @description
    * Add unit of time to the selected day
    *
    * @param {date} type The type
    * @param {date} amount The amount
     */
    $scope.add = (function(_this) {
      return function(type, amount) {
        var newdate;
        newdate = moment($scope.data_source.date.date).add(amount, type);
        $scope.data_source.setDate(new BBModel.Day({
          date: newdate.format(),
          spaces: 0
        }));
        $scope.setLastSelectedDate(newdate);
        $scope.loadDay();
        return $scope.$broadcast('dateChanged', newdate);
      };
    })(this);

    /***
    * @ngdoc method
    * @name subtract
    * @methodOf BB.Directives:bbTimes
    * @description
    * Subtract unit of time to the selected day
    *
    * @param {date} type The type
    * @param {date} amount The amount
     */
    $scope.subtract = (function(_this) {
      return function(type, amount) {
        return $scope.add(type, -amount);
      };
    })(this);

    /***
    * @ngdoc method
    * @name loadDay
    * @methodOf BB.Directives:bbTimes
    * @description
    * Load day
     */
    $scope.loadDay = (function(_this) {
      return function() {
        var pslots;
        if ($scope.data_source && $scope.data_source.days_link || $scope.item_link_source) {
          if (!$scope.selected_date && $scope.data_source && $scope.data_source.date) {
            $scope.selected_date = $scope.data_source.date.date;
          }
          if (!$scope.selected_date) {
            $scope.setLoaded($scope);
            return;
          }
          $scope.notLoaded($scope);
          pslots = TimeService.query({
            company: $scope.bb.company,
            cItem: $scope.data_source,
            item_link: $scope.item_link_source,
            date: $scope.selected_date,
            client: $scope.client,
            available: 1
          });
          pslots["finally"](function() {
            return $scope.setLoaded($scope);
          });
          return pslots.then(function(data) {
            var dtimes, found_time, i, j, k, len, len1, len2, pad, ref, s, t, v;
            $scope.slots = data;
            $scope.$broadcast('slotsUpdated');
            if ($scope.add_padding && data.length > 0) {
              dtimes = {};
              for (i = 0, len = data.length; i < len; i++) {
                s = data[i];
                dtimes[s.time] = 1;
              }
              ref = $scope.add_padding;
              for (v = j = 0, len1 = ref.length; j < len1; v = ++j) {
                pad = ref[v];
                if (!dtimes[pad]) {
                  data.splice(v, 0, new BBModel.TimeSlot({
                    time: pad,
                    avail: 0
                  }, data[0].service));
                }
              }
            }
            if (($scope.data_source.requested_time || $scope.data_source.time) && $scope.selected_date.isSame($scope.data_source.date.date)) {
              found_time = false;
              for (k = 0, len2 = data.length; k < len2; k++) {
                t = data[k];
                if (t.time === $scope.data_source.requested_time) {
                  $scope.data_source.requestedTimeUnavailable();
                  $scope.highlightSlot(t);
                  $scope.skipThisStep();
                  $scope.decideNextPage();
                  found_time = true;
                  break;
                }
                if ($scope.data_source.time && t.time === $scope.data_source.time.time) {
                  $scope.data_source.setTime(t);
                  found_time = true;
                }
              }
              if (!found_time) {
                if (!$scope.options.persist_requested_time) {
                  $scope.data_source.requestedTimeUnavailable();
                }
                $scope.time_not_found = true;
                return AlertService.add("danger", {
                  msg: "Sorry, your requested time slot is not available. Please choose a different time."
                });
              }
            }
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.setLoaded($scope);
        }
      };
    })(this);

    /***
    * @ngdoc method
    * @name padTimes
    * @methodOf BB.Directives:bbTimes
    * @description
    * Pad Times in according of times parameter
    *
    * @param {date} times The times
     */
    $scope.padTimes = (function(_this) {
      return function(times) {
        return $scope.add_padding = times;
      };
    })(this);

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbTimes
    * @description
    * Set this page section as ready
     */
    return $scope.setReady = (function(_this) {
      return function() {
        if (!$scope.data_source.time) {
          AlertService.clear();
          AlertService.add("danger", {
            msg: "You need to select a time slot"
          });
          return false;
        } else {
          if ($scope.data_source.ready) {
            return $scope.addItemToBasket();
          } else {
            return true;
          }
        }
      };
    })(this);
  });

  angular.module('BB.Directives').directive('bbAccordianGroup', function() {
    return {
      restrict: 'AE',
      scope: true,
      controller: 'AccordianGroup'
    };
  });

  angular.module('BB.Controllers').controller('AccordianGroup', function($scope, $rootScope, $q) {
    var hasAvailability, updateAvailability;
    $scope.accordian_slots = [];
    $scope.is_open = false;
    $scope.has_availability = false;
    $scope.is_selected = false;
    $scope.collaspe_when_time_selected = true;
    $scope.start_time = 0;
    $scope.end_time = 0;
    $scope.init = (function(_this) {
      return function(start_time, end_time, options) {
        var i, len, ref, slot;
        $scope.start_time = start_time;
        $scope.end_time = end_time;
        $scope.collaspe_when_time_selected = options && !options.collaspe_when_time_selected ? false : true;
        ref = $scope.slots;
        for (i = 0, len = ref.length; i < len; i++) {
          slot = ref[i];
          if (slot.time >= start_time && slot.time < end_time) {
            $scope.accordian_slots.push(slot);
          }
        }
        return updateAvailability();
      };
    })(this);
    updateAvailability = (function(_this) {
      return function() {
        var item;
        $scope.has_availability = false;
        if ($scope.accordian_slots) {
          $scope.has_availability = hasAvailability();
          item = $scope.data_source;
          if (item.time && item.time.time >= $scope.start_time && item.time.time < $scope.end_time && (item.date && item.date.date.isSame($scope.selected_day.date, 'day'))) {
            $scope.is_selected = true;
            if (!$scope.collaspe_when_time_selected) {
              return $scope.is_open = true;
            }
          } else {
            $scope.is_selected = false;
            return $scope.is_open = false;
          }
        }
      };
    })(this);
    hasAvailability = (function(_this) {
      return function() {
        var i, len, ref, slot;
        if (!$scope.accordian_slots) {
          return false;
        }
        ref = $scope.accordian_slots;
        for (i = 0, len = ref.length; i < len; i++) {
          slot = ref[i];
          if (slot.availability() > 0) {
            return true;
          }
        }
        return false;
      };
    })(this);
    $scope.$on('slotChanged', (function(_this) {
      return function(event) {
        return updateAvailability();
      };
    })(this));
    return $scope.$on('slotsUpdated', (function(_this) {
      return function(event) {
        var i, len, ref, slot;
        $scope.accordian_slots = [];
        ref = $scope.slots;
        for (i = 0, len = ref.length; i < len; i++) {
          slot = ref[i];
          if (slot.time >= $scope.start_time && slot.time < $scope.end_time) {
            $scope.accordian_slots.push(slot);
          }
        }
        return updateAvailability();
      };
    })(this));
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbTimeRanges
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of time rangers for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbTimeRanges A hash of options
  * @property {string} selected_slot The selected slot
  * @property {date} selected_date The selected date
  * @property {string} postcode The postcode
  * @property {date} original_start_date The original start date
  * @property {date} start_at_week_start The start at week start
  * @property {object} alert The alert service - see {@link BB.Services:Alert Alert Service}
   */
  angular.module('BB.Directives').directive('bbTimeRanges', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      priority: 1,
      controller: 'TimeRangeList'
    };
  });

  angular.module('BB.Controllers').controller('TimeRangeList', function($scope, $element, $attrs, $rootScope, $q, TimeService, AlertService, BBModel, FormDataStoreService, DateTimeUlititiesService) {
    var currentPostcode, isSubtractValid, setTimeRange;
    $scope.controller = "public.controllers.TimeRangeList";
    currentPostcode = $scope.bb.postcode;
    FormDataStoreService.init('TimeRangeList', $scope, ['selected_slot', 'postcode', 'original_start_date', 'start_at_week_start']);
    if (currentPostcode !== $scope.postcode) {
      $scope.selected_slot = null;
      $scope.selected_date = null;
    }
    $scope.postcode = $scope.bb.postcode;
    $scope.notLoaded($scope);
    if (!$scope.data_source) {
      $scope.data_source = $scope.bb.current_item;
    }
    $scope.options = $scope.$eval($attrs.bbTimeRanges) || {};
    $rootScope.connection_started.then(function() {
      var date, diff, selected_day, start_date;
      if ($attrs.bbTimeRangeLength != null) {
        $scope.time_range_length = $scope.$eval($attrs.bbTimeRangeLength);
      } else if ($scope.options && $scope.options.time_range_length) {
        $scope.time_range_length = $scope.options.time_range_length;
      } else {
        $scope.time_range_length = 7;
      }
      if (($attrs.bbDayOfWeek != null) || ($scope.options && $scope.options.day_of_week)) {
        $scope.day_of_week = $attrs.bbDayOfWeek != null ? $scope.$eval($attrs.bbDayOfWeek) : $scope.options.day_of_week;
      }
      if (($attrs.bbSelectedDay != null) || ($scope.options && $scope.options.selected_day)) {
        selected_day = $attrs.bbSelectedDay != null ? moment($scope.$eval($attrs.bbSelectedDay)) : moment($scope.options.selected_day);
        if (moment.isMoment(selected_day)) {
          $scope.selected_day = selected_day;
        }
      }
      $scope.options.ignore_min_advance_datetime = $scope.options.ignore_min_advance_datetime ? true : false;
      if (!$scope.start_date && $scope.last_selected_date) {
        if ($scope.original_start_date) {
          diff = $scope.last_selected_date.diff($scope.original_start_date, 'days');
          diff = diff % $scope.time_range_length;
          diff = diff === 0 ? diff : diff + 1;
          start_date = $scope.last_selected_date.clone().subtract(diff, 'days');
          setTimeRange($scope.last_selected_date, start_date);
        } else {
          setTimeRange($scope.last_selected_date);
        }
      } else if ($scope.bb.current_item.date || $scope.bb.current_item.requested_date) {
        date = $scope.bb.current_item.date ? $scope.bb.current_item.date.date : $scope.bb.current_item.requested_date;
        setTimeRange(date);
      } else if ($scope.selected_day) {
        $scope.original_start_date = $scope.original_start_date || moment($scope.selected_day);
        setTimeRange($scope.selected_day);
      } else {
        $scope.start_at_week_start = true;
        setTimeRange(moment());
      }
      return $scope.loadData();
    }, function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name setTimeRange
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Set time range in according of selected date and start date parameters
    *
    * @param {date} selected_date The selected date
    * @param {date} start_date The start date
     */
    setTimeRange = function(selected_date, start_date) {
      if (start_date) {
        $scope.start_date = start_date;
      } else if ($scope.day_of_week) {
        $scope.start_date = selected_date.clone().day($scope.day_of_week);
      } else if ($scope.start_at_week_start) {
        $scope.start_date = selected_date.clone().startOf('week');
      } else {
        $scope.start_date = selected_date.clone();
      }
      $scope.selected_day = selected_date;
      $scope.selected_date = $scope.selected_day.toDate();
      isSubtractValid();
    };
    $scope.init = function(options) {
      if (options == null) {
        options = {};
      }
      if (options.selected_day != null) {
        if (!options.selected_day._isAMomementObject) {
          return $scope.selected_day = moment(options.selected_day);
        }
      }
    };

    /***
    * @ngdoc method
    * @name moment
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Add to moment date in according of date parameter
    *
    * @param {date} date The date
     */
    $scope.moment = function(date) {
      return moment(date);
    };

    /***
    * @ngdoc method
    * @name setDataSource
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Set data source in according of source parameter
    *
    * @param {array} source The source of data
     */
    $scope.setDataSource = function(source) {
      return $scope.data_source = source;
    };
    $scope.$on("currentItemUpdate", function(event) {
      return $scope.loadData();
    });

    /***
    * @ngdoc method
    * @name add
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Add new time range in according of type and amount parameters
    *
    * @param {object} type The type
    * @param {object} amount The amount of the days
     */
    $scope.add = function(type, amount) {
      if (amount > 0) {
        $element.removeClass('subtract');
        $element.addClass('add');
      }
      $scope.selected_day = moment($scope.selected_date);
      switch (type) {
        case 'days':
          setTimeRange($scope.selected_day.add(amount, 'days'));
          break;
        case 'weeks':
          $scope.start_date.add(amount, type);
          setTimeRange($scope.start_date);
          break;
        case 'months':
          $scope.start_date.add(amount, type).startOf('month');
          setTimeRange($scope.start_date);
      }
      return $scope.loadData();
    };

    /***
    * @ngdoc method
    * @name subtract
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Substract amount
    *
    * @param {object} type The type
    * @param {object} amount The amount of the days
     */
    $scope.subtract = function(type, amount) {
      $element.removeClass('add');
      $element.addClass('subtract');
      return $scope.add(type, -amount);
    };

    /***
    * @ngdoc method
    * @name isSubtractValid
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Deprecated due to performance issues, use $scope.is_subtract_valid and $scope.subtract_length instead
    *
    * @param {object} type The type
    * @param {object} amount The amount of the days
     */
    $scope.isSubtractValid = function(type, amount) {
      var date;
      if (!$scope.start_date || $scope.isAdmin()) {
        return true;
      }
      date = $scope.start_date.clone().subtract(amount, type);
      return !date.isBefore(moment(), 'day');
    };

    /***
    * @ngdoc method
    * @name isSubtractValid
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Verify if substraction is valid
    *
     */
    isSubtractValid = function() {
      var diff;
      $scope.is_subtract_valid = true;
      diff = Math.ceil($scope.selected_day.diff(moment(), 'day', true));
      $scope.subtract_length = diff < $scope.time_range_length ? diff : $scope.time_range_length;
      if (diff <= 0) {
        $scope.is_subtract_valid = false;
      }
      if ($scope.subtract_length > 1) {
        return $scope.subtract_string = "Prev " + $scope.subtract_length + " days";
      } else if ($scope.subtract_length === 1) {
        return $scope.subtract_string = "Prev day";
      } else {
        return $scope.subtract_string = "Prev";
      }
    };

    /***
    * @ngdoc method
    * @name selectedDateChanged
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Select date change
    *
     */
    $scope.selectedDateChanged = function() {
      setTimeRange(moment($scope.selected_date));
      $scope.selected_slot = null;
      return $scope.loadData();
    };

    /***
    * @ngdoc method
    * @name isPast
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Calculate if the current earliest date is in the past - in which case we might want to disable going backwards
    *
     */
    $scope.isPast = function() {
      if (!$scope.start_date) {
        return true;
      }
      return moment().isAfter($scope.start_date);
    };

    /***
    * @ngdoc method
    * @name status
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Check the status of the slot to see if it has been selected
    *
    * @param {date} day The day
    * @param {array} slot The slot
     */
    $scope.status = function(day, slot) {
      var status;
      if (!slot) {
        return;
      }
      status = slot.status();
      return status;
    };

    /***
    * @ngdoc method
    * @name selectSlot
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Called when user selects a time slot use this when you want to route to the next step as a slot is selected
    *
    * @param {date} day The day
    * @param {array} slot The slot
    * @param {string=} route A route of the selected slot
     */
    $scope.selectSlot = function(day, slot, route) {
      if (slot && slot.availability() > 0) {
        $scope.bb.current_item.setTime(slot);
        if (day) {
          $scope.setLastSelectedDate(day.date);
          $scope.bb.current_item.setDate(day);
        }
        if ($scope.bb.current_item.reserve_ready) {
          $scope.notLoaded($scope);
          return $scope.addItemToBasket().then(function() {
            $scope.setLoaded($scope);
            return $scope.decideNextPage(route);
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        } else {
          return $scope.decideNextPage(route);
        }
      }
    };

    /***
    * @ngdoc method
    * @name highlightSlot
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Called when user selects a time slot use this when you just want to hightlight the the slot and not progress to the next step
    *
    * @param {date} day The day
    * @param {array} slot The slot
     */
    $scope.highlightSlot = function(day, slot) {
      var current_item;
      current_item = $scope.bb.current_item;
      if (slot && slot.availability() > 0) {
        if (day) {
          $scope.setLastSelectedDate(day.date);
          current_item.setDate(day);
        }
        current_item.setTime(slot);
        current_item.setDate(day);
        $scope.selected_slot = slot;
        $scope.selected_day = day.date;
        $scope.selected_date = day.date.toDate();
        if ($scope.bb.current_item.earliest_time_slot && $scope.bb.current_item.earliest_time_slot.selected && (!$scope.bb.current_item.earliest_time_slot.date.isSame(day.date, 'day') || $scope.bb.current_item.earliest_time_slot.time !== slot.time)) {
          $scope.bb.current_item.earliest_time_slot.selected = false;
        }
        $rootScope.$broadcast("time:selected");
        return $scope.$broadcast('slotChanged', day, slot);
      }
    };

    /***
    * @ngdoc method
    * @name loadData
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Load the time data
    *
     */
    $scope.loadData = function() {
      var current_item, date, duration, edate, loc, promise;
      current_item = $scope.bb.current_item;
      if (current_item.service && !$scope.options.ignore_min_advance_datetime) {
        $scope.min_date = current_item.service.min_advance_datetime;
        $scope.max_date = current_item.service.max_advance_datetime;
        if ($scope.selected_day && $scope.selected_day.isBefore(current_item.service.min_advance_datetime, 'day') && !$scope.isAdmin()) {
          setTimeRange(current_item.service.min_advance_datetime);
        }
      }
      date = $scope.start_date;
      edate = moment(date).add($scope.time_range_length, 'days');
      $scope.end_date = moment(edate).add(-1, 'days');
      AlertService.clear();
      duration = $scope.bb.current_item.duration;
      if ($scope.bb.current_item.min_duration) {
        duration = $scope.bb.current_item.min_duration;
      }
      loc = null;
      if ($scope.bb.postcode) {
        loc = ",,,," + $scope.bb.postcode + ",";
      }
      if ($scope.data_source && $scope.data_source.days_link) {
        $scope.notLoaded($scope);
        loc = null;
        if ($scope.bb.postcode) {
          loc = ",,,," + $scope.bb.postcode + ",";
        }
        promise = TimeService.query({
          company: $scope.bb.company,
          resource_ids: $scope.bb.item_defaults.resources,
          cItem: $scope.data_source,
          date: date,
          client: $scope.client,
          end_date: $scope.end_date,
          duration: duration,
          location: loc,
          num_resources: $scope.bb.current_item.num_resources,
          available: 1
        });
        promise["finally"](function() {
          return $scope.setLoaded($scope);
        });
        return promise.then(function(datetime_arr) {
          var d, day, dtimes, i, j, k, len, len1, len2, pad, pair, ref, ref1, results, slot, time_slots, v;
          $scope.days = [];
          ref = _.sortBy(_.pairs(datetime_arr), function(pair) {
            return pair[0];
          });
          results = [];
          for (i = 0, len = ref.length; i < len; i++) {
            pair = ref[i];
            d = pair[0];
            time_slots = pair[1];
            day = {
              date: moment(d),
              slots: time_slots
            };
            $scope.days.push(day);
            if (time_slots.length > 0) {
              if (!current_item.earliest_time || current_item.earliest_time.isAfter(d)) {
                current_item.earliest_time = moment(d).add(time_slots[0].time, 'minutes');
              }
              if (!current_item.earliest_time_slot || current_item.earliest_time_slot.date.isAfter(d)) {
                current_item.earliest_time_slot = {
                  date: moment(d).add(time_slots[0].time, 'minutes'),
                  time: time_slots[0].time
                };
              }
            }
            if ($scope.add_padding && time_slots.length > 0) {
              dtimes = {};
              for (j = 0, len1 = time_slots.length; j < len1; j++) {
                slot = time_slots[j];
                dtimes[slot.time] = 1;
                slot.date = day.date.format('DD-MM-YY');
              }
              ref1 = $scope.add_padding;
              for (v = k = 0, len2 = ref1.length; k < len2; v = ++k) {
                pad = ref1[v];
                if (!dtimes[pad]) {
                  time_slots.splice(v, 0, new BBModel.TimeSlot({
                    time: pad,
                    avail: 0
                  }, time_slots[0].service));
                }
              }
            }
            results.push(DateTimeUlititiesService.checkRequestedTime(day, time_slots, current_item));
          }
          return results;
        }, function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      } else {
        return $scope.setLoaded($scope);
      }
    };

    /***
    * @ngdoc method
    * @name checkRequestedTime
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Check requested time
    *
    * @param {date} day The day
    * @param {date} time_losts The time slots
     */

    /***
    * @ngdoc method
    * @name padTimes
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * The pad time
    *
    * @param {date} times The times
     */
    $scope.padTimes = function(times) {
      return $scope.add_padding = times;
    };

    /***
    * @ngdoc method
    * @name setReady
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Set this page section as ready
     */
    $scope.setReady = function() {
      if (!$scope.bb.current_item.time) {
        AlertService.raise('TIME_SLOT_NOT_SELECTED');
        return false;
      } else if ($scope.bb.moving_booking && $scope.bb.current_item.start_datetime().isSame($scope.bb.current_item.original_datetime) && ($scope.current_item.person_name === $scope.current_item.person.name)) {
        AlertService.raise('APPT_AT_SAME_TIME');
        return false;
      } else if ($scope.bb.moving_booking) {
        if ($scope.bb.company.$has('resources') && !$scope.bb.current_item.resource) {
          $scope.bb.current_item.resource = true;
        }
        if ($scope.bb.company.$has('people') && !$scope.bb.current_item.person) {
          $scope.bb.current_item.person = true;
        }
        return true;
      } else {
        if ($scope.bb.current_item.reserve_ready) {
          return $scope.addItemToBasket();
        } else {
          return true;
        }
      }
    };

    /***
    * @ngdoc method
    * @name format_date
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Format the date in according of fmt parameter
    *
    * @param {date} fmt The format of date
     */
    $scope.format_date = function(fmt) {
      if ($scope.start_date) {
        return $scope.start_date.format(fmt);
      }
    };

    /***
    * @ngdoc method
    * @name format_start_date
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Format the start date in according of fmt parameter
    *
    * @param {date} fmt The format of start date
     */
    $scope.format_start_date = function(fmt) {
      return $scope.format_date(fmt);
    };

    /***
    * @ngdoc method
    * @name format_end_date
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Format the end date in according of fmt parameter
    *
    * @param {date} fmt The format of end date
     */
    $scope.format_end_date = function(fmt) {
      if ($scope.end_date) {
        return $scope.end_date.format(fmt);
      }
    };

    /***
    * @ngdoc method
    * @name pretty_month_title
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Format the month title in according of month formant, year format and separator parameters
    *
    * @param {date} month_format The month format
    * @param {date} year_format The year format
    * @param {object} separator The separator of month and year format
     */
    $scope.pretty_month_title = function(month_format, year_format, seperator) {
      var month_year_format, start_date;
      if (seperator == null) {
        seperator = '-';
      }
      month_year_format = month_format + ' ' + year_format;
      if ($scope.start_date && $scope.end_date && $scope.end_date.isAfter($scope.start_date, 'month')) {
        start_date = $scope.format_start_date(month_format);
        if ($scope.start_date.month() === 11) {
          start_date = $scope.format_start_date(month_year_format);
        }
        return start_date + ' ' + seperator + ' ' + $scope.format_end_date(month_year_format);
      } else {
        return $scope.format_start_date(month_year_format);
      }
    };

    /***
    * @ngdoc method
    * @name selectEarliestTimeSlot
    * @methodOf BB.Directives:bbTimeRanges
    * @description
    * Select earliest time slot
     */
    return $scope.selectEarliestTimeSlot = function() {
      var day, slot;
      day = _.find($scope.days, function(day) {
        return day.date.isSame($scope.bb.current_item.earliest_time_slot.date, 'day');
      });
      slot = _.find(day.slots, function(slot) {
        return slot.time === $scope.bb.current_item.earliest_time_slot.time;
      });
      if (day && slot) {
        $scope.bb.current_item.earliest_time_slot.selected = true;
        return $scope.highlightSlot(day, slot);
      }
    };
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc directive
  * @name BB.Directives:bbTotal
  * @restrict AE
  * @scope true
  *
  * @description
  *
  * Loads a list of totals for the currently in scope company
  *
  * <pre>
  * restrict: 'AE'
  * replace: true
  * scope: true
  * </pre>
  *
  * @param {hash}  bbTotal A hash of options
  * @property {array} payment_status The payment status
  * @property {array} total The total
   */
  angular.module('BB.Directives').directive('bbTotal', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Total'
    };
  });

  angular.module('BB.Controllers').controller('Total', function($scope, $rootScope, $q, $location, $window, PurchaseService, QueryStringService) {
    $scope.controller = "public.controllers.Total";
    $scope.notLoaded($scope);
    $rootScope.connection_started.then((function(_this) {
      return function() {
        var id;
        $scope.bb.payment_status = null;
        id = QueryStringService('purchase_id');
        if (id && !$scope.bb.total) {
          PurchaseService.query({
            url_root: $scope.bb.api_url,
            purchase_id: id
          }).then(function(total) {
            $scope.total = total;
            $scope.setLoaded($scope);
            if (total.paid === total.total_price) {
              return $scope.$emit("checkout:success", total);
            }
          });
        } else {
          $scope.total = $scope.bb.total;
          $scope.setLoaded($scope);
          if ($scope.total.paid === $scope.total.total_price) {
            $scope.$emit("checkout:success", $scope.total);
          }
        }
        return $scope.reset();
      };
    })(this), function(err) {
      return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
    });

    /***
    * @ngdoc method
    * @name print
    * @methodOf BB.Directives:bbTotal
    * @description
    * Open new window from partial url
     */
    return $scope.print = (function(_this) {
      return function() {
        $window.open($scope.bb.partial_url + 'print_purchase.html?id=' + $scope.total.long_id, '_blank', 'width=700,height=500,toolbar=0,menubar=0,location=0,status=1,scrollbars=1,resizable=1,left=0,top=0');
        return true;
      };
    })(this);
  });

}).call(this);

(function() {
  var app;

  app = angular.module('BB.Filters');

  angular.module('BB.Filters').filter('stripPostcode', function() {
    return function(address) {
      var match;
      match = address.toLowerCase().match(/[a-z]+\d/);
      if (match) {
        address = address.substr(0, match.index);
      }
      address = $.trim(address);
      if (/,$/.test(address)) {
        address = address.slice(0, -1);
      }
      return address;
    };
  });

  angular.module('BB.Filters').filter('labelNumber', function() {
    return function(input, labels) {
      var response;
      response = input;
      if (labels[input]) {
        response = labels[input];
      }
      return response;
    };
  });

  angular.module('BB.Filters').filter('interpolate', [
    'version', function(version) {
      return function(text) {
        return String(text).replace(/\%VERSION\%/mg, version);
      };
    }
  ]);

  angular.module('BB.Filters').filter('rag', function() {
    return function(value, v1, v2) {
      if (value <= v1) {
        return "red";
      } else if (value <= v2) {
        return "amber";
      } else {
        return "green";
      }
    };
  });

  angular.module('BB.Filters').filter('time', function($window) {
    return function(v) {
      return $window.sprintf("%02d:%02d", Math.floor(v / 60), v % 60);
    };
  });

  angular.module('BB.Filters').filter('address_single_line', function() {
    return (function(_this) {
      return function(address) {
        var addr;
        if (!address) {
          return;
        }
        if (!address.address1) {
          return;
        }
        addr = "";
        addr += address.address1;
        if (address.address2 && address.address2.length > 0) {
          addr += ", ";
          addr += address.address2;
        }
        if (address.address3 && address.address3.length > 0) {
          addr += ", ";
          addr += address.address3;
        }
        if (address.address4 && address.address4.length > 0) {
          addr += ", ";
          addr += address.address4;
        }
        if (address.address5 && address.address5.length > 0) {
          addr += ", ";
          addr += address.address5;
        }
        if (address.postcode && address.postcode.length > 0) {
          addr += ", ";
          addr += address.postcode;
        }
        return addr;
      };
    })(this);
  });

  angular.module('BB.Filters').filter('address_multi_line', function() {
    return (function(_this) {
      return function(address) {
        var str;
        if (!address) {
          return;
        }
        if (!address.address1) {
          return;
        }
        str = "";
        if (address.address1) {
          str += address.address1;
        }
        if (address.address2 && str.length > 0) {
          str += "<br/>";
        }
        if (address.address2) {
          str += address.address2;
        }
        if (address.address3 && str.length > 0) {
          str += "<br/>";
        }
        if (address.address3) {
          str += address.address3;
        }
        if (address.address4 && str.length > 0) {
          str += "<br/>";
        }
        if (address.address4) {
          str += address.address4;
        }
        if (address.address5 && str.length > 0) {
          str += "<br/>";
        }
        if (address.address5) {
          str += address.address5;
        }
        if (address.postcode && str.length > 0) {
          str += "<br/>";
        }
        if (address.postcode) {
          str += address.postcode;
        }
        return str;
      };
    })(this);
  });

  angular.module('BB.Filters').filter('map_lat_long', function() {
    return (function(_this) {
      return function(address) {
        var cord;
        if (!address) {
          return;
        }
        if (!address.map_url) {
          return;
        }
        cord = /([-+]*\d{1,3}[\.]\d*)[, ]([-+]*\d{1,3}[\.]\d*)/.exec(address.map_url);
        return cord[0];
      };
    })(this);
  });

  angular.module('BB.Filters').filter('currency', function($filter) {
    return (function(_this) {
      return function(number, currencyCode) {
        return $filter('icurrency')(number, currencyCode);
      };
    })(this);
  });

  angular.module('BB.Filters').filter('icurrency', function($window, $rootScope) {
    return (function(_this) {
      return function(number, currencyCode) {
        var currency, decimal, format, thousand;
        currencyCode || (currencyCode = $rootScope.bb_currency);
        currency = {
          USD: "$",
          GBP: "£",
          AUD: "$",
          EUR: "€",
          CAD: "$",
          MIXED: "~"
        };
        if ($.inArray(currencyCode, ["USD", "AUD", "CAD", "MIXED", "GBP"]) >= 0) {
          thousand = ",";
          decimal = ".";
          format = "%s%v";
        } else {
          thousand = ".";
          decimal = ",";
          format = "%s%v";
        }
        number = number / 100.0;
        return $window.accounting.formatMoney(number, currency[currencyCode], 2, thousand, decimal, format);
      };
    })(this);
  });

  angular.module('BB.Filters').filter('raw_currency', function() {
    return (function(_this) {
      return function(number) {
        return number / 100.0;
      };
    })(this);
  });

  angular.module('BB.Filters').filter('pretty_price', function($filter) {
    return function(price, symbol) {
      return $filter('ipretty_price')(price, symbol);
    };
  });

  angular.module('BB.Filters').filter('ipretty_price', function($window, $rootScope) {
    return function(price, symbol) {
      var currency;
      if (!symbol) {
        currency = {
          USD: "$",
          GBP: "£",
          AUD: "$",
          EUR: "€",
          CAD: "$",
          MIXED: "~"
        };
        symbol = currency[$rootScope.bb_currency];
      }
      price /= 100.0;
      if (parseFloat(price) === 0) {
        return 'Free';
      } else if (parseFloat(price) % 1 === 0) {
        return symbol + parseFloat(price);
      } else {
        return symbol + $window.sprintf("%.2f", parseFloat(price));
      }
    };
  });

  angular.module('BB.Filters').filter('time_period', function() {
    return function(v, options) {
      var hour_string, hours, min_string, mins, separator, str, val;
      if (!angular.isNumber(v)) {
        return;
      }
      hour_string = options && options.abbr_units ? "hr" : "hour";
      min_string = options && options.abbr_units ? "min" : "minute";
      separator = options && angular.isString(options.separator) ? options.separator : "and";
      val = parseInt(v);
      if (val < 60) {
        str = val + " " + min_string;
        if (val > 1) {
          str += "s";
        }
        return str;
      }
      hours = parseInt(val / 60);
      mins = val % 60;
      if (mins === 0) {
        if (hours === 1) {
          return "1 " + hour_string;
        } else {
          return hours + " " + hour_string + "s";
        }
      } else {
        str = hours + " " + hour_string;
        if (hours > 1) {
          str += "s";
        }
        if (mins === 0) {
          return str;
        }
        if (separator.length > 0) {
          str += " " + separator;
        }
        str += " " + mins + " " + min_string;
        if (mins > 1) {
          str += "s";
        }
      }
      return str;
    };
  });

  angular.module('BB.Filters').filter('twelve_hour_time', function($window) {
    return function(time, options) {
      var h, m, omit_mins_on_hour, separator, suffix, t;
      if (!angular.isNumber(time)) {
        return;
      }
      omit_mins_on_hour = options && options.omit_mins_on_hour || false;
      separator = options && options.separator ? options.separator : ":";
      t = time;
      h = Math.floor(t / 60);
      m = t % 60;
      suffix = 'am';
      if (h >= 12) {
        suffix = 'pm';
      }
      if (h > 12) {
        h -= 12;
      }
      if (m === 0 && omit_mins_on_hour) {
        time = "" + h;
      } else {
        time = ("" + h + separator) + $window.sprintf("%02d", m);
      }
      time += suffix;
      return time;
    };
  });

  angular.module('BB.Filters').filter('time_period_from_seconds', function() {
    return function(v) {
      var hours, mins, secs, str, val;
      val = parseInt(v);
      if (val < 60) {
        return "" + val + " seconds";
      }
      hours = Math.floor(val / 3600);
      mins = Math.floor(val % 3600 / 60);
      secs = Math.floor(val % 60);
      str = "";
      if (hours > 0) {
        str += hours + " hour";
        if (hours > 1) {
          str += "s";
        }
        if (mins === 0 && secs === 0) {
          return str;
        }
        str += " and ";
      }
      if (mins > 0) {
        str += mins + " minute";
        if (mins > 1) {
          str += "s";
        }
        if (secs === 0) {
          return str;
        }
        str += " and ";
      }
      str += secs + " second";
      if (secs > 0) {
        str += "s";
      }
      return str;
    };
  });

  angular.module('BB.Filters').filter('round_up', function() {
    return function(number, interval) {
      var result;
      result = number / interval;
      result = parseInt(result);
      result = result * interval;
      if ((number % interval) > 0) {
        result = result + interval;
      }
      return result;
    };
  });

  angular.module('BB.Filters').filter('exclude_days', function() {
    return function(days, excluded) {
      return _.filter(days, function(day) {
        return excluded.indexOf(day.date.format('dddd')) === -1;
      });
    };
  });

  angular.module('BB.Filters').filter('local_phone_number', function(SettingsService, ValidatorService) {
    return function(phone_number) {
      var cc;
      if (!phone_number) {
        return;
      }
      cc = SettingsService.getCountryCode();
      switch (cc) {
        case "uk":
          return "0" + phone_number;
        case "us":
          return phone_number.replace(ValidatorService.us_phone_number, "($1) $2 $3");
        default:
          return phone_number;
      }
    };
  });

  angular.module('BB.Filters').filter('datetime', function(SettingsService) {
    return function(date, format) {
      var cc, datestrings;
      if (date && moment.isMoment(date)) {
        datestrings = {
          datetime_us: 'MM/DD/YYYY, h:mm a',
          datetime_uk: 'DD/MM/YYYY, HH:mm',
          date_us: 'MM/DD/YYYY',
          date_uk: 'DD/MM/YYYY',
          time_us: 'h:mm a',
          time_uk: 'HH:mm'
        };
        cc = SettingsService.getCountryCode();
        if (cc !== "us") {
          cc = "uk";
        }
        if (format && format.match(/(date(time_uk|time_us|_us|_uk)*|(time(_uk|_us)*))/)) {
          return date.format(datestrings[format + "_" + cc]);
        } else if (format) {
          return date.format(format);
        } else {
          return date.format(datestrings["date_" + cc]);
        }
      } else {

      }
    };
  });

  angular.module('BB.Filters').filter('range', function() {
    return function(input, min, max) {
      var i, j, ref, ref1;
      for (i = j = ref = parseInt(min), ref1 = parseInt(max); ref <= ref1 ? j <= ref1 : j >= ref1; i = ref <= ref1 ? ++j : --j) {
        input.push(i);
      }
      return input;
    };
  });

  angular.module('BB.Filters').filter('international_number', function() {
    return (function(_this) {
      return function(number, prefix) {
        if (number && prefix) {
          return prefix + " " + number;
        } else if (number) {
          return "" + number;
        } else {
          return "";
        }
      };
    })(this);
  });

  angular.module('BB.Filters').filter("startFrom", function() {
    return function(input, start) {
      if (input === undefined) {
        return input;
      } else {
        return input.slice(+start);
      }
    };
  });

  angular.module('BB.Filters').filter('add', function() {
    return (function(_this) {
      return function(item, value) {
        if (item && value) {
          item = parseInt(item);
          return item + value;
        }
      };
    })(this);
  });

  angular.module('BB.Filters').filter('spaces_remaining', function() {
    return function(spaces) {
      if (spaces < 1) {
        return 0;
      } else {
        return spaces;
      }
    };
  });

  angular.module('BB.Filters').filter('key_translate', function() {
    return function(input) {
      var add_underscore, remove_punctuations, upper_case;
      upper_case = angular.uppercase(input);
      remove_punctuations = upper_case.replace(/[\.,-\/#!$%\^&\*;:{}=\-_`~()]/g, "");
      add_underscore = remove_punctuations.replace(/\ /g, "_");
      return add_underscore;
    };
  });

  app.filter('clearTimezone', function() {
    return function(val, offset) {
      if (val !== null && val.length > 19) {
        return val.substring(0, 19);
      }
      return val;
    };
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Directives').directive('bbBasket', function(PathSvc) {
    return {
      restrict: 'A',
      replace: true,
      scope: true,
      templateUrl: function(element, attrs) {
        if (_.has(attrs, 'mini')) {
          return PathSvc.directivePartial("_basket_mini");
        } else {
          return PathSvc.directivePartial("basket");
        }
      },
      controllerAs: 'BasketCtrl',
      controller: function($scope, $modal, BasketService) {
        var BasketInstanceCtrl;
        $scope.setUsingBasket(true);
        this.empty = function() {
          return $scope.$eval('emptyBasket()');
        };
        this.view = function() {
          return $scope.$eval('viewBasket()');
        };
        $scope.showBasketDetails = function() {
          var modalInstance;
          if (($scope.bb.current_page === "basket") || ($scope.bb.current_page === "checkout")) {
            return false;
          } else {
            return modalInstance = $modal.open({
              templateUrl: $scope.getPartial("_basket_details"),
              scope: $scope,
              controller: BasketInstanceCtrl,
              resolve: {
                basket: function() {
                  return $scope.bb.basket;
                }
              }
            });
          }
        };
        BasketInstanceCtrl = function($scope, $rootScope, $modalInstance, basket) {
          $scope.basket = basket;
          return $scope.cancel = function() {
            return $modalInstance.dismiss("cancel");
          };
        };
        $scope.$watch(function() {
          var len;
          $scope.basketItemCount = len = $scope.bb.basket ? $scope.bb.basket.length() : 0;
          if (!len) {
            $scope.basketStatus = "empty";
          } else {
            if (len === 1) {
              $scope.basketStatus = "1 item in your basket";
            } else {
              $scope.basketStatus = len + " items in your basket";
            }
          }
        });
      },
      link: function(scope, element, attrs) {
        return element.bind('click', function(e) {
          return e.preventDefault();
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbMinSpend', function() {
    return {
      restrict: 'A',
      scope: true,
      controller: function($scope, $element, $attrs, AlertService, $filter) {
        var checkMinSpend, options;
        options = $scope.$eval($attrs.bbMinSpend || {});
        $scope.min_spend = options.min_spend || 0;
        $scope.setReady = function() {
          return checkMinSpend();
        };
        return checkMinSpend = function() {
          var i, item, len1, price, ref;
          price = 0;
          ref = $scope.bb.stacked_items;
          for (i = 0, len1 = ref.length; i < len1; i++) {
            item = ref[i];
            price += item.service.price;
          }
          if (price >= $scope.min_spend) {
            AlertService.clear();
            return true;
          } else {
            AlertService.clear();
            price = $filter('ipretty_price')($scope.min_spend);
            AlertService.add("warning", {
              msg: "You need to spend at least " + price + " to make a booking."
            });
            return false;
          }
        };
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Directives').directive('bbBreadcrumb', function(PathSvc) {
    return {
      restrict: 'A',
      replace: true,
      scope: true,
      controller: 'Breadcrumbs',
      templateUrl: function(element, attrs) {
        if (_.has(attrs, 'complex')) {
          return PathSvc.directivePartial("_breadcrumb_complex");
        } else {
          return PathSvc.directivePartial("_breadcrumb");
        }
      },
      link: function(scope) {}
    };
  });

  angular.module('BB.Controllers').controller('Breadcrumbs', function($scope) {
    var atDisablePoint, currentStep, lastStep, loadStep;
    loadStep = $scope.loadStep;
    $scope.steps = $scope.bb.steps;
    $scope.allSteps = $scope.bb.allSteps;
    $scope.loadStep = function(number) {
      if (!lastStep() && !currentStep(number) && !atDisablePoint()) {
        return loadStep(number);
      }
    };
    lastStep = function() {
      return $scope.bb.current_step === $scope.bb.allSteps.length;
    };
    currentStep = function(step) {
      return step === $scope.bb.current_step;
    };
    atDisablePoint = function() {
      if (!angular.isDefined($scope.bb.disableGoingBackAtStep)) {
        return false;
      }
      return $scope.bb.current_step >= $scope.bb.disableGoingBackAtStep;
    };
    return $scope.isDisabledStep = function(step) {
      if (lastStep() || currentStep(step.number) || !step.passed || atDisablePoint()) {
        return true;
      } else {
        return false;
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  var app;

  app = angular.module('BB.Directives');

  app.directive('bbContentNew', function(PathSvc) {
    return {
      restrict: 'A',
      replace: true,
      scope: true,
      templateUrl: PathSvc.directivePartial("content_main"),
      controller: function($scope) {
        $scope.initPage = function() {
          return $scope.$eval('setPageLoaded()');
        };
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbDatepickerPopup', function($parse, $document, $timeout, $bbug) {
    var e, error, ie8orLess;
    ie8orLess = false;
    try {
      ie8orLess = window.parseInt(/MSIE\s*(\d)/.exec(window.navigator.userAgent)[1]);
    } catch (error) {
      e = error;
      ie8orLess = false;
    }
    return {
      restrict: 'A',
      priority: -1,
      require: 'ngModel',
      link: function(scope, element, attrs, ngModel) {
        var callDateHandler, data, dateFormat, f, format, getTimeRangeScope, getter, origDateParser, replacementDateParser, timeRangeScope, yearNow;
        origDateParser = null;
        data = element.controller('ngModel');
        if (attrs.datepickerPopup != null) {
          format = {
            date_us: "MM/dd/yyyy",
            date_uk: "dd/MM/yyyy"
          };
          if (scope.bb.company.country_code === "us") {
            attrs.datepickerPopup = format.date_us;
          } else {
            attrs.datepickerPopup = format.date_uk;
          }
        }
        dateFormat = !!attrs.bbDatepickerPopup ? attrs.bbDatepickerPopup : 'DD/MM/YYYY';
        yearNow = moment(new Date()).year();
        getter = $parse(attrs.ngModel);
        timeRangeScope = scope;
        getTimeRangeScope = function(scope) {
          if (scope) {
            if (scope.controller && scope.controller.indexOf('TimeRangeList') > 0) {
              return timeRangeScope = scope;
            } else {
              return getTimeRangeScope(scope.$parent);
            }
          }
        };
        getTimeRangeScope(scope);
        if (ie8orLess) {
          $bbug(element).on('keydown keyup keypress', function(ev) {
            ev.preventDefault();
            return ev.stopPropagation();
          });
        }
        if (ie8orLess || scope.display.xs) {
          $bbug(element).attr('readonly', 'true');
        }
        $bbug(element).on('keydown', function(e) {
          if (e.keyCode === 13) {
            replacementDateParser($bbug(e.target).val(), true);
            $document.trigger('click');
            return $bbug(element).blur();
          }
        });
        $bbug(element).on('click', function(e) {
          e.preventDefault();
          e.stopPropagation();
          return $timeout(function() {
            return scope.opened = true;
          });
        });
        $bbug(element).on('focus', function() {
          if ($(this).attr("readonly")) {
            return this.blur();
          }
        });
        callDateHandler = function(date) {
          var isDate, watch;
          watch = scope.$watch(getter, function(newVal, oldVal) {
            if (!newVal) {
              return getter.assign(timeRangeScope, date);
            }
          });
          $timeout(watch, 0);
          isDate = _.isDate(date);
          if (isDate) {
            getter.assign(timeRangeScope, date);
            ngModel.$setValidity('date', true);
            scope.$eval(attrs.onDateChange);
          }
          return isDate;
        };
        replacementDateParser = function(viewValue, returnKey) {
          var mDate;
          if (callDateHandler(viewValue)) {
            return viewValue;
          }
          if (ie8orLess) {
            return viewValue;
          }
          mDate = moment(viewValue, dateFormat);
          if (!mDate.isValid()) {
            mDate = moment(new Date());
          }
          if (/\/YY$/.test(dateFormat)) {
            dateFormat += 'YY';
          }
          if (mDate.year() === 0) {
            mDate.year(yearNow);
          }
          viewValue = mDate.format('MM/DD/YYYY');
          viewValue = viewValue.replace(/\/00/, '/20');
          if (/\/02\d{2}$/.test(viewValue)) {
            return;
          }
          if (returnKey) {
            if (mDate.year().toString().length === 2) {
              mDate.year(mDate.year() + 2000);
            }
            return callDateHandler(mDate._d);
          } else {
            return origDateParser.call(this, viewValue);
          }
        };
        f = function() {
          if (_.isFunction(data.$parsers[0])) {
            origDateParser = data.$parsers[0];
            data.$parsers[0] = replacementDateParser;
          } else {
            return setTimeout(f, 10);
          }
        };
        return f();
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('datetimepicker', function() {
    var controller, link;
    controller = function($scope) {
      $scope.open = function($event) {
        $event.preventDefault();
        $event.stopPropagation();
        return $scope.opened = true;
      };
      return $scope.$watch('$$value$$', function(value) {
        if (value != null) {
          return $scope.updateModel(value);
        }
      });
    };
    link = function(scope, element, attrs, ngModel) {
      ngModel.$render = function() {
        if (ngModel.$viewValue) {
          if (moment.isMoment(ngModel.$viewValue)) {
            return scope.$$value$$ = ngModel.$viewValue.format();
          } else {
            return scope.$$value$$ = ngModel.$viewValue;
          }
        } else {
          return scope.$$value$$ = scope.schemaValidate.schema["default"];
        }
      };
      return scope.updateModel = function(value) {
        return ngModel.$setViewValue(moment(value).format());
      };
    };
    return {
      require: 'ngModel',
      link: link,
      controller: controller,
      scope: {
        schemaValidate: '='
      },
      templateUrl: 'datetimepicker.html'
    };
  });

}).call(this);

(function() {
  angular.module("BB.Directives").directive("bbFbLogin", function(LoginService, $rootScope, AlertService, $window) {
    return {
      restrict: 'A',
      scope: true,
      link: function(scope, element, attrs) {
        var checkLoginState, loginToBBWithFBUser, options, statusChangeCallback;
        options = scope.$eval(attrs.bbFbLogin) || {};
        $rootScope.connection_started.then(function() {
          return checkLoginState();
        });
        statusChangeCallback = function(response) {
          var params;
          if (response.status === 'connected') {
            params = {};
            params.access_token = response.authResponse.accessToken;
            if (options.login_only) {
              params.login_only = options.login_only;
            }
            loginToBBWithFBUser(params);
          } else if (response.status === 'not_authorized') {
            scope.loginFB();
          } else {
            scope.loginFB();
          }
        };
        checkLoginState = function() {
          FB.getLoginStatus(function(response) {
            statusChangeCallback(response);
          });
        };
        loginToBBWithFBUser = function(params) {
          return LoginService.FBLogin(scope.bb.company, params).then(function(member) {
            $rootScope.member = member;
            scope.setClient($rootScope.member);
            if (scope.bb.destination) {
              return scope.redirectTo(scope.bb.destination);
            } else {
              scope.setLoaded(scope);
              return scope.decideNextPage();
            }
          }, function(err) {
            if (err.data.error === "FACEBOOK-LOGIN-MEMBER-NOT-FOUND") {
              return AlertService.raise('FB_LOGIN_NOT_A_MEMBER');
            } else {
              return AlertService.raise('LOGIN_FAILED');
            }
          });
        };
        return scope.loginFB = function() {
          return FB.login((function(response) {
            var params;
            if (response.status === 'connected') {
              params = {};
              params.access_token = response.authResponse.accessToken;
              if (options.login_only) {
                params.login_only = options.login_only;
              }
              loginToBBWithFBUser(params);
            } else if (response.status === 'not_authorized') {
              AlertService.raise('LOGIN_FAILED');
            } else {
              AlertService.raise('LOGIN_FAILED');
            }
          }), {
            scope: 'public_profile,email'
          });
        };
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Directives').directive('bbFormDataStore', function(FormDataStoreService) {
    return {
      require: '?bbWidget',
      link: function(scope) {
        return FormDataStoreService.register(scope);
      }
    };
  });

}).call(this);

(function() {
  var app;

  app = angular.module('BB.Directives');

  app.directive('ngConfirmClick', function() {
    return {
      link: function(scope, element, attr) {
        var clickAction, msg;
        msg = attr.ngConfirmClick || "Are you sure?";
        clickAction = attr.ngConfirmedClick;
        return element.bind('click', (function(_this) {
          return function(event) {
            if (window.confirm(msg)) {
              return scope.$eval(clickAction);
            }
          };
        })(this));
      }
    };
  });

  app.directive('ngValidInclude', function($compile) {
    return {
      link: function(scope, element, attr) {
        return scope[attr.watchValue].then((function(_this) {
          return function(logged) {
            element.attr('ng-include', attr.ngValidInclude);
            element.attr('ng-valid-include', null);
            return $compile(element)(scope);
          };
        })(this));
      }
    };
  });

  app.directive('ngDelayed', function($compile) {
    return {
      link: function(scope, element, attr) {
        return scope[attr.ngDelayedWatch].then((function(_this) {
          return function(logged) {
            element.attr(attr.ngDelayed, attr.ngDelayedValue);
            element.attr('ng-delayed-value', null);
            element.attr('ng-delayed-watch', null);
            element.attr('ng-delayed', null);
            $compile(element)(scope);
            if (attr.ngDelayedReady) {
              return scope[attr.ngDelayedReady].resolve(true);
            }
          };
        })(this));
      }
    };
  });

  app.directive('ngInitial', function() {
    return {
      restrict: 'A',
      controller: [
        '$scope', '$element', '$attrs', '$parse', function($scope, $element, $attrs, $parse) {
          var getter, setter, val;
          val = $attrs.ngInitial || $attrs.value;
          getter = $parse($attrs.ngModel);
          setter = getter.assign;
          if (val === "true") {
            val = true;
          } else if (val === "false") {
            val = false;
          }
          return setter($scope, val);
        }
      ]
    };
  });

  app.directive('bbPrintPage', function($window, $timeout) {
    return {
      restrict: 'A',
      link: function(scope, element, attr) {
        if (attr.bbPrintPage) {
          return scope.$watch(attr.bbPrintPage, (function(_this) {
            return function(newVal, oldVal) {
              return $timeout(function() {
                return $window.print();
              }, 3000);
            };
          })(this));
        }
      }
    };
  });

  app.directive('bbInclude', function($compile, $rootScope) {
    return {
      link: function(scope, element, attr) {
        var track_page;
        track_page = attr.bbTrackPage != null ? true : false;
        return scope.$watch('bb.path_setup', (function(_this) {
          return function(newval, oldval) {
            if (newval) {
              element.attr('ng-include', "'" + scope.getPartial(attr.bbInclude) + "'");
              element.attr('bb-include', null);
              $compile(element)(scope);
              if (track_page) {
                return $rootScope.$broadcast("page:loaded", attr.bbInclude);
              }
            }
          };
        })(this));
      }
    };
  });

  app.directive('bbRaiseAlertWhenInvalid', function($compile) {
    return {
      require: '^form',
      link: function(scope, element, attr, ctrl) {
        var options;
        ctrl.raise_alerts = true;
        options = scope.$eval(attr.bbRaiseAlertWhenInvalid);
        if (options && options.alert) {
          return ctrl.alert = options.alert;
        }
      }
    };
  });

  app.directive('bbHeader', function($compile) {
    return {
      link: function(scope, element, attr) {
        scope.bb.waitForRoutes();
        return scope.$watch('bb.path_setup', (function(_this) {
          return function(newval, oldval) {
            if (newval) {
              element.attr('ng-include', "'" + scope.getPartial(attr.bbHeader) + "'");
              element.attr('bb-header', null);
              return $compile(element)(scope);
            }
          };
        })(this));
      }
    };
  });

  app.directive('bbDate', function() {
    return {
      restrict: 'AE',
      scope: true,
      link: function(scope, element, attrs) {
        var date, track_service;
        track_service = attrs.bbTrackService != null;
        if (attrs.bbDate) {
          date = moment(scope.$eval(attrs.bbDate));
        } else if (scope.bb && scope.bb.current_item && scope.bb.current_item.date) {
          date = scope.bb.current_item.date.date;
        } else {
          date = moment();
        }
        if (track_service && scope.bb.current_item && scope.bb.current_item.service) {
          scope.min_date = scope.bb.current_item.service.min_advance_datetime;
          scope.max_date = scope.bb.current_item.service.max_advance_datetime;
        }
        scope.$broadcast('dateChanged', moment(date));
        scope.bb_date = {
          date: date,
          js_date: date.toDate(),
          addDays: function(type, amount) {
            this.date = moment(this.date).add(amount, type);
            this.js_date = this.date.toDate();
            return scope.$broadcast('dateChanged', moment(this.date));
          },
          subtractDays: function(type, amount) {
            return this.addDays(type, -amount);
          },
          setDate: function(date) {
            this.date = date;
            this.js_date = date.toDate();
            return scope.$broadcast('dateChanged', moment(this.date));
          }
        };
        scope.$on("currentItemUpdate", function(event) {
          if (scope.bb.current_item.service && track_service) {
            scope.min_date = scope.bb.current_item.service.min_advance_datetime;
            scope.max_date = scope.bb.current_item.service.max_advance_datetime;
            if (scope.bb_date.date.isBefore(scope.min_date, 'day')) {
              scope.bb_date.setDate(scope.min_date.clone());
            }
            if (scope.bb_date.date.isAfter(scope.max_date, 'day')) {
              return scope.bb_date.setDate(scope.max_date.clone());
            }
          }
        });
        return scope.$watch('bb_date.js_date', function(newval, oldval) {
          var ndate;
          ndate = moment(newval);
          if (!scope.bb_date.date.isSame(ndate)) {
            scope.bb_date.date = ndate;
            if (moment(ndate).isValid()) {
              return scope.$broadcast('dateChanged', moment(ndate));
            }
          }
        });
      }
    };
  });

  app.directive('bbDebounce', function($timeout) {
    return {
      restrict: 'A',
      link: function(scope, element, attrs) {
        var delay;
        delay = 400;
        if (attrs.bbDebounce) {
          delay = attrs.bbDebounce;
        }
        return element.bind('click', (function(_this) {
          return function() {
            $timeout(function() {
              return element.attr('disabled', true);
            }, 0);
            return $timeout(function() {
              return element.attr('disabled', false);
            }, delay);
          };
        })(this));
      }
    };
  });

  app.directive('bbLocalNumber', function() {
    return {
      restrict: 'A',
      require: 'ngModel',
      link: function(scope, element, attrs, ctrl) {
        var prettyifyNumber;
        prettyifyNumber = function(value) {
          if (value && value[0] !== "0") {
            value = "0" + value;
          } else {
            value;
          }
          return value;
        };
        return ctrl.$formatters.push(prettyifyNumber);
      }
    };
  });

  app.directive('bbPadWithZeros', function() {
    return {
      restrict: 'A',
      require: 'ngModel',
      link: function(scope, element, attrs, ctrl) {
        var how_many, options, padNumber;
        options = scope.$eval(attrs.bbPadWithZeros) || {};
        how_many = options.how_many || 2;
        padNumber = function(value) {
          var i, index, padding, ref;
          value = String(value);
          if (value && value.length < how_many) {
            padding = "";
            for (index = i = 1, ref = how_many - value.length; 1 <= ref ? i <= ref : i >= ref; index = 1 <= ref ? ++i : --i) {
              padding += "0";
            }
            value = padding.concat(value);
          }
          return value;
        };
        return ctrl.$formatters.push(padNumber);
      }
    };
  });

  app.directive('bbFormResettable', function($parse) {
    return {
      restrict: 'A',
      controller: function($scope, $element, $attrs) {
        $scope.inputs = [];
        $scope.resetForm = function(options) {
          var i, input, len, ref, results;
          if (options && options.clear_submitted) {
            $scope[$attrs.name].submitted = false;
          }
          ref = $scope.inputs;
          results = [];
          for (i = 0, len = ref.length; i < len; i++) {
            input = ref[i];
            input.getter.assign($scope, null);
            results.push(input.controller.$setPristine());
          }
          return results;
        };
        return {
          registerInput: function(input, ctrl) {
            var getter;
            getter = $parse(input);
            return $scope.inputs.push({
              getter: getter,
              controller: ctrl
            });
          }
        };
      }
    };
  });

  app.directive('bbResettable', function() {
    return {
      restrict: 'A',
      require: ['ngModel', '^bbFormResettable'],
      link: function(scope, element, attrs, ctrls) {
        var formResettableCtrl, ngModelCtrl;
        ngModelCtrl = ctrls[0];
        formResettableCtrl = ctrls[1];
        return formResettableCtrl.registerInput(attrs.ngModel, ngModelCtrl);
      }
    };
  });

  app.directive('bbDateSplit', function($parse) {
    return {
      restrict: 'A',
      require: ['ngModel'],
      link: function(scope, element, attrs, ctrls) {
        var ngModel, question;
        ngModel = ctrls[0];
        question = scope.$eval(attrs.bbDateSplit);
        question.date = {
          day: null,
          month: null,
          year: null,
          date: null,
          joinDate: function() {
            var date_string;
            if (this.day && this.month && this.year) {
              date_string = this.day + '/' + this.month + '/' + this.year;
              this.date = moment(date_string, "DD/MM/YYYY");
              date_string = this.date.toISODate();
              ngModel.$setViewValue(date_string);
              return ngModel.$render();
            }
          },
          splitDate: function(date) {
            if (date && date.isValid()) {
              this.day = date.date();
              this.month = date.month() + 1;
              this.year = date.year();
              return this.date = date;
            }
          }
        };
        if (question.answer) {
          question.date.splitDate(moment(question.answer));
        }
        if (ngModel.$viewValue) {
          return question.date.splitDate(moment(ngModel.$viewValue));
        }
      }
    };
  });

  app.directive('bbCommPref', function() {
    return {
      restrict: 'A',
      require: ['ngModel'],
      link: function(scope, element, attrs, ctrls) {
        var comm_pref, ng_model_ctrl, parser;
        ng_model_ctrl = ctrls[0];
        comm_pref = scope.$eval(attrs.bbCommPref) || false;
        if ((scope.bb.current_item.settings.send_email_followup != null) && (scope.bb.current_item.settings.send_sms_followup != null)) {
          comm_pref = scope.bb.current_item.settings.send_email_followup;
        } else {
          scope.bb.current_item.settings.send_email_followup = comm_pref;
          scope.bb.current_item.settings.send_sms_followup = comm_pref;
        }
        ng_model_ctrl.$setViewValue(comm_pref);
        parser = function(value) {
          scope.bb.current_item.settings.send_email_followup = value;
          scope.bb.current_item.settings.send_sms_followup = value;
          return value;
        };
        return ng_model_ctrl.$parsers.push(parser);
      }
    };
  });

  app.directive('bbCountTicketTypes', function($rootScope) {
    return {
      restrict: 'A',
      scope: false,
      link: function(scope, element, attrs) {
        var countTicketTypes;
        $rootScope.connection_started.then(function() {
          return countTicketTypes();
        });
        scope.$on("basket:updated", function(event, basket) {
          return countTicketTypes();
        });
        return countTicketTypes = function(items) {
          var counts, i, item, len;
          items = scope.bb.basket.timeItems();
          counts = [];
          for (i = 0, len = items.length; i < len; i++) {
            item = items[i];
            if (item.tickets) {
              if (counts[item.tickets.name]) {
                counts[item.tickets.name] += item.tickets.qty;
              } else {
                counts[item.tickets.name] = item.tickets.qty;
              }
              item.number = counts[item.tickets.name];
            }
          }
          return scope.counts = counts;
        };
      }
    };
  });

  app.directive('bbCapitaliseFirstLetter', function() {
    return {
      restrict: 'A',
      require: ['ngModel'],
      link: function(scope, element, attrs, ctrls) {
        var ngModel;
        ngModel = ctrls[0];
        return scope.$watch(attrs.ngModel, function(newval, oldval) {
          var string;
          if (newval) {
            string = scope.$eval(attrs.ngModel);
            string = string.charAt(0).toUpperCase() + string.slice(1);
            ngModel.$setViewValue(string);
            ngModel.$render();
          }
        });
      }
    };
  });

  app.directive('bbApiUrl', function($rootScope, $compile, $sniffer, $timeout, $window, $location) {
    return {
      restrict: 'A',
      scope: {
        'apiUrl': '@bbApiUrl'
      },
      compile: function(tElem, tAttrs) {
        return {
          pre: function(scope, element, attrs) {
            var src, url;
            $rootScope.bb || ($rootScope.bb = {});
            $rootScope.bb.api_url = scope.apiUrl;
            url = document.createElement('a');
            url.href = scope.apiUrl;
            if (($sniffer.msie && $sniffer.msie <= 9) || ($sniffer.webkit && $sniffer.webkit < 537)) {
              if (!(url.host === '' || url.host === $location.host() || url.host === (($location.host()) + ":" + ($location.port())))) {
                if (url.protocol[url.protocol.length - 1] === ':') {
                  src = url.protocol + "//" + url.host + "/ClientProxy.html";
                } else {
                  src = url.protocol + "://" + url.host + "/ClientProxy.html";
                }
                $rootScope.iframe_proxy_ready = false;
                return $compile("<iframe id='ieapiframefix' name='" + url.hostname + ("' src='" + src + "' style='visibility:false;display:none;'></iframe>"))(scope, (function(_this) {
                  return function(cloned, scope) {
                    cloned.bind("load", function() {
                      $rootScope.iframe_proxy_ready = true;
                      return $rootScope.$broadcast('iframe_proxy_ready', {
                        iframe_proxy_ready: true
                      });
                    });
                    return element.append(cloned);
                  };
                })(this));
              }
            }
          }
        };
      }
    };
  });

  app.directive('bbPriceFilter', function(PathSvc) {
    return {
      restrict: 'AE',
      replace: true,
      scope: false,
      require: '^?bbServices',
      templateUrl: function(element, attrs) {
        return PathSvc.directivePartial("_price_filter");
      },
      controller: function($scope, $attrs) {
        var setPricefilter, suitable_max;
        $scope.$watch('items', function(new_val, old_val) {
          if (new_val) {
            return setPricefilter(new_val);
          }
        });
        setPricefilter = function(items) {
          $scope.price_array = _.uniq(_.map(items, function(item) {
            return item.price / 100 || 0;
          }));
          $scope.price_array.sort(function(a, b) {
            return a - b;
          });
          return suitable_max();
        };
        suitable_max = function() {
          var max_number, min_number, top_number;
          top_number = _.last($scope.price_array);
          max_number = (function() {
            switch (false) {
              case !(top_number < 1):
                return 0;
              case !(top_number < 11):
                return 10;
              case !(top_number < 51):
                return 50;
              case !(top_number < 101):
                return 100;
              case !(top_number < 1000):
                return (Math.ceil(top_number / 100)) * 100;
            }
          })();
          min_number = 0;
          $scope.price_options = {
            min: min_number,
            max: max_number
          };
          return $scope.filters.price = {
            min: min_number,
            max: max_number
          };
        };
        $scope.$watch('filters.price.min', function(new_val, old_val) {
          if (new_val !== old_val) {
            return $scope.filterChanged();
          }
        });
        return $scope.$watch('filters.price.max', function(new_val, old_val) {
          if (new_val !== old_val) {
            return $scope.filterChanged();
          }
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbBookingExport', function() {
    return {
      restrict: 'AE',
      scope: true,
      template: '<div bb-include="_popout_export_booking" style="display: inline-block"></div>',
      link: function(scope, el, attrs) {
        var setHTML;
        scope.$watch('total', function(new_val, old_val) {
          if (new_val) {
            return setHTML(new_val);
          }
        });
        scope.$watch('purchase', function(new_val, old_val) {
          if (new_val) {
            return setHTML(new_val);
          }
        });
        return setHTML = function(purchase_total) {
          return scope.html = ("<div class='text-center'><a href='" + (purchase_total.webcalLink()) + "'><img src='images/outlook.png' alt='outlook calendar icon' height='30' width='30' /><div class='clearfix'></div><span>Outlook</span></a></div><p></p>") + ("<div class='text-center'><a href='" + (purchase_total.gcalLink()) + "'><img src='images/google.png' alt='google calendar icon' height='30' width='30' /><div class='clearfix'></div><span>Google</span></a></div><p></p>") + ("<div class='text-center'><a href='" + (purchase_total.icalLink()) + "'><img src='images/ical.png' alt='ical calendar icon' height='30' width='30' /><div class='clearfix'></div><span>iCal</span></a></div>");
        };
      }
    };
  });


  /***
  * @ngdoc directive
  * @name BB.Directives:bbBlurOnReturn
  * @restrict A
  * @scope true
  *
  * @description
  * Removes focus from an input[type=text] element when return key is pressed
  * @example
  * <input type='text' bb-blur-on-return></div>
   */

  angular.module('BB.Directives').directive('bbBlurOnReturn', function($timeout) {
    return {
      restrict: 'A',
      require: 'ngModel',
      link: function(scope, el, attrs) {
        return el.keydown(function(e) {
          var key;
          key = e.which || e.keyCode;
          if (key === 13 || key === '13') {
            return $timeout(function() {
              if (e.target) {
                return e.target.blur();
              }
            }, 10);
          }
        });
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  var app, isEmpty;

  app = angular.module('BB.Directives');

  app.directive('bbQuestionLine', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      link: function(scope, element, attrs) {
        var e, elm, html, index;
        if (scope.question.detail_type === "heading") {
          elm = "";
          if (scope.question.name.length > 0) {
            elm += "<div class='bb-question-heading'>" + scope.question.name + "</div>";
          }
          if (scope.question.help_text && scope.question.help_text.length > 0) {
            elm += "<div class='bb-question-help-text'>" + scope.question.help_text + "</div>";
          }
          element.html(elm);
        }
        if (scope.idmaps && ((scope.idmaps[scope.question.detail_type] && scope.idmaps[scope.question.detail_type].block) || (scope.idmaps[scope.question.id] && scope.idmaps[scope.question.id].block))) {
          index = scope.idmaps[scope.question.id] ? scope.question.id : scope.question.detail_type;
          html = scope.$parent.idmaps[index].html;
          return e = $compile(html)(scope, (function(_this) {
            return function(cloned, scope) {
              return element.replaceWith(cloned);
            };
          })(this));
        }
      }
    };
  });

  app.directive('bbQuestion', function($compile, $timeout) {
    return {
      priority: 0,
      replace: true,
      transclude: false,
      restrict: 'A',
      compile: function(el, attr, trans) {
        return {
          pre: function(scope, element, attrs) {
            var adminRequired, date_format, date_format_2;
            adminRequired = attrs.bbAdminRequired != null ? true : false;
            date_format = 'DD/MM/YYYY';
            date_format_2 = 'dd/MM/yyyy';
            if ((attrs.bbDateFormat != null) && attrs.bbDateFormat === 'US') {
              date_format = 'MM/DD/YYYY';
              date_format_2 = 'MM/dd/yyyy';
            }
            return scope.$watch(attrs.bbQuestion, function(question) {
              var e, html, i, index, itemx, j, k, lastName, len1, len2, len3, name, placeholder, ref, ref1, ref2;
              if (question) {
                html = '';
                lastName = '';
                placeholder = '';
                if (attrs.defaultPlaceholder != null) {
                  if (question.detail_type === "text_area" | question.detail_type === "text_field") {
                    if (question["default"]) {
                      placeholder = question["default"];
                    }
                    if (question.answer === question["default"]) {
                      question.answer = "";
                    }
                  }
                }
                scope.recalc = (function(_this) {
                  return function() {
                    if (angular.isDefined(scope.recalc_price)) {
                      if (!question.outcome) {
                        scope.recalc_price();
                      }
                    }
                    if (angular.isDefined(scope.recalc_question)) {
                      return scope.recalc_question();
                    }
                  };
                })(this);
                if (scope.idmaps && (scope.idmaps[question.detail_type] || scope.idmaps[question.id])) {
                  index = scope.idmaps[scope.question.id] ? scope.question.id : scope.question.detail_type;
                  html = scope.idmaps[index].html;
                } else if (question.detail_type === "select" || question.detail_type === "select-price") {
                  html = "<select ng-model='question.answer' name='q" + question.id + "' id='" + question.id + "' ng-change='recalc()' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' class='form-question form-control'>";
                  ref = question.options;
                  for (i = 0, len1 = ref.length; i < len1; i++) {
                    itemx = ref[i];
                    html += "<option data_id='" + itemx.id + "' value='" + (itemx.name.replace(/'/g, "&apos;")) + "'>" + itemx.display_name + "</option>";
                  }
                  html += "</select>";
                } else if (question.detail_type === "text_area") {
                  html = "<textarea placeholder='" + placeholder + "' ng-model='question.answer' name='q" + question.id + "' id='" + question.id + "' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' rows=3 class='form-question form-control'>" + question['answer'] + "</textarea>";
                } else if (question.detail_type === "radio") {
                  html = '<div class="radio-group">';
                  ref1 = question.options;
                  for (j = 0, len2 = ref1.length; j < len2; j++) {
                    itemx = ref1[j];
                    html += "<div class='radio'><label class='radio-label'><input ng-model='question.answer' name='q" + question.id + "' id='" + question.id + "' ng-change='recalc()' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' type='radio' value=\"" + itemx.name + "\"/>" + itemx.name + "</label></div>";
                  }
                  html += "</div>";
                } else if (question.detail_type === "check") {
                  name = question.name;
                  if (name === lastName) {
                    name = "";
                  }
                  lastName = question.name;
                  html = "<div class='checkbox' ng-class='{\"selected\": question.answer}'><label><input name='q" + question.id + "' id='" + question.id + "' ng-model='question.answer' ng-checked='question.answer == \"1\"' ng-change='recalc()' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' type='checkbox' value=1>" + name + "</label></div>";
                } else if (question.detail_type === "check-price") {
                  html = "<div class='checkbox'><label><input name='q" + question.id + "' id='" + question.id + "' ng-model='question.answer' ng-checked='question.answer == \"1\"' ng-change='recalc()' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' type='checkbox' value=1> ({{question.price | currency:'GBP'}})</label></div>";
                } else if (question.detail_type === "radio-price") {
                  html = '<div class="radio-group">';
                  ref2 = question.options;
                  for (k = 0, len3 = ref2.length; k < len3; k++) {
                    itemx = ref2[k];
                    html += "<div class='radio'><label class='radio-label'><input ng-model='question.answer' name='q" + question.id + "' id='" + question.id + "' ng-change='recalc()' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' type='radio' value=\"" + itemx.name + "\"/>" + itemx.display_name + "</label></div>";
                  }
                  html += "</div>";
                } else if (question.detail_type === "date") {
                  html = "<div class='input-group date-picker'> <input type='text' class='form-question form-control' name='q" + question.id + "' id='" + question.id + "' bb-datepicker-popup='" + date_format + "' datepicker-popup='" + date_format_2 + "' ng-model='question.answer' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' datepicker-options='{\"starting-day\": 1}' show-weeks='false' show-button-bar='false' is-open='opened' /> <span class='input-group-btn' ng-click='$event.preventDefault();$event.stopPropagation();opened=true'> <button class='btn btn-default' type='submit'><span class='glyphicon glyphicon-calendar'></span></button> </span> </div>";
                } else {
                  html = "<input type='text' placeholder='" + placeholder + "'  ng-model='question.answer' name='q" + question.id + "' id='" + question.id + "' ng-required='question.currentlyShown && ((" + adminRequired + " && question.required) || (question.required && !bb.isAdmin))' class='form-question form-control'/>";
                }
                if (html) {
                  return e = $compile(html)(scope, (function(_this) {
                    return function(cloned, scope) {
                      return element.replaceWith(cloned);
                    };
                  })(this));
                }
              }
            });
          },
          post: function(scope, $e, $a, parentControl) {}
        };
      }
    };
  });

  app.directive('bbQuestionSetup', function() {
    return {
      restrict: 'A',
      terminal: true,
      priority: 1000,
      link: function(scope, element, attrs) {
        var block, child, def, i, id, idmaps, index, len1, ref;
        idmaps = {};
        def = null;
        ref = element.children();
        for (index = i = 0, len1 = ref.length; i < len1; index = ++i) {
          child = ref[index];
          id = $(child).attr("bb-question-id");
          block = false;
          if ($(child).attr("bb-replace-block")) {
            block = true;
          }
          child.innerHTML = child.innerHTML.replace(/question_form/g, "question_form_" + index);
          idmaps[id] = {
            id: id,
            html: child.innerHTML,
            block: block
          };
        }
        scope.idmaps = idmaps;
        return element.replaceWith("");
      }
    };
  });

  app.directive("bbFocus", [
    function() {
      var FOCUS_CLASS;
      FOCUS_CLASS = "bb-focused";
      return {
        restrict: "A",
        require: "ngModel",
        link: function(scope, element, attrs, ctrl) {
          ctrl.$focused = false;
          return element.bind("focus", function(evt) {
            element.addClass(FOCUS_CLASS);
            return scope.$apply(function() {
              return ctrl.$focused = true;
            });
          }).bind("blur", function(evt) {
            element.removeClass(FOCUS_CLASS);
            return scope.$apply(function() {
              return ctrl.$focused = false;
            });
          });
        }
      };
    }
  ]);

  app.directive('bbCurrencyField', function($filter) {
    return {
      restrict: 'A',
      require: 'ngModel',
      link: function(scope, element, attrs, ctrl) {
        var convertToCurrency, convertToInteger;
        convertToCurrency = function(value) {
          return value / 100;
        };
        convertToInteger = function(value) {
          return value * 100;
        };
        ctrl.$formatters.push(convertToCurrency);
        return ctrl.$parsers.push(convertToInteger);
      }
    };
  });

  isEmpty = function(value) {
    return angular.isUndefined(value) || value === "" || value === null || value !== value;
  };

  app.directive("ngMin", function() {
    return {
      restrict: "A",
      require: "ngModel",
      link: function(scope, elem, attr, ctrl) {
        var minValidator;
        minValidator = function(value) {
          var min;
          min = scope.$eval(attr.ngMin) || 0;
          ctrl.$setValidity("ngMin", isEmpty(value) || value >= min);
          return value;
        };
        ctrl.$parsers.push(minValidator);
        ctrl.$formatters.push(minValidator);
      }
    };
  });

  app.directive("ngMax", function() {
    return {
      restrict: "A",
      require: "ngModel",
      link: function(scope, elem, attr, ctrl) {
        var maxValidator;
        maxValidator = function(value) {
          var max;
          max = scope.$eval(attr.ngMax);
          ctrl.$setValidity("ngMax", isEmpty(value) || value <= max);
          return value;
        };
        ctrl.$parsers.push(maxValidator);
        ctrl.$formatters.push(maxValidator);
      }
    };
  });

  app.directive("creditCardNumber", function() {
    var getCardType, isValid, linker;
    getCardType = function(ccnumber) {
      if (!ccnumber) {
        return '';
      }
      ccnumber = ccnumber.toString().replace(/\s+/g, '');
      if (/^(34)|^(37)/.test(ccnumber)) {
        return "american_express";
      }
      if (/^(62)|^(88)/.test(ccnumber)) {
        return "china_unionpay";
      }
      if (/^30[0-5]/.test(ccnumber)) {
        return "diners_club_carte_blanche";
      }
      if (/^(2014)|^(2149)/.test(ccnumber)) {
        return "diners_club_enroute";
      }
      if (/^36/.test(ccnumber)) {
        return "diners_club_international";
      }
      if (/^(6011)|^(622(1(2[6-9]|[3-9][0-9])|[2-8][0-9]{2}|9([01][0-9]|2[0-5])))|^(64[4-9])|^65/.test(ccnumber)) {
        return "discover";
      }
      if (/^35(2[89]|[3-8][0-9])/.test(ccnumber)) {
        return "jcb";
      }
      if (/^(6304)|^(6706)|^(6771)|^(6709)/.test(ccnumber)) {
        return "laser";
      }
      if (/^(5018)|^(5020)|^(5038)|^(5893)|^(6304)|^(6759)|^(6761)|^(6762)|^(6763)|^(0604)/.test(ccnumber)) {
        return "maestro";
      }
      if (/^5[1-5]/.test(ccnumber)) {
        return "master";
      }
      if (/^4/.test(ccnumber)) {
        return "visa";
      }
      if (/^(4026)|^(417500)|^(4405)|^(4508)|^(4844)|^(4913)|^(4917)/.test(ccnumber)) {
        return "visa_electron";
      }
    };
    isValid = function(ccnumber) {
      var len, mul, prodArr, sum;
      if (!ccnumber) {
        return false;
      }
      ccnumber = ccnumber.toString().replace(/\s+/g, '');
      len = ccnumber.length;
      mul = 0;
      prodArr = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9], [0, 2, 4, 6, 8, 1, 3, 5, 7, 9]];
      sum = 0;
      while (len--) {
        sum += prodArr[mul][parseInt(ccnumber.charAt(len), 10)];
        mul ^= 1;
      }
      return sum % 10 === 0 && sum > 0;
    };
    linker = function(scope, element, attributes, ngModel) {
      return scope.$watch(function() {
        return ngModel.$modelValue;
      }, function(newValue) {
        ngModel.$setValidity('card_number', isValid(newValue));
        scope.cardType = getCardType(newValue);
        if ((newValue != null) && newValue.length === 16) {
          if (ngModel.$invalid) {
            element.parent().addClass('has-error');
            return element.parent().removeClass('has-success');
          } else {
            element.parent().removeClass('has-error');
            return element.parent().addClass('has-success');
          }
        } else {
          return element.parent().removeClass('has-success');
        }
      });
    };
    return {
      restrict: "C",
      require: "ngModel",
      link: linker,
      scope: {
        'cardType': '='
      }
    };
  });

  app.directive("cardSecurityCode", function() {
    var linker;
    linker = function(scope, element, attributes) {
      return scope.$watch('cardType', function(newValue) {
        if (newValue === 'american_express') {
          element.attr('maxlength', 4);
          return element.attr('placeholder', "••••");
        } else {
          element.attr('maxlength', 3);
          return element.attr('placeholder', "•••");
        }
      });
    };
    return {
      restrict: "AC",
      link: linker,
      scope: {
        'cardType': '='
      }
    };
  });

  app.directive('bbInputGroupManager', function(ValidatorService) {
    return {
      restrict: 'A',
      controller: function($scope, $element, $attrs) {
        $scope.input_manger = {
          input_groups: {},
          inputs: [],
          registerInput: function(input, name) {
            if (this.inputs.indexOf(input.$name) >= 0) {
              return;
            }
            this.inputs.push(input.$name);
            if (!this.input_groups[name]) {
              this.input_groups[name] = {
                inputs: [],
                valid: false
              };
            }
            return this.input_groups[name].inputs.push(input);
          },
          validateInputGroup: function(name) {
            var i, input, is_valid, j, len1, len2, ref, ref1;
            is_valid = false;
            ref = this.input_groups[name].inputs;
            for (i = 0, len1 = ref.length; i < len1; i++) {
              input = ref[i];
              is_valid = input.$modelValue;
              if (is_valid) {
                break;
              }
            }
            if (is_valid === !this.input_groups[name].valid) {
              ref1 = this.input_groups[name].inputs;
              for (j = 0, len2 = ref1.length; j < len2; j++) {
                input = ref1[j];
                input.$setValidity(input.$name, is_valid);
              }
              return this.input_groups[name].valid = is_valid;
            }
          }
        };
        return $element.on("submit", function() {
          var input_group, results;
          results = [];
          for (input_group in $scope.input_manger.input_groups) {
            results.push($scope.input_manger.validateInputGroup(input_group));
          }
          return results;
        });
      }
    };
  });

  app.directive("bbInputGroup", function() {
    return {
      restrict: "A",
      require: 'ngModel',
      link: function(scope, elem, attrs, ngModel) {
        if (scope.input_manger.inputs.indexOf(ngModel.$name) >= 0) {
          return;
        }
        scope.input_manger.registerInput(ngModel, attrs.bbInputGroup);
        return scope.$watch(attrs.ngModel, function(newval, oldval) {
          if (newval === !oldval) {
            return scope.input_manger.validateInputGroup(attrs.bbInputGroup);
          }
        });
      }
    };
  });

  app.directive('bbQuestionLabel', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      scope: false,
      link: function(scope, element, attrs) {
        return scope.$watch(attrs.bbQuestionLabel, function(question) {
          if (question) {
            if (question.detail_type === "check" || question.detail_type === "check-price") {
              return element.html("");
            }
          }
        });
      }
    };
  });

  app.directive('bbQuestionLink', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      scope: true,
      link: function(scope, element, attrs) {
        var id;
        id = parseInt(attrs.bbQuestionLink);
        return scope.$watch("question_set", function(newval, oldval) {
          var i, len1, q, ref, results;
          if (newval) {
            ref = scope.question_set;
            results = [];
            for (i = 0, len1 = ref.length; i < len1; i++) {
              q = ref[i];
              if (q.id === id) {
                scope.question = q;
                element.attr('ng-model', "question.answer");
                element.attr('bb-question-link', null);
                results.push($compile(element)(scope));
              } else {
                results.push(void 0);
              }
            }
            return results;
          }
        });
      }
    };
  });

  app.directive('bbQuestionSet', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      scope: true,
      link: function(scope, element, attrs) {
        var set;
        set = attrs.bbQuestionSet;
        element.addClass('ng-hide');
        return scope.$watch(set, function(newval, oldval) {
          if (newval) {
            scope.question_set = newval;
            return element.removeClass('ng-hide');
          }
        });
      }
    };
  });

  app.directive("bbMatchInput", function() {
    return {
      restrict: "A",
      require: 'ngModel',
      link: function(scope, element, attrs, ctrl, ngModel) {
        var compare;
        scope.$watch(attrs.bbMatchInput, function() {
          scope.val_1 = scope.$eval(attrs.bbMatchInput);
          return compare(ctrl.$viewValue);
        });
        compare = function(value) {
          ctrl.$setValidity('match', scope.val_1 === value);
          return value;
        };
        return ctrl.$parsers.push(compare);
      }
    };
  });

}).call(this);

(function() {
  var app;

  app = angular.module('BB.Directives');

  app.directive("bbIntTelNumber", function($parse) {
    return {
      restrict: "A",
      require: "ngModel",
      link: function(scope, element, attrs, ctrl) {
        var format, isValid, options, parse;
        options = scope.$eval(attrs.bbIntTelNumber);
        element.intlTelInput(options);
        isValid = function(value) {
          if (value) {
            return element.intlTelInput("isValidNumber");
          } else {
            return true;
          }
        };
        format = function(value) {
          var str;
          str = "";
          if (scope.$eval(attrs.ngModel + '_prefix') != null) {
            str += "+" + scope.$eval(attrs.ngModel + '_prefix') + " ";
          }
          if (scope.$eval(attrs.ngModel) != null) {
            str += scope.$eval(attrs.ngModel);
          }
          if (str[0] === "+") {
            element.intlTelInput("setNumber", "+" + (scope.$eval(attrs.ngModel + '_prefix')) + " " + (scope.$eval(attrs.ngModel)));
            ctrl.$setValidity("phone", isValid(value));
          }
          return str;
        };
        parse = function(value) {
          var getter, prefix;
          prefix = element.intlTelInput("getSelectedCountryData").dialCode;
          getter = $parse(attrs.ngModel + '_prefix');
          getter.assign(scope, prefix);
          ctrl.$setValidity("phone", isValid(value));
          return value;
        };
        ctrl.$formatters.push(format);
        return ctrl.$parsers.push(parse);
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  var app;

  app = angular.module('BB.Directives');

  app.directive('bbLoader', function($rootScope, $compile, PathSvc, TemplateSvc) {
    return {
      restrict: 'A',
      replace: false,
      scope: {},
      controllerAs: 'LoaderCtrl',
      controller: function($scope) {
        var addScopeId, hideLoader, parentScopeId, removeScopeId, scopeIdArr, showLoader;
        parentScopeId = $scope.$parent.$id;
        scopeIdArr = [];
        addScopeId = function(id) {
          scopeIdArr.push(id);
          scopeIdArr = _.uniq(scopeIdArr);
        };
        removeScopeId = function(id) {
          scopeIdArr = _.without(scopeIdArr, id);
          return scopeIdArr.length;
        };
        showLoader = function(e, cscope) {
          var sid;
          sid = cscope.$id;
          while (cscope) {
            if (cscope.$id === parentScopeId) {
              addScopeId(sid);
              $scope.scopeLoaded = false;
              break;
            }
            cscope = cscope.$parent;
          }
        };
        hideLoader = function(e, cscope) {
          if (!removeScopeId(cscope.$id)) {
            $scope.scopeLoaded = true;
          }
        };
        $rootScope.$on('show:loader', showLoader);
        $rootScope.$on('hide:loader', hideLoader);
        $scope.scopeLoaded = false;
      },
      link: function(scope, element, attrs) {
        TemplateSvc.get(PathSvc.directivePartial("loader")).then(function(html) {
          var str;
          if (_.isString(attrs.bbLoader)) {
            str = attrs.bbLoader.slice(1);
            if (/^#/.test(attrs.bbLoader)) {
              html.attr('id', str);
            } else if (/^\./.test(attrs.bbLoader)) {
              html.addClass(str);
            }
          }
          element.prepend(html);
          $compile(html)(scope);
        });
      }
    };
  });

  app.directive('bbLoadingSpinner', function($compile) {
    return {
      transclude: true,
      link: function(scope, element, attrs, controller, transclude) {
        var loadingScopes;
        loadingScopes = {};
        scope.isLoading = false;
        return scope.$on('isLoading', function(event, isLoading) {
          event.stopPropagation();
          loadingScopes[event.targetScope.$id] = isLoading;
          return scope.isLoading = _.every(_.values(loadingScopes));
        });
      },
      template: "<div ng-show=\"isLoading\" class=\"loader-wrapper\">\n  <div class=\"loader\"></div>\n</div>\n<div ng-transclude></div>"
    };
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Directives').directive('bbContent', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      link: function(scope, element, attrs) {
        element.attr('ng-include', "bb_main");
        element.attr('onLoad', "initPage()");
        element.attr('bb-content', null);
        element.attr('ng-hide', "hide_page");
        scope.initPage = (function(_this) {
          return function() {
            scope.setPageLoaded();
            return scope.setLoadingPage(false);
          };
        })(this);
        return $compile(element)(scope);
      }
    };
  });

  angular.module('BB.Directives').directive('bbLoading', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      link: function(scope, element, attrs) {
        scope.scopeLoaded = scope.areScopesLoaded(scope);
        element.attr('ng-hide', "scopeLoaded");
        element.attr('bb-loading', null);
        $compile(element)(scope);
      }
    };
  });

  angular.module('BB.Directives').directive('bbWaitFor', function($compile) {
    return {
      transclude: false,
      restrict: 'A',
      priority: 800,
      link: function(scope, element, attrs) {
        var name, prom;
        name = attrs.bbWaitVar;
        name || (name = "allDone");
        scope[name] = false;
        prom = scope.$eval(attrs.bbWaitFor);
        prom.then(function() {
          return scope[name] = true;
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbScrollTo', function($rootScope, AppConfig, BreadcrumbService, $bbug, $window, SettingsService) {
    return {
      transclude: false,
      restrict: 'A',
      link: function(scope, element, attrs) {
        var always_scroll, bb_transition_time, evnts, scrollToCallback;
        evnts = attrs.bbScrollTo.split(',');
        always_scroll = (attrs.bbAlwaysScroll != null) || false;
        bb_transition_time = attrs.bbTransitionTime != null ? parseInt(attrs.bbTransitionTime, 10) : 500;
        if (angular.isArray(evnts)) {
          angular.forEach(evnts, function(evnt) {
            return scope.$on(evnt, function(e) {
              return scrollToCallback(evnt);
            });
          });
        } else {
          scope.$on(evnts, function(e) {
            return scrollToCallback(evnts);
          });
        }
        return scrollToCallback = function(evnt) {
          var current_step, scroll_to_element;
          if (evnt === "page:loaded" && scope.display && scope.display.xs && $bbug('[data-scroll-id="' + AppConfig.uid + '"]').length) {
            scroll_to_element = $bbug('[data-scroll-id="' + AppConfig.uid + '"]');
          } else {
            scroll_to_element = $bbug(element);
          }
          current_step = BreadcrumbService.getCurrentStep();
          if (scroll_to_element) {
            if ((evnt === "page:loaded" && current_step > 1) || always_scroll || (evnt === "widget:restart") || (!scroll_to_element.is(':visible') && scroll_to_element.offset().top !== 0)) {
              if ('parentIFrame' in $window) {
                return parentIFrame.scrollToOffset(0, scroll_to_element.offset().top - SettingsService.getScrollOffset());
              } else {
                return $bbug("html, body").animate({
                  scrollTop: scroll_to_element.offset().top - SettingsService.getScrollOffset()
                }, bb_transition_time);
              }
            }
          }
        };
      }
    };
  });

  angular.module('BB.Directives').directive('bbSlotGrouper', function() {
    return {
      restrict: 'A',
      scope: true,
      link: function(scope, element, attrs) {
        var i, len, slot, slots;
        slots = scope.$eval(attrs.slots);
        if (!slots) {
          return;
        }
        scope.grouped_slots = [];
        for (i = 0, len = slots.length; i < len; i++) {
          slot = slots[i];
          if (slot.time >= scope.$eval(attrs.startTime) && slot.time < scope.$eval(attrs.endTime)) {
            scope.grouped_slots.push(slot);
          }
        }
        return scope.has_slots = scope.grouped_slots.length > 0;
      }
    };
  });

  angular.module('BB.Directives').directive('bbForm', function($bbug, $window, SettingsService) {
    return {
      restrict: 'A',
      require: '^form',
      link: function(scope, elem, attrs, ctrls) {
        var form_controller;
        form_controller = ctrls;
        return elem.on("submit", function() {
          var invalid_form_group, invalid_input, property;
          form_controller.submitted = true;
          for (property in form_controller) {
            if (angular.isObject(form_controller[property]) && form_controller[property].hasOwnProperty('$valid')) {
              form_controller[property].submitted = true;
            }
          }
          scope.$apply();
          invalid_form_group = elem.find('.has-error:first');
          if (invalid_form_group && invalid_form_group.length > 0) {
            if ('parentIFrame' in $window) {
              parentIFrame.scrollToOffset(0, invalid_form_group.offset().top - SettingsService.getScrollOffset());
            } else {
              $bbug("html, body").animate({
                scrollTop: invalid_form_group.offset().top - SettingsService.getScrollOffset()
              }, 1000);
            }
            invalid_input = invalid_form_group.find('.ng-invalid');
            invalid_input.focus();
            return false;
          }
          return true;
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbAddressMap', function($document) {
    return {
      restrict: 'A',
      scope: true,
      replace: true,
      controller: function($scope, $element, $attrs) {
        $scope.isDraggable = $document.width() > 480;
        return $scope.$watch($attrs.bbAddressMap, function(new_val, old_val) {
          var map_item;
          if (!new_val) {
            return;
          }
          map_item = new_val;
          $scope.map = {
            center: {
              latitude: map_item.lat,
              longitude: map_item.long
            },
            zoom: 15
          };
          $scope.options = {
            scrollwheel: false,
            draggable: $scope.isDraggable
          };
          return $scope.marker = {
            id: 0,
            coords: {
              latitude: map_item.lat,
              longitude: map_item.long
            }
          };
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbMergeDuplicateQuestions', function() {
    return {
      restrict: 'A',
      scope: true,
      controller: function($scope, $rootScope) {
        $scope.questions = {};
        return $rootScope.$on("item_details:loaded", function() {
          var i, item, j, len, len1, question, ref, ref1;
          ref = $scope.bb.stacked_items;
          for (i = 0, len = ref.length; i < len; i++) {
            item = ref[i];
            if (item.item_details && item.item_details.questions) {
              item.item_details.hide_questions = false;
              ref1 = item.item_details.questions;
              for (j = 0, len1 = ref1.length; j < len1; j++) {
                question = ref1[j];
                if ($scope.questions[question.id]) {
                  item.setCloneAnswers($scope.questions[question.id].item);
                  item.item_details.hide_questions = true;
                  break;
                } else {
                  $scope.questions[question.id] = {
                    question: question,
                    item: item
                  };
                }
              }
            }
          }
          return $scope.has_questions = _.pluck($scope.questions, 'question').length > 0;
        });
      }
    };
  });

  angular.module('BB.Directives').directive('bbModal', function($window, $bbug, $timeout) {
    return {
      restrict: 'A',
      scope: true,
      link: function(scope, elem, attrs) {
        var deregisterWatcher;
        return $timeout(function() {
          return elem.parent().parent().parent().css("z-index", 999999);
        }, deregisterWatcher = scope.$watch(function() {
          var height, modal_padding, new_height;
          height = elem.height();
          if ($bbug(window).width() >= 769) {
            modal_padding = 200;
          } else {
            modal_padding = 20;
          }
          if (height > $bbug(window).height()) {
            new_height = $bbug(window).height() - modal_padding;
            elem.css({
              "height": new_height + "px",
              "overflow-y": "scroll"
            });
            return deregisterWatcher();
          }
        }));
      }
    };
  });


  /***
  * @ngdoc directive
  * @name BB.Directives:bbBackgroundImage
  * @restrict A
  * @scope true
  *
  * @description
  * Adds a background-image to an element
  
  * @param
  * {string} url
  *
  * @example
  * <div bb-background-image='images/example.jpg'></div>
   */

  angular.module('BB.Directives').directive('bbBackgroundImage', function() {
    return {
      restrict: 'A',
      scope: true,
      link: function(scope, el, attrs) {
        var killWatch;
        if (!attrs.bbBackgroundImage || attrs.bbBackgroundImage === "") {
          return;
        }
        return killWatch = scope.$watch(attrs.bbBackgroundImage, function(new_val, old_val) {
          if (new_val) {
            killWatch();
            return el.css('background-image', 'url("' + new_val + '")');
          }
        });
      }
    };
  });


  /***
  * @ngdoc directive
  * @name BB.Directives:bbCapacityView
  * @restrict A
  * @description
  * Assigns an appropriate description of ticket availability based
  * on the value of the "Select spaces view" dropdown in the admin console
  * @param
  * {object} The event object
  * @attribute ticket-type-singular
  * {String} Custom name for the ticket
  * @example
  * <span bb-capacity-view='event' ticket-type-singular='seat'></span>
  * @example_result
  * <span bb-capacity-view='event' ticket-type-singular='seat' class='ng-binding'>5 of 10 seats available</span>
   */

  angular.module('BB.Directives').directive('bbCapacityView', function() {
    return {
      restrict: 'A',
      template: '{{capacity_view_description}}',
      link: function(scope, el, attrs) {
        var killWatch, ticket_type;
        ticket_type = attrs.ticketTypeSingular || "ticket";
        return killWatch = scope.$watch(attrs.bbCapacityView, function(item) {
          var num_spaces_plural, spaces_left_plural;
          if (item) {
            killWatch();
            num_spaces_plural = item.num_spaces > 1 ? "s" : "";
            spaces_left_plural = item.spaces_left > 1 ? "s" : "";
            switch (item.chain.capacity_view) {
              case "NUM_SPACES":
                return scope.capacity_view_description = scope.ticket_spaces = item.num_spaces + " " + ticket_type + num_spaces_plural;
              case "NUM_SPACES_LEFT":
                return scope.capacity_view_description = scope.ticket_spaces = item.spaces_left + " " + ticket_type + spaces_left_plural + " available";
              case "NUM_SPACES_AND_SPACES_LEFT":
                return scope.capacity_view_description = scope.ticket_spaces = item.spaces_left + " of " + item.num_spaces + " " + ticket_type + num_spaces_plural + " available";
            }
          }
        });
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB').directive('bbMemberLogin', function(PathSvc) {
    return {
      restrict: 'A',
      controller: 'MemberLogin',
      templateUrl: function(elem, attrs) {
        if (attrs.bbCustomLoginForm != null) {
          return PathSvc.directivePartial("_member_login_form");
        } else {
          return PathSvc.directivePartial("_member_login_schema_form");
        }
      }
    };
  });

  angular.module('BB.Controllers').controller('MemberLogin', function($scope, $log, $rootScope, $templateCache, $q, halClient, BBModel, $sessionStorage, $window, AlertService, LoginService, ValidatorService) {
    $scope.login_form = {};
    $scope.validator = ValidatorService;
    $rootScope.connection_started.then(function() {
      if (LoginService.checkLogin()) {
        $scope.setClient($rootScope.member);
        if ($scope.bb.destination) {
          return $scope.redirectTo($scope.bb.destination);
        } else {
          $scope.setLoaded($scope);
          return $scope.decideNextPage();
        }
      } else {
        return halClient.$get($scope.bb.api_url + "/api/v1").then(function(root) {
          return root.$get("new_login").then(function(new_login) {
            $scope.form = new_login.form;
            return $scope.schema = new_login.schema;
          }, function(err) {
            return console.log('err ', err);
          });
        }, function(err) {
          return console.log('err ', err);
        });
      }
    });
    $scope.submit = function(form) {
      form['role'] = 'member';
      return $scope.company.$post('login', {}, form).then(function(login) {
        if (login.$has('members')) {
          return login.$get('members').then(function(members) {
            return $scope.handleLogin(members[0]);
          });
        } else if (login.$has('member')) {
          return login.$get('member').then(function(member) {
            return $scope.handleLogin(member);
          });
        }
      }, function(err) {
        if (err.data.error === "Account has been disabled") {
          return AlertService.raise('ACCOUNT_DISABLED');
        } else {
          return AlertService.raise('LOGIN_FAILED');
        }
      });
    };
    return $scope.handleLogin = function(member) {
      member = LoginService.setLogin(member, $scope.login_form.persist_login);
      $scope.setClient(member);
      if ($scope.bb.destination) {
        return $scope.redirectTo($scope.bb.destination);
      } else {
        $scope.skipThisStep();
        return $scope.decideNextPage();
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbMonthPicker', function(PathSvc, $timeout) {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      require: ['^?bbEvents', '^?bbMultiCompanyEvents'],
      templateUrl: function(element, attrs) {
        return PathSvc.directivePartial("_month_picker");
      },
      link: function(scope, el, attrs) {
        var stopWatch;
        scope.picker_settings = scope.$eval(attrs.bbMonthPicker) || {};
        scope.picker_settings.months_to_show = scope.picker_settings.months_to_show || 3;
        return stopWatch = scope.$watch(attrs.dayData, function(dates) {
          if (dates) {
            scope.processDates(dates);
            return stopWatch();
          }
        });
      },
      controller: function($scope) {
        $scope.processDates = function(dates) {
          var cur_month, d, date, datehash, day, day_data, diff, i, j, k, l, last_date, len, m, month, months, ref, w, week;
          datehash = {};
          for (i = 0, len = dates.length; i < len; i++) {
            date = dates[i];
            datehash[date.date.format("DDMMYY")] = date;
            if (!$scope.first_available_day && date.spaces > 0) {
              $scope.first_available_day = date.date;
            }
          }
          if ($scope.picker_settings.start_at_first_available_day) {
            cur_month = $scope.first_available_day.clone().startOf('month');
          } else {
            cur_month = moment().startOf('month');
          }
          last_date = _.last(dates);
          diff = last_date.date.diff(cur_month, 'months');
          diff = diff > 0 ? diff + 1 : 1;
          $scope.num_months = $scope.picker_settings && $scope.picker_settings.months ? $scope.picker_settings.months : diff;
          months = [];
          for (m = j = 1, ref = $scope.num_months; 1 <= ref ? j <= ref : j >= ref; m = 1 <= ref ? ++j : --j) {
            date = cur_month.clone().startOf('week');
            month = {
              weeks: []
            };
            month.index = m - 1;
            for (w = k = 1; k <= 6; w = ++k) {
              week = {
                days: []
              };
              for (d = l = 1; l <= 7; d = ++l) {
                if (date.isSame(date.clone().startOf('month'), 'day') && !month.start_date) {
                  month.start_date = date.clone();
                }
                day_data = datehash[date.format("DDMMYY")];
                day = {
                  date: date.clone(),
                  data: day_data,
                  available: day_data && day_data.spaces && day_data.spaces > 0,
                  today: moment().isSame(date, 'day'),
                  past: date.isBefore(moment(), 'day'),
                  disabled: !month.start_date || !date.isSame(month.start_date, 'month')
                };
                week.days.push(day);
                if ($scope.selected_date && day.date.isSame($scope.selected_date, 'day')) {
                  day.selected = true;
                  $scope.selected_day = day;
                }
                date.add(1, 'day');
              }
              month.weeks.push(week);
            }
            months.push(month);
            cur_month.add(1, 'month');
          }
          $scope.months = months;
          return $scope.slick_config = {
            nextArrow: ".month-next",
            prevArrow: ".month-prev",
            slidesToShow: $scope.months.length >= $scope.picker_settings.months_to_show ? $scope.picker_settings.months_to_show : $scope.months.length,
            infinite: false,
            responsive: [
              {
                breakpoint: 1200,
                settings: {
                  slidesToShow: $scope.months.length >= 2 ? 2 : $scope.months.length
                }
              }, {
                breakpoint: 992,
                settings: {
                  slidesToShow: 1
                }
              }
            ],
            method: {},
            event: {
              init: function(event, slick) {
                return $timeout(function() {
                  var len1, n, ref1, results;
                  if ($scope.selected_day != null) {
                    ref1 = $scope.months;
                    results = [];
                    for (n = 0, len1 = ref1.length; n < len1; n++) {
                      m = ref1[n];
                      if (m.start_date.month() === $scope.selected_day.date.month()) {
                        results.push(slick.slickGoTo(m.index));
                      } else {
                        results.push(void 0);
                      }
                    }
                    return results;
                  }
                });
              }
            }
          };
        };
        $scope.$on('event_list_filter_date:changed', function(event, date) {
          if ($scope.selected_day) {
            return $scope.selected_day.selected = false;
          }
        });
        return $scope.toggleDay = function(day) {
          if (!day || day.data && (day.data.spaces === 0 || day.disabled || !day.available) || (!day.data && !day._d)) {
            return;
          }
          if ($scope.selected_day) {
            $scope.selected_day.selected = false;
          }
          if (!$scope.selected_day || ($scope.selected_day && !day.date.isSame($scope.selected_day.date, 'day'))) {
            day.selected = true;
            $scope.selected_day = day;
          }
          return $scope.showDay(day.date);
        };
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('ngOptions', function($sniffer, $rootScope) {
    return {
      restrict: 'A',
      link: function(scope, el, attrs) {
        var size;
        size = parseInt(attrs['size'], 10);
        if (!isNaN(size) && size > 1 && $sniffer.msie) {
          return $rootScope.$on('loading:finished', function() {
            el.focus();
            return $('body').focus();
          });
        }
      }
    };
  });

}).call(this);

(function() {
  'use strict';
  var app;

  app = angular.module('BB.Directives');

  app.directive('script', function($compile, halClient) {
    return {
      transclude: false,
      restrict: 'E',
      link: function(scope, element, attrs) {
        var body, json, res;
        if (attrs.type === 'text/hal-object') {
          body = element[0].innerText;
          json = $bbug.parseJSON(body);
          return res = halClient.$parse(json);
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbPaymentButton', function($compile, $sce, $http, $templateCache, $q, $log, TemplateSvc) {
    var getButtonFormTemplate, getTemplate, linker, setClassAndValue;
    getTemplate = function(type, scope) {
      switch (type) {
        case 'button_form':
          return getButtonFormTemplate(scope);
        case 'page':
          return TemplateSvc.get("payment.html");
        case 'location':
          return "<a href='{{payment_link}}'>{{label}}</a>";
        default:
          return "";
      }
    };
    getButtonFormTemplate = function(scope) {
      var src;
      src = $sce.parseAsResourceUrl("'" + scope.payment_link + "'")();
      return $http.get(src, {}).then(function(response) {
        return response.data;
      });
    };
    setClassAndValue = function(scope, element, attributes) {
      var c, i, inputs, j, len, main_tag, ref, results;
      switch (scope.link_type) {
        case 'button_form':
          inputs = element.find("input");
          main_tag = ((function() {
            var j, len, results;
            results = [];
            for (j = 0, len = inputs.length; j < len; j++) {
              i = inputs[j];
              if ($(i).attr('type') === 'submit') {
                results.push(i);
              }
            }
            return results;
          })())[0];
          if (attributes.value) {
            $(main_tag).attr('value', attributes.value);
          }
          break;
        case 'page':
        case 'location':
          main_tag = element.find("a")[0];
      }
      if (attributes["class"]) {
        ref = attributes["class"].split(" ");
        results = [];
        for (j = 0, len = ref.length; j < len; j++) {
          c = ref[j];
          $(main_tag).addClass(c);
          results.push($(element).removeClass(c));
        }
        return results;
      }
    };
    linker = function(scope, element, attributes) {
      return scope.$watch('total', function() {
        var url;
        scope.bb.payment_status = "pending";
        scope.bb.total = scope.total;
        scope.link_type = scope.total.$link('new_payment').type;
        scope.label = attributes.value || "Make Payment";
        scope.payment_link = scope.total.$href('new_payment');
        url = scope.total.$href('new_payment');
        return $q.when(getTemplate(scope.link_type, scope)).then(function(template) {
          element.html(template).show();
          $compile(element.contents())(scope);
          return setClassAndValue(scope, element, attributes);
        }, function(err) {
          $log.warn(err.data);
          return element.remove();
        });
      });
    };
    return {
      restrict: 'EA',
      replace: true,
      scope: {
        total: '=',
        bb: '=',
        decideNextPage: '='
      },
      link: linker
    };
  });

  angular.module('BB.Directives').directive('bbPaypalExpressButton', function($compile, $sce, $http, $templateCache, $q, $log, $window, UriTemplate) {
    var linker;
    linker = function(scope, element, attributes) {
      var paypalOptions, total;
      total = scope.total;
      paypalOptions = scope.paypalOptions;
      scope.href = new UriTemplate(total.$link('paypal_express').href).fillFromObject(paypalOptions);
      return scope.showLoader = function() {
        if (scope.notLoaded) {
          return scope.notLoaded(scope);
        }
      };
    };
    return {
      restrict: 'EA',
      replace: true,
      template: "<a ng-href=\"{{href}}\" ng-click=\"showLoader()\">Pay</a>",
      scope: {
        total: '=',
        bb: '=',
        decideNextPage: '=',
        paypalOptions: '=bbPaypalExpressButton',
        notLoaded: '='
      },
      link: linker
    };
  });

}).call(this);

(function() {
  'use strict';
  var app;

  app = angular.module('BB.Directives');

  app.directive('bbPaypal', function(PathSvc) {
    return {
      restrict: 'A',
      replace: true,
      scope: {
        ppDetails: "=bbPaypal"
      },
      templateUrl: PathSvc.directivePartial("paypal_button"),
      link: function(scope, element, attrs) {
        var keys;
        scope.inputs = [];
        if (!scope.ppDetails) {
          return;
        }
        keys = _.keys(scope.ppDetails);
        return _.each(keys, function(keyName) {
          var obj;
          obj = {
            name: keyName,
            value: scope.ppDetails[keyName]
          };
          return scope.inputs.push(obj);
        });
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('pricepicker', function() {
    var controller, link;
    controller = function($scope) {
      return $scope.$watch('price', function(price) {
        if (price != null) {
          return $scope.updateModel(price);
        }
      });
    };
    link = function(scope, element, attrs, ngModel) {
      ngModel.$render = function() {
        if (ngModel.$viewValue) {
          return scope.price = ngModel.$viewValue;
        }
      };
      return scope.updateModel = function(value) {
        return ngModel.$setViewValue(value);
      };
    };
    return {
      require: 'ngModel',
      link: link,
      controller: controller,
      scope: {
        currency: '@'
      },
      template: "<span>{{0 | currency: currency | limitTo: 1}}</span>\n<input type=\"number\" ng-model=\"price\" class=\"form-control\" step=\"0.01\">"
    };
  });

}).call(this);

(function() {
  angular.module("BB.Directives").directive('scoped', function($document, $timeout) {
    var scopeIt;
    this.compat = (function() {
      var DOMRules, DOMStyle, changeSelectorTextAllowed, check, e, error, scopeSupported, testSheet, testStyle;
      check = document.createElement('style');
      if (typeof check.sheet !== 'undefined') {
        DOMStyle = 'sheet';
      } else if (typeof check.getSheet !== 'undefined') {
        DOMStyle = 'getSheet';
      } else {
        DOMStyle = 'styleSheet';
      }
      scopeSupported = void 0 !== check.scoped;
      document.body.appendChild(check);
      testSheet = check[DOMStyle];
      if (testSheet.addRule) {
        testSheet.addRule('c', 'blink');
      } else {
        testSheet.insertRule('c{}', 0);
      }
      DOMRules = testSheet.rules ? 'rules' : 'cssRules';
      testStyle = testSheet[DOMRules][0];
      try {
        testStyle.selectorText = 'd';
      } catch (error) {
        e = error;
      }
      changeSelectorTextAllowed = 'd' === testStyle.selectorText.toLowerCase();
      check.parentNode.removeChild(check);
      return {
        scopeSupported: scopeSupported,
        rules: DOMRules,
        sheet: DOMStyle,
        changeSelectorTextAllowed: changeSelectorTextAllowed
      };
    })();
    scopeIt = (function(_this) {
      return function(element) {
        var allRules, glue, id, idCounter, index, par, results, rule, selector, sheet, styleNode, styleRule;
        styleNode = element[0];
        idCounter = 0;
        sheet = styleNode[_this.compat.sheet];
        if (!sheet) {
          return;
        }
        allRules = sheet[_this.compat.rules];
        par = styleNode.parentNode;
        id = par.id || (par.id = 'scopedByScopedPolyfill_' + ++idCounter);
        glue = '';
        index = allRules.length || 0;
        while (par) {
          if (par.id) {
            glue = '#' + par.id + ' ' + glue;
          }
          par = par.parentNode;
        }
        results = [];
        while (index--) {
          rule = allRules[index];
          if (rule.selectorText) {
            if (!rule.selectorText.match(new RegExp(glue))) {
              selector = glue + ' ' + rule.selectorText.split(',').join(', ' + glue);
              selector = selector.replace(/[\ ]+:root/gi, '');
              if (_this.compat.changeSelectorTextAllowed) {
                results.push(rule.selectorText = selector);
              } else {
                if (!rule.type || 1 === rule.type) {
                  styleRule = rule.style.cssText;
                  if (styleRule) {
                    if (sheet.removeRule) {
                      sheet.removeRule(index);
                    } else {
                      sheet.deleteRule(index);
                    }
                    if (sheet.addRule) {
                      results.push(sheet.addRule(selector, styleRule));
                    } else {
                      results.push(sheet.insertRule(selector + '{' + styleRule + '}', index));
                    }
                  } else {
                    results.push(void 0);
                  }
                } else {
                  results.push(void 0);
                }
              }
            } else {
              results.push(void 0);
            }
          } else {
            results.push(void 0);
          }
        }
        return results;
      };
    })(this);
    return {
      restrict: 'A',
      link: function(scope, element, attrs) {
        scope.scopeSupported = this.compat.scopeSupported;
        if (!this.compat.scopeSupported) {
          return $timeout(function() {
            return scopeIt(element);
          });
        }
      },
      controller: function($scope, $element, $timeout) {
        if (!$scope.scopeSupported) {
          this.updateCss = function() {
            return $timeout(function() {
              return scopeIt($element);
            });
          };
        }
      }
    };
  });

}).call(this);

(function() {
  var app;

  app = angular.module('BB.Directives');

  app.directive('bbDisplayMode', function($compile, $window, $bbug) {
    return {
      transclude: false,
      restrict: 'A',
      template: '<span class="visible-xs"></span><span class="visible-sm"></span><span class="visible-md"></span><span class="visible-lg"></span>',
      link: function(scope, elem, attrs) {
        var getCurrentSize, isVisible, markers, t, update;
        markers = elem.find('span');
        $bbug(elem).addClass("bb-display-mode");
        scope.display = {};
        isVisible = function(element) {
          return element && element.style.display !== 'none' && element.offsetWidth && element.offsetHeight;
        };
        getCurrentSize = function() {
          var element, i, len;
          for (i = 0, len = markers.length; i < len; i++) {
            element = markers[i];
            if (isVisible(element)) {
              return element.className.slice(8, 11);
            }
            scope.display = {};
            scope.display[element.className.slice(8, 11)] = true;
            return false;
          }
        };
        update = (function(_this) {
          return function() {
            var nsize;
            nsize = getCurrentSize();
            if (nsize !== _this.currentSize) {
              _this.currentSize = nsize;
              scope.display.xs = false;
              scope.display.sm = false;
              scope.display.md = false;
              scope.display.lg = false;
              scope.display.not_xs = true;
              scope.display.not_sm = true;
              scope.display.not_md = true;
              scope.display.not_lg = true;
              scope.display[nsize] = true;
              scope.display["not_" + nsize] = false;
              return true;
            }
            return false;
          };
        })(this);
        t = null;
        angular.element($window).bind('resize', (function(_this) {
          return function() {
            window.clearTimeout(t);
            return t = setTimeout(function() {
              if (update()) {
                return scope.$apply();
              }
            }, 50);
          };
        })(this));
        return angular.element($window).bind('load', (function(_this) {
          return function() {
            if (update()) {
              return scope.$apply();
            }
          };
        })(this));
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('bbToggleEdit', function($compile, $window, $document) {
    return {
      restrict: 'AE',
      link: function(scope, element, attr) {
        scope.editing = false;
        element.on('dblclick', (function(_this) {
          return function(event) {
            return scope.$apply(function() {
              return scope.editing = true;
            });
          };
        })(this));
        $document.on('click', (function(_this) {
          return function() {
            if (!element.is(':hover')) {
              return scope.$apply(function() {
                return scope.editing = false;
              });
            }
          };
        })(this));
        return true;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Directives').directive('popover', function() {
    var openElement, openScope;
    openElement = null;
    openScope = null;
    $('div[ng-controller="BBCtrl"]').off('.bbtooltip').on('click.bbtooltip', function(e) {
      var target;
      target = $(e.target).closest('[popover]')[0];
      if (!target && openElement && openScope) {
        $(openElement).next('.popover').remove();
        openScope.tt_isOpen = false;
      }
      return true;
    });
    return {
      restrict: 'EA',
      priority: -1000,
      link: function(scope, element) {
        element.on('click.bbtooltip', function(e) {
          if (openElement === $(e.target).closest('[popover]')[0]) {
            e.preventDefault();
            return;
          }
          if (openElement && openScope) {
            $(openElement).next('.popover').remove();
            openScope.tt_isOpen = false;
          }
          openElement = element[0];
          return openScope = scope;
        });
        return scope.$on('$destroy', function() {
          return $(element).off('.bbtooltip');
        });
      }
    };
  });

}).call(this);

(function (angular) {
  'use strict';

  /* Directives */
  var app = angular.module('BB.Directives');

  app.directive('appVersion', function(version) {
    return function(scope, elm, attrs) {
      elm.text(version);
    };
  });
}(window.angular));

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Address
  *
  * @description
  * Representation of an Address Object
  *
  * @property {string} address1 First line of the address 
  * @property {string} address2 Second line of the address 
  * @property {string} address3 Third line of the address 
  * @property {string} address4 Fourth line of the address 
  * @property {string} address5 Fifth line of the address 
  * @property {string} postcode The Postcode/Zipcode
  * @property {string} country The country
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("AddressModel", function($q, BBModel, BaseModel) {
    var Address;
    return Address = (function(superClass) {
      extend(Address, superClass);

      function Address(data) {
        Address.__super__.constructor.call(this, data);
        if (!this.map_url || this.map_url === "") {
          if (this.lat && this.long) {
            this.map_url = "https://www.google.com/maps/@" + this.lat + "," + this.long + ",17z";
          }
        }
      }


      /***
      * @ngdoc method
      * @name addressSingleLine
      * @methodOf BB.Models:Address
      * @description
      * Get a the address as a single comma sepeated line
      *
      * @returns {string} The returned address
       */

      Address.prototype.addressSingleLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        if (this.address2 && str.length > 0) {
          str += ", ";
        }
        if (this.address2) {
          str += this.address2;
        }
        if (this.address3 && str.length > 0) {
          str += ", ";
        }
        if (this.address3) {
          str += this.address3;
        }
        if (this.address4 && str.length > 0) {
          str += ", ";
        }
        if (this.address4) {
          str += this.address4;
        }
        if (this.address5 && str.length > 0) {
          str += ", ";
        }
        if (this.address5) {
          str += this.address5;
        }
        if (this.postcode && str.length > 0) {
          str += ", ";
        }
        if (this.postcode) {
          str += this.postcode;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name hasAddress
      * @methodOf BB.Models:Address
      * @description
      * Checks if this is considered a valid address
      *
      * @returns {boolean} If this is a valid address
       */

      Address.prototype.hasAddress = function() {
        return this.address1 || this.address2 || this.postcode;
      };


      /***
      * @ngdoc method
      * @name addressCsvLine
      * @methodOf BB.Models:Address
      * @description
      * Get all address fields as a single comma sepeated line - suitable for csv export
      *
      * @returns {string} The returned address
       */

      Address.prototype.addressCsvLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        str += ", ";
        if (this.address2) {
          str += this.address2;
        }
        str += ", ";
        if (this.address3) {
          str += this.address3;
        }
        str += ", ";
        if (this.address4) {
          str += this.address4;
        }
        str += ", ";
        if (this.address5) {
          str += this.address5;
        }
        str += ", ";
        if (this.postcode) {
          str += this.postcode;
        }
        str += ", ";
        if (this.country) {
          str += this.country;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name addressMultiLine
      * @methodOf BB.Models:Address
      * @description
      * Get a the address as multiple lines with line feeds
      *
      * @returns {string} The returned address
       */

      Address.prototype.addressMultiLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        if (this.address2 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address2) {
          str += this.address2;
        }
        if (this.address3 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address3) {
          str += this.address3;
        }
        if (this.address4 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address4) {
          str += this.address4;
        }
        if (this.address5 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address5) {
          str += this.address5;
        }
        if (this.postcode && str.length > 0) {
          str += "<br/>";
        }
        if (this.postcode) {
          str += this.postcode;
        }
        return str;
      };

      return Address;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Affiliate
  *
  * @description
  * Representation of an Affiliate Object
  *
  * @property {string} affiliate_id Id of the affiliated company
  * @property {string} reference The reference of the affiliated company
  * @property {integer} country_code Country code of the affiliated company
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("AffiliateModel", function($q, BBModel, BaseModel, halClient, $rootScope) {
    var Affiliate;
    return Affiliate = (function(superClass) {
      extend(Affiliate, superClass);

      function Affiliate(data) {
        Affiliate.__super__.constructor.call(this, data);
        this.test = 1;
      }


      /***
      * @ngdoc method
      * @name getCompanyByRef
      * @methodOf BB.Models:Affiliate
      * @description
      * Find a company in according to reference
      *
      * @param {string} ref A reference to find a company based on it
      *
      * @returns {promise} A promise for the company reference
       */

      Affiliate.prototype.getCompanyByRef = function(ref) {
        var defer, href, prms, uri;
        prms = {
          id: this.cookie,
          reference: ref
        };
        href = $rootScope.bb.api_url + "/api/v1/affiliates/{id}/companies/{reference}";
        uri = new UriTemplate(href).fillFromObject(prms || {});
        defer = $q.defer();
        halClient.$get(uri, {}).then(function(company) {
          if (company) {
            return defer.resolve(new BBModel.Company(company));
          } else {
            return defer.reject('No company for ref ' + ref);
          }
        }, function(err) {
          console.log('err ', err);
          return defer.reject(err);
        });
        return defer.promise;
      };

      return Affiliate;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Answer
  *
  * @description
  * Representation of an Answer Object
  *
  * @property {string} question The question that the answer belongs to
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("AnswerModel", function($q, BBModel, BaseModel, $bbug) {
    var Answer;
    return Answer = (function(superClass) {
      extend(Answer, superClass);

      function Answer(data) {
        Answer.__super__.constructor.call(this, data);
      }


      /***
      * @ngdoc method
      * @name getQuestion
      * @methodOf BB.Models:Answer
      * @description
      * Build an array of questions 
      *
      * @returns {promise} A promise for the question/s
       */

      Answer.prototype.getQuestion = function() {
        var defer;
        defer = $q.defer();
        if (this.question) {
          defer.resolve(this.question);
        }
        if (this._data.$has('question')) {
          this._data.$get('question').then((function(_this) {
            return function(question) {
              _this.question = question;
              return defer.resolve(_this.question);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      return Answer;

    })(BaseModel);
  });

}).call(this);

(function() {
  angular.module('BB.Models').service("BBModel", function($q, $injector) {
    var admin_models, afuncs, fn, fn1, fn2, fn3, funcs, i, j, k, l, len, len1, len2, len3, member_models, mfuncs, model, models, pfuncs, purchase_models;
    models = ['Address', 'Answer', 'Affiliate', 'Basket', 'BasketItem', 'BookableItem', 'Category', 'Client', 'ClientDetails', 'Company', 'CompanySettings', 'Day', 'Event', 'EventChain', 'EventGroup', 'EventTicket', 'EventSequence', 'ItemDetails', 'Person', 'PurchaseItem', 'PurchaseTotal', 'Question', 'Resource', 'Service', 'Slot', 'Space', 'Clinic', 'SurveyQuestion', 'TimeSlot', 'BusinessQuestion', 'Image', 'Deal', 'PrePaidBooking', 'MembershipLevel', 'Product', 'BBCollection', 'ExternalPurchase', 'PackageItem', 'BulkPurchase'];
    funcs = {};
    fn = (function(_this) {
      return function(model) {
        return funcs[model] = function(p1, p2) {
          return new ($injector.get(model + "Model"))(p1, p2);
        };
      };
    })(this);
    for (i = 0, len = models.length; i < len; i++) {
      model = models[i];
      fn(model);
    }
    purchase_models = ['Booking', 'Total', 'CourseBooking'];
    pfuncs = {};
    fn1 = (function(_this) {
      return function(model) {
        return pfuncs[model] = function(init) {
          return new ($injector.get("Purchase." + model + "Model"))(init);
        };
      };
    })(this);
    for (j = 0, len1 = purchase_models.length; j < len1; j++) {
      model = purchase_models[j];
      fn1(model);
    }
    funcs['Purchase'] = pfuncs;
    member_models = ['Member', 'Booking', 'PrePaidBooking', 'Wallet', 'WalletLog', 'Purchase', 'PurchaseItem', 'WalletPurchaseBand'];
    mfuncs = {};
    fn2 = (function(_this) {
      return function(model) {
        return mfuncs[model] = function(init) {
          return new ($injector.get("Member." + model + "Model"))(init);
        };
      };
    })(this);
    for (k = 0, len2 = member_models.length; k < len2; k++) {
      model = member_models[k];
      fn2(model);
    }
    funcs['Member'] = mfuncs;
    admin_models = ['Booking', 'Slot', 'User', 'Administrator', 'Schedule', 'Address', 'Resource', 'Person', 'Service', 'Login', 'EventChain', 'EventGroup', 'Event', 'Queuer', 'ClientQueue', 'Clinic'];
    afuncs = {};
    fn3 = (function(_this) {
      return function(model) {
        return afuncs[model] = function(init) {
          return new ($injector.get("Admin." + model + "Model"))(init);
        };
      };
    })(this);
    for (l = 0, len3 = admin_models.length; l < len3; l++) {
      model = admin_models[l];
      fn3(model);
    }
    funcs['Admin'] = afuncs;
    return funcs;
  });

  angular.module('BB.Models').service("BaseModel", function($q, $injector, $rootScope, $timeout) {
    var Base;
    return Base = (function() {
      function Base(data) {
        this.deleted = false;
        this.updateModel(data);
      }

      Base.prototype.updateModel = function(data) {
        var link, links, m, n, name, obj, results;
        if (data) {
          this._data = data;
        }
        if (data) {
          for (n in data) {
            m = data[n];
            this[n] = m;
          }
        }
        if (this._data && this._data.$href) {
          this.self = this._data.$href("self");
          links = this.$links();
          this.__linkedData = {};
          this.__linkedPromises = {};
          results = [];
          for (link in links) {
            obj = links[link];
            name = this._snakeToCamel("get_" + link);
            results.push((function(_this) {
              return function(link, obj, name) {
                if (!_this[name]) {
                  _this[name] = function() {
                    return this.$buildOject(link);
                  };
                }
                if (!_this[name + "Promise"]) {
                  return _this[name + "Promise"] = function() {
                    return this.$buildOjectPromise(link);
                  };
                }
              };
            })(this)(link, obj, name));
          }
          return results;
        }
      };

      Base.prototype._snakeToCamel = function(s) {
        return s.replace(/(\_\w)/g, function(m) {
          return m[1].toUpperCase();
        });
      };

      Base.prototype.$buildOject = function(link) {
        if (this.__linkedData[link]) {
          return this.__linkedData[link];
        }
        this.$buildOjectPromise(link).then((function(_this) {
          return function(ans) {
            _this.__linkedData[link] = ans;
            return $timeout(function() {
              return _this.__linkedData[link] = ans;
            });
          };
        })(this));
        return null;
      };

      Base.prototype.$buildOjectPromise = function(link) {
        var prom;
        if (this.__linkedPromises[link]) {
          return this.__linkedPromises[link];
        }
        prom = $q.defer();
        this.__linkedPromises[link] = prom.promise;
        this.$get(link).then((function(_this) {
          return function(res) {
            var inj;
            inj = $injector.get('BB.Service.' + link);
            if (inj) {
              if (inj.promise) {
                return inj.unwrap(res).then(function(ans) {
                  return prom.resolve(ans);
                }, function(err) {
                  return prom.reject(err);
                });
              } else {
                return prom.resolve(inj.unwrap(res));
              }
            } else {
              return prom.resolve(res);
            }
          };
        })(this), function(err) {
          return prom.reject(err);
        });
        return this.__linkedPromises[link];
      };

      Base.prototype.get = function(ikey) {
        if (!this._data) {
          return null;
        }
        return this._data[ikey];
      };

      Base.prototype.set = function(ikey, value) {
        if (!this._data) {
          return null;
        }
        return this._data[ikey] = value;
      };

      Base.prototype.$href = function(rel, params) {
        if (this._data) {
          return this._data.$href(rel, params);
        }
      };

      Base.prototype.$has = function(rel) {
        if (this._data) {
          return this._data.$has(rel);
        }
      };

      Base.prototype.$flush = function(rel, params) {
        if (this._data) {
          return this._data.$href(rel, params);
        }
      };

      Base.prototype.$get = function(rel, params) {
        if (this._data) {
          return this._data.$get(rel, params);
        }
      };

      Base.prototype.$post = function(rel, params, dat) {
        if (this._data) {
          return this._data.$post(rel, params, dat);
        }
      };

      Base.prototype.$put = function(rel, params, dat) {
        if (this._data) {
          return this._data.$put(rel, params, dat);
        }
      };

      Base.prototype.$patch = function(rel, params, dat) {
        if (this._data) {
          return this._data.$patch(rel, params, dat);
        }
      };

      Base.prototype.$del = function(rel, params) {
        if (this._data) {
          return this._data.$del(rel, params);
        }
      };

      Base.prototype.$links = function() {
        if (this._data) {
          return this._data.$links();
        }
      };

      Base.prototype.$toStore = function() {
        if (this._data) {
          return this._data.$toStore();
        }
      };

      return Base;

    })();
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Basket
  *
  * @description
  * Representation of an Basket Object
  *
  * @property {integer} company_id Company id that the basket belongs to 
  * @property {integer} total_price Total price of the basket
  * @property {integer} total_due_price Total price of the basket after applying discounts
  * @property {array} items Array of items that are in the basket
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BasketModel", function($q, BBModel, BaseModel) {
    var Basket;
    return Basket = (function(superClass) {
      extend(Basket, superClass);

      function Basket(data, scope) {
        if (scope && scope.isAdmin) {
          this.is_admin = scope.isAdmin;
        } else {
          this.is_admin = false;
        }
        if ((scope != null) && scope.parent_client) {
          this.parent_client_id = scope.parent_client.id;
        }
        this.items = [];
        Basket.__super__.constructor.call(this, data);
      }


      /***
      * @ngdoc method
      * @name addItem
      * @methodOf BB.Models:Basket
      * @description
      * Adds an item to the items array of the basket
      *
       */

      Basket.prototype.addItem = function(item) {
        var i, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i === item) {
            return;
          }
          if (i.id && item.id && i.id === item.id) {
            return;
          }
        }
        return this.items.push(item);
      };


      /***
      * @ngdoc method
      * @name clear
      * @methodOf BB.Models:Basket
      * @description
      * Empty items array
      *
       */

      Basket.prototype.clear = function() {
        return this.items = [];
      };


      /***
      * @ngdoc method
      * @name clearItem
      * @methodOf BB.Models:Basket
      * @description
      * Remove a given item from the items array
      *
       */

      Basket.prototype.clearItem = function(item) {
        return this.items = this.items.filter(function(i) {
          return i !== item;
        });
      };


      /***
      * @ngdoc method
      * @name readyToCheckout
      * @methodOf BB.Models:Basket
      * @description
      * Checks if items array is not empty, so it's ready for the checkout
      *
      * @returns {boolean} If items array is not empty
       */

      Basket.prototype.readyToCheckout = function() {
        if (this.items.length > 0) {
          return true;
        } else {
          return false;
        }
      };


      /***
      * @ngdoc method
      * @name timeItems
      * @methodOf BB.Models:Basket
      * @description
      * Build an array of time items (i.e. event and appointment bookings)
      *
      * @returns {array}
       */

      Basket.prototype.timeItems = function() {
        var i, j, len, ref, titems;
        titems = [];
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i.isTimeItem()) {
            titems.push(i);
          }
        }
        return titems;
      };


      /***
      * @ngdoc method
      * @name hasTimeItems
      * @methodOf BB.Models:Basket
      * @description
      * Indicates if the basket contains time items (i.e. event and appointment bookings)
      *
      * @returns {boolean}
       */

      Basket.prototype.hasTimeItems = function() {
        var i, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i.isTimeItem()) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name basketItems
      * @methodOf BB.Models:Basket
      * @description
      * Gets all BasketItem's that are not coupons
      *
      * @returns {array} array of basket items
       */

      Basket.prototype.basketItems = function() {
        var bitems, i, j, len, ref;
        bitems = [];
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (!i.is_coupon) {
            bitems.push(i);
          }
        }
        return bitems;
      };


      /***
      * @ngdoc method
      * @name externalPurchaseItems
      * @methodOf BB.Models:Basket
      * @description
      * Gets all external purchases in the basket
      *
      * @returns {array} array of external purchases
       */

      Basket.prototype.externalPurchaseItems = function() {
        var eitems, i, j, len, ref;
        eitems = [];
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i.isExternalPurchase()) {
            eitems.push(i);
          }
        }
        return eitems;
      };


      /***
      * @ngdoc method
      * @name couponItems
      * @methodOf BB.Models:Basket
      * @description
      * Build an array of items that are coupons
      *
      * @returns {array} the newly build array of coupon items
       */

      Basket.prototype.couponItems = function() {
        var citems, i, j, len, ref;
        citems = [];
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i.is_coupon) {
            citems.push(i);
          }
        }
        return citems;
      };


      /***
      * @ngdoc method
      * @name removeCoupons
      * @methodOf BB.Models:Basket
      * @description
      * Remove coupon items from the items array
      *
      * @returns {array} the items array after removing items that are coupons
       */

      Basket.prototype.removeCoupons = function() {
        return this.items = _.reject(this.items, function(x) {
          return x.is_coupon;
        });
      };


      /***
      * @ngdoc method
      * @name setSettings
      * @methodOf BB.Models:Basket
      * @description
      * Extend the settings with the set param passed to the function
      *
      * @returns {object} settings object
       */

      Basket.prototype.setSettings = function(set) {
        if (!set) {
          return;
        }
        this.settings || (this.settings = {});
        return $.extend(this.settings, set);
      };


      /***
      * @ngdoc method
      * @name setClient
      * @methodOf BB.Models:Basket
      * @description
      * Set the client
      *
      * @returns {object} client object
       */

      Basket.prototype.setClient = function(client) {
        return this.client = client;
      };


      /***
      * @ngdoc method
      * @name setClientDetails
      * @methodOf BB.Models:Basket
      * @description
      * Set client details
      *
      * @returns {object} client details
       */

      Basket.prototype.setClientDetails = function(client_details) {
        return this.client_details = new BBModel.PurchaseItem(client_details);
      };


      /***
      * @ngdoc method
      * @name getPostData
      * @methodOf BB.Models:Basket
      * @description
      * Build an array with details for every item in items array
      *
      * @returns {array} newly created details array
       */

      Basket.prototype.getPostData = function() {
        var item, j, len, post, ref;
        post = {
          client: this.client.getPostData(),
          settings: this.settings,
          reference: this.reference
        };
        post.is_admin = this.is_admin;
        post.parent_client_id = this.parent_client_id;
        post.take_from_wallet = this.take_from_wallet;
        post.items = [];
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          post.items.push(item.getPostData());
        }
        return post;
      };


      /***
      * @ngdoc method
      * @name dueTotal
      * @methodOf BB.Models:Basket
      * @description
      * Total price after checking every item if it is on the wait list
      *
      * @returns {integer} total
       */

      Basket.prototype.dueTotal = function() {
        var item, j, len, ref, total;
        total = this.totalPrice();
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.isWaitlist()) {
            total -= item.price;
          }
        }
        if (total < 0) {
          total = 0;
        }
        return total;
      };


      /***
      * @ngdoc method
      * @name length
      * @methodOf BB.Models:Basket
      * @description
      * Length of the items array
      *
      * @returns {integer} length
       */

      Basket.prototype.length = function() {
        return this.items.length;
      };


      /***
      * @ngdoc method
      * @name questionPrice
      * @methodOf BB.Models:Basket
      * @description
      * Calculates total question's price
      *
      * @returns {integer} question's price
       */

      Basket.prototype.questionPrice = function(options) {
        var item, j, len, price, ref, unready;
        unready = options && options.unready;
        price = 0;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if ((!item.ready && unready) || !unready) {
            price += item.questionPrice();
          }
        }
        return price;
      };


      /***
      * @ngdoc method
      * @name totalPrice
      * @methodOf BB.Models:Basket
      * @description
      * Calculates total price of the items after coupuns have been applied
      *
      * @returns {integer} total price
       */

      Basket.prototype.totalPrice = function(options) {
        var item, j, len, price, ref, unready;
        unready = options && options.unready;
        price = 0;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if ((!item.ready && unready) || !unready) {
            price += item.totalPrice();
          }
        }
        return price;
      };


      /***
      * @ngdoc method
      * @name updateTotalPrice
      * @methodOf BB.Models:Basket
      * @description
      * Update the total_price attribute using totalPrice method
      *
      * @returns {integer} the updated total_price variable
       */

      Basket.prototype.updateTotalPrice = function(options) {
        return this.total_price = this.totalPrice(options);
      };


      /***
      * @ngdoc method
      * @name fullPrice
      * @methodOf BB.Models:Basket
      * @description
      * Calculates full price of all items, before applying any coupons or deals
      *
      * @returns {integer} full price
       */

      Basket.prototype.fullPrice = function() {
        var item, j, len, price, ref;
        price = 0;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          price += item.fullPrice();
        }
        return price;
      };


      /***
      * @ngdoc method
      * @name hasCoupon
      * @methodOf BB.Models:Basket
      * @description
      * Checks if there is an item in items array, that is a coupon
      *
      * @returns {boolean} true or false if a coupon is found or not
       */

      Basket.prototype.hasCoupon = function() {
        var item, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.is_coupon) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name totalCoupons
      * @methodOf BB.Models:Basket
      * @description
      * Calculates the full discount for the basket
      *
      * @returns {integer} full discount
       */

      Basket.prototype.totalCoupons = function() {
        return this.fullPrice() - this.totalPrice() - this.totalDealPaid();
      };


      /***
      * @ngdoc method
      * @name totalDuration
      * @methodOf BB.Models:Basket
      * @description
      * Calculates total duration of all items in basket
      *
      * @returns {integer} total duration
       */

      Basket.prototype.totalDuration = function() {
        var duration, item, j, len, ref;
        duration = 0;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.service && item.service.listed_duration) {
            duration += item.service.listed_duration;
          }
        }
        return duration;
      };


      /***
      * @ngdoc method
      * @name containsDeal
      * @methodOf BB.Models:Basket
      * @description
      * Checks if there is an item in items array, that is a deal
      *
      * @returns {boolean} true or false depending if a deal was found or not
       */

      Basket.prototype.containsDeal = function() {
        var item, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.deal_id) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name hasDeal
      * @methodOf BB.Models:Basket
      * @description
      * Checks if there is any item in items array with a deal code
      *
      * @returns {boolean} true or false depending if a deal code was found or not
       */

      Basket.prototype.hasDeal = function() {
        var item, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.deal_codes && item.deal_codes.length > 0) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name getDealCodes
      * @methodOf BB.Models:Basket
      * @description
      * Builds an array of deal codes
      *
      * @returns {array} deal codes array
       */

      Basket.prototype.getDealCodes = function() {
        this.deals = this.items[0] && this.items[0].deal_codes ? this.items[0].deal_codes : [];
        return this.deals;
      };


      /***
      * @ngdoc method
      * @name totalDeals
      * @methodOf BB.Models:Basket
      * @description
      * Calculates the total amount of deal codes array
      *
      * @returns {integer} total amount of deals
       */

      Basket.prototype.totalDeals = function() {
        var deal, j, len, ref, value;
        value = 0;
        ref = this.getDealCodes();
        for (j = 0, len = ref.length; j < len; j++) {
          deal = ref[j];
          value += deal.value;
        }
        return value;
      };


      /***
      * @ngdoc method
      * @name totalDealPaid
      * @methodOf BB.Models:Basket
      * @description
      * Calculates the amount paid by gift certificates
      *
      * @returns {integer} amount paid by deals
       */

      Basket.prototype.totalDealPaid = function() {
        var item, j, len, ref, total_cert_paid;
        total_cert_paid = 0;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.certificate_paid) {
            total_cert_paid += item.certificate_paid;
          }
        }
        return total_cert_paid;
      };


      /***
      * @ngdoc method
      * @name remainingDealBalance
      * @methodOf BB.Models:Basket
      * @description
      * Calculates the difference between total deals amount and amount paid by deals
      *
      * @returns {integer} The remaining deal (gift certificate) balance
       */

      Basket.prototype.remainingDealBalance = function() {
        return this.totalDeals() - this.totalDealPaid();
      };


      /***
      * @ngdoc method
      * @name hasWaitlistItem
      * @methodOf BB.Models:Basket
      * @description
      * Checks if the basket contains an wait list event
      *
      * @returns {boolean} true or false
       */

      Basket.prototype.hasWaitlistItem = function() {
        var item, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.isWaitlist()) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name hasExternalPurchase
      * @methodOf BB.Models:Basket
      * @description
      * Checks if the basket contains an external purchase
      *
      * @returns {boolean} true or false
       */

      Basket.prototype.hasExternalPurchase = function() {
        var item, j, len, ref;
        ref = this.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.isExternalPurchase()) {
            return true;
          }
        }
        return false;
      };


      /***
      * @ngdoc method
      * @name useWallet
      * @methodOf BB.Models:Basket
      * @description
      * Indicates if a wallet should be used for payment
      *
      * @returns {boolean} true or false
       */

      Basket.prototype.useWallet = function(value, client) {
        if (client && client.$has('wallet') && value) {
          this.take_from_wallet = true;
          return true;
        } else {
          this.take_from_wallet = false;
          return false;
        }
      };

      return Basket;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:BasketItem
  *
  * @description
  * Representation of an BasketItem Object
  *
  * @property {integer} company_id Company id that the basket item belongs to
  * @property {integer} total_price Total price of the basket item
  * @property {integer} total_due_price Total price of the basket item after applying discounts
  * @property {array} items Arrays of items that are in the basket
  * @property {integer} event_id The event id of the basket item
  * @property {date} datetime Date and time of the event
  * @property {integer} status Status of the items
  *
   */
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BasketItemModel", function($q, $window, BBModel, BookableItemModel, BaseModel, $bbug) {
    var BasketItem;
    return BasketItem = (function(superClass) {
      extend(BasketItem, superClass);

      function BasketItem(data, bb) {
        this.fullPrice = bind(this.fullPrice, this);
        this.totalPrice = bind(this.totalPrice, this);
        this.getQty = bind(this.getQty, this);
        this.questionPrice = bind(this.questionPrice, this);
        var chain, comp, per, res, serv, t;
        BasketItem.__super__.constructor.call(this, data);
        this.ready = false;
        this.days_link = null;
        this.book_link = null;
        this.parts_links = {};
        this.settings || (this.settings = {});
        this.has_questions = false;
        if (bb) {
          this.reserve_without_questions = bb.reserve_without_questions;
        }
        if (this.time) {
          this.time = new BBModel.TimeSlot({
            time: this.time,
            event_id: this.event_id,
            selected: true,
            avail: 1,
            price: this.price
          });
        }
        if (this.date) {
          this.date = new BBModel.Day({
            date: this.date,
            spaces: 1
          });
        }
        if (this.datetime) {
          this.date = new BBModel.Day({
            date: this.datetime.toISODate(),
            spaces: 1
          });
          t = this.datetime.hour() * 60 + this.datetime.minute();
          this.time = new BBModel.TimeSlot({
            time: t,
            event_id: this.event_id,
            selected: true,
            avail: 1,
            price: this.price
          });
        }
        if (this.id) {
          this.reserve_ready = true;
          this.held = {
            time: this.time,
            date: this.date,
            event_id: this.event_id
          };
        }
        this.promises = [];
        if (data) {
          if (data.$has("answers")) {
            data.$get("answers").then((function(_this) {
              return function(answers) {
                var a, i, len, results;
                data.questions = [];
                results = [];
                for (i = 0, len = answers.length; i < len; i++) {
                  a = answers[i];
                  results.push(data.questions.push({
                    id: a.question_id,
                    answer: a.value
                  }));
                }
                return results;
              };
            })(this));
          }
          if (data.$has('company')) {
            comp = data.$get('company');
            this.promises.push(comp);
            comp.then((function(_this) {
              return function(comp) {
                var c;
                c = new BBModel.Company(comp);
                _this.promises.push(c.getSettings());
                return _this.setCompany(c);
              };
            })(this));
          }
          if (data.$has('service')) {
            serv = data.$get('service');
            this.promises.push(serv);
            serv.then((function(_this) {
              return function(serv) {
                var prom;
                if (serv.$has('category')) {
                  prom = serv.$get('category');
                  _this.promises.push(prom);
                  prom.then(function(cat) {
                    return _this.setCategory(new BBModel.Category(cat));
                  });
                }
                _this.setService(new BBModel.Service(serv), data.questions);
                if (_this.duration) {
                  _this.setDuration(_this.duration);
                }
                _this.checkReady();
                if (_this.time) {
                  return _this.time.service = _this.service;
                }
              };
            })(this));
          }
          if (data.$has('event_group')) {
            serv = data.$get('event_group');
            this.promises.push(serv);
            serv.then((function(_this) {
              return function(serv) {
                var prom;
                if (serv.$has('category')) {
                  prom = serv.$get('category');
                  _this.promises.push(prom);
                  prom.then(function(cat) {
                    return _this.setCategory(new BBModel.Category(cat));
                  });
                }
                _this.setEventGroup(new BBModel.EventGroup(serv));
                if (_this.time) {
                  return _this.time.service = _this.event_group;
                }
              };
            })(this));
          }
          if (data.$has('event_chain')) {
            chain = data.$get('event_chain');
            this.promises.push(chain);
            if (!data.$has('event')) {
              chain.then((function(_this) {
                return function(serv) {
                  return _this.setEventChain(new BBModel.EventChain(serv), data.questions);
                };
              })(this));
            }
          }
          if (data.$has('resource')) {
            res = data.$get('resource');
            this.promises.push(res);
            res.then((function(_this) {
              return function(res) {
                return _this.setResource(new BBModel.Resource(res), false);
              };
            })(this));
          }
          if (data.$has('person')) {
            per = data.$get('person');
            this.promises.push(per);
            per.then((function(_this) {
              return function(per) {
                return _this.setPerson(new BBModel.Person(per), false);
              };
            })(this));
          }
          if (data.$has('event')) {
            data.$get('event').then((function(_this) {
              return function(event) {
                return _this.setEvent(new BBModel.Event(event));
              };
            })(this));
          }
          if (data.settings) {
            this.settings = $bbug.extend(true, {}, data.settings);
          }
          if (data.attachment_id) {
            this.attachment_id = data.attachment_id;
          }
          if (data.$has('product')) {
            data.$get('product').then((function(_this) {
              return function(product) {
                return _this.setProduct(new BBModel.Product(product));
              };
            })(this));
          }
          if (data.$has('package_item')) {
            data.$get('package_item').then((function(_this) {
              return function(package_item) {
                return _this.setPackageItem(new BBModel.PackageItem(package_item));
              };
            })(this));
          }
          if (data.$has('bulk_purchase')) {
            data.$get('bulk_purchase').then((function(_this) {
              return function(bulk_purchase) {
                return _this.setBulkPurchase(new BBModel.BulkPurchase(bulk_purchase));
              };
            })(this));
          }
          if (data.$has('deal')) {
            data.$get('deal').then((function(_this) {
              return function(deal) {
                return _this.setDeal(new BBModel.Deal(deal));
              };
            })(this));
          }
          if (data.$has('pre_paid_booking')) {
            data.$get('pre_paid_booking').then((function(_this) {
              return function(pre_paid_booking) {
                return _this.setPrepaidBooking(new BBModel.PrePaidBooking(pre_paid_booking));
              };
            })(this));
          }
          if (data.clinic_id) {
            this.clinic_id = data.clinic_id;
          }
        }
      }


      /***
      * @ngdoc method
      * @name setDefaults
      * @methodOf BB.Models:BasketItem
      * @description
      * Set the default settings
      *
      * @returns {object} Default settings
       */

      BasketItem.prototype.setDefaults = function(defaults) {
        if (defaults.settings) {
          this.settings = defaults.settings;
        }
        if (defaults.company) {
          this.setCompany(defaults.company);
        }
        if (defaults.merge_resources) {
          this.setResource(null);
        }
        if (defaults.merge_people) {
          this.setPerson(null);
        }
        if (defaults.resource) {
          this.setResource(defaults.resource);
        }
        if (defaults.person) {
          this.setPerson(defaults.person);
        }
        if (defaults.service) {
          this.setService(defaults.service);
        }
        if (defaults.category) {
          this.setCategory(defaults.category);
        }
        if (defaults.time) {
          this.requested_time = parseInt(defaults.time);
        }
        if (defaults.date) {
          this.requested_date = moment(defaults.date);
        }
        if (defaults.service_ref) {
          this.service_ref = defaults.service_ref;
        }
        if (defaults.group) {
          this.group = defaults.group;
        }
        if (defaults.clinic) {
          this.clinic = defaults.clinic;
          this.clinic_id = defaults.clinic.id;
        }
        if (defaults.private_note) {
          this.private_note = defaults.private_note;
        }
        if (defaults.event_group) {
          this.setEventGroup(defaults.event_group);
        }
        if (defaults.event) {
          this.setEvent(defaults.event);
        }
        return this.defaults = defaults;
      };


      /***
      * @ngdoc method
      * @name storeDefaults
      * @methodOf BB.Models:BasketItem
      * @description
      * Store the default settings by attaching them to the current context
      *
      * @returns {array} defaults variable
       */

      BasketItem.prototype.storeDefaults = function(defaults) {
        return this.defaults = defaults;
      };


      /***
      * @ngdoc method
      * @name defaultService
      * @methodOf BB.Models:BasketItem
      * @description
      * Return the default service if existent
      *
      * @returns {array} Default service
       */

      BasketItem.prototype.defaultService = function() {
        if (!this.defaults) {
          return null;
        }
        return this.defaults.service;
      };


      /***
      * @ngdoc method
      * @name requestedTimeUnavailable
      * @methodOf BB.Models:BasketItem
      * @description
      * Delete requested time and date if these are unavailable
       */

      BasketItem.prototype.requestedTimeUnavailable = function() {
        delete this.requested_time;
        return delete this.requested_date;
      };


      /***
      * @ngdoc method
      * @name setSlot
      * @methodOf BB.Models:BasketItem
      * @description
      * Set the current slot based on the passed parameter
      *
      * @param {object} slot A hash representing a slot object
      * @returns {array} The available slot
       */

      BasketItem.prototype.setSlot = function(slot) {
        var t;
        this.date = new BBModel.Day({
          date: slot.datetime.toISODate(),
          spaces: 1
        });
        t = slot.datetime.hour() * 60 + slot.datetime.minute();
        this.time = new BBModel.TimeSlot({
          time: t,
          avail: 1,
          price: this.price
        });
        return this.available_slot = slot.id;
      };


      /***
      * @ngdoc method
      * @name setCompany
      * @methodOf BB.Models:BasketItem
      * @description
      * Set the current company based on the passed parameter
      * @param {object} company a hash representing a company object
       */

      BasketItem.prototype.setCompany = function(company) {
        this.company = company;
        this.parts_links.company = this.company.$href('self');
        if (this.item_details) {
          return this.item_details.currency_code = this.company.currency_code;
        }
      };


      /***
      * @ngdoc method
      * @name clearExistingItem
      * @methodOf BB.Models:BasketItem
      * @description
      * Clear existing item
       */

      BasketItem.prototype.clearExistingItem = function() {
        var prom;
        if (this.$has('self') && this.event_id) {
          prom = this.$del('self');
          this.promises.push(prom);
          prom.then(function() {});
        }
        delete this.earliest_time;
        return delete this.event_id;
      };


      /***
      * @ngdoc method
      * @name setItem
      * @methodOf BB.Models:BasketItem
      * @description
      * Set the current item based on the item object passed as parameter
       */

      BasketItem.prototype.setItem = function(item) {
        if (!item) {
          return;
        }
        if (item.type === "person") {
          return this.setPerson(item);
        } else if (item.type === "service") {
          return this.setService(item);
        } else if (item.type === "resource") {
          return this.setResource(item);
        }
      };


      /***
      * @ngdoc method
      * @name setService
      * @methodOf BB.Models:BasketItem
      * @description
      * Set service in according of server parameter, if default_question is null
      *
      * @returns {array} The returned service set
       */

      BasketItem.prototype.setService = function(serv, default_questions) {
        var prom;
        if (default_questions == null) {
          default_questions = null;
        }
        if (this.service) {
          if (this.service.self && serv.self && this.service.self === serv.self) {
            if (this.service.$has('book')) {
              this.book_link = this.service;
            }
            if (serv.$has('days')) {
              this.days_link = serv;
            }
            if (serv.$has('book')) {
              this.book_link = serv;
            }
            return;
          }
          this.item_details = null;
          this.clearExistingItem();
        }
        if (this.service && serv && this.service.self && serv.self) {
          if ((this.service.self !== serv.self) && serv.durations && serv.durations.length > 1) {
            this.duration = null;
            this.listed_duration = null;
          }
        }
        this.service = serv;
        if (serv && (serv instanceof BookableItemModel)) {
          this.service = serv.item;
        }
        this.parts_links.service = this.service.$href('self');
        if (this.service.$has('book')) {
          this.book_link = this.service;
        }
        if (serv.$has('days')) {
          this.days_link = serv;
        }
        if (serv.$has('book')) {
          this.book_link = serv;
        }
        if (this.service.$has('questions')) {
          this.has_questions = true;
          prom = this.service.$get('questions');
          this.promises.push(prom);
          prom.then((function(_this) {
            return function(details) {
              if (_this.company) {
                details.currency_code = _this.company.currency_code;
              }
              _this.item_details = new BBModel.ItemDetails(details);
              _this.has_questions = _this.item_details.hasQuestions;
              if (default_questions) {
                _this.item_details.setAnswers(default_questions);
                return _this.setAskedQuestions();
              }
            };
          })(this), (function(_this) {
            return function(err) {
              return _this.has_questions = false;
            };
          })(this));
        } else {
          this.has_questions = false;
        }
        if (this.service && this.service.durations && this.service.durations.length === 1) {
          this.setDuration(this.service.durations[0]);
          this.listed_duration = this.service.durations[0];
        }
        if (this.service && this.service.listed_durations && this.service.listed_durations.length === 1) {
          this.listed_duration = this.service.listed_durations[0];
        }
        if (this.service.$has('category')) {
          prom = this.service.getCategoryPromise();
          if (prom) {
            return this.promises.push(prom);
          }
        }
      };


      /***
      * @ngdoc method
      * @name setEventGroup
      * @methodOf BB.Models:BasketItem
      * @description
      * Set event group based on the event_group param
      *
      * @param {object} event_group a hash
       */

      BasketItem.prototype.setEventGroup = function(event_group) {
        var prom;
        if (this.event_group) {
          if (this.event_group.self && event_group.self && this.event_group.self === event_group.self) {
            return;
          }
        }
        this.event_group = event_group;
        this.parts_links.event_group = this.event_group.$href('self').replace('event_group', 'service');
        if (this.event_group.$has('category')) {
          prom = this.event_group.getCategoryPromise();
          if (prom) {
            return this.promises.push(prom);
          }
        }
      };


      /***
      * @ngdoc method
      * @name setEventChain
      * @methodOf BB.Models:BasketItem
      * @description
      * Set event chain in according of event_chain parameter, default_qustions is null
      *
      * @returns {array} The returned set event chaint
       */

      BasketItem.prototype.setEventChain = function(event_chain, default_questions) {
        var prom;
        if (default_questions == null) {
          default_questions = null;
        }
        if (this.event_chain) {
          if (this.event_chain.self && event_chain.self && this.event_chain.self === event_chain.self) {
            return;
          }
        }
        this.event_chain = event_chain;
        this.base_price = parseFloat(event_chain.price);
        if ((this.price != null) && this.price !== this.base_price) {
          this.setPrice(this.price);
        } else {
          this.setPrice(this.base_price);
        }
        if (this.event_chain.isSingleBooking()) {
          this.tickets = {
            name: "Admittance",
            max: 1,
            type: "normal",
            price: this.base_price
          };
          this.tickets.pre_paid_booking_id = this.pre_paid_booking_id;
          if (this.num_book) {
            this.tickets.qty = this.num_book;
          }
        }
        if (this.event_chain.$has('questions')) {
          this.has_questions = true;
          prom = this.event_chain.$get('questions');
          this.promises.push(prom);
          return prom.then((function(_this) {
            return function(details) {
              var a, i, len, q, ref;
              _this.item_details = new BBModel.ItemDetails(details);
              _this.has_questions = _this.item_details.hasQuestions;
              if (_this.questions) {
                ref = _this.item_details.questions;
                for (i = 0, len = ref.length; i < len; i++) {
                  q = ref[i];
                  a = _.find(_this.questions, function(c) {
                    return c.id === q.id;
                  });
                  if (a && q.answer === void 0 || a !== q.answer) {
                    q.answer = a.answer;
                  }
                }
                _this.setAskedQuestions();
              }
              if (default_questions) {
                _this.item_details.setAnswers(default_questions);
                return _this.setAskedQuestions();
              }
            };
          })(this), (function(_this) {
            return function(err) {
              return _this.has_questions = false;
            };
          })(this));
        } else {
          return this.has_questions = false;
        }
      };


      /***
      * @ngdoc method
      * @name setEvent
      * @methodOf BB.Models:BasketItem
      * @description
      * Set event according to event parameter
      *
      * @param {object} event A hash representing an event object
       */

      BasketItem.prototype.setEvent = function(event, default_questions) {
        var prom;
        if (default_questions == null) {
          default_questions = null;
        }
        if (this.event) {
          this.event.unselect();
        }
        this.event = event;
        this.event.select();
        this.event_chain_id = event.event_chain_id;
        this.setDate({
          date: event.date
        });
        this.setTime(event.time);
        this.setDuration(event.duration);
        if (event.$has('book')) {
          this.book_link = event;
        }
        if (event.qty) {
          this.num_book = event.qty;
        }
        prom = this.event.getChain();
        this.promises.push(prom);
        prom.then((function(_this) {
          return function(chain) {
            return _this.setEventChain(chain, default_questions);
          };
        })(this));
        prom = this.event.getGroup();
        this.promises.push(prom);
        prom.then((function(_this) {
          return function(group) {
            return _this.setEventGroup(group);
          };
        })(this));
        if (this.event.getSpacesLeft() <= 0 && !this.company.settings) {
          if (this.company.getSettings().has_waitlists) {
            return this.status = 8;
          }
        } else if (this.event.getSpacesLeft() <= 0 && this.company.settings && this.company.settings.has_waitlists) {
          return this.status = 8;
        }
      };


      /***
      * @ngdoc method
      * @name setCategory
      * @methodOf BB.Models:BasketItem
      * @description
      * Set category according to cat parameter
      *
      * @param {object} cat A hash representing a category object
       */

      BasketItem.prototype.setCategory = function(cat) {
        return this.category = cat;
      };


      /***
      * @ngdoc method
      * @name setPerson
      * @methodOf BB.Models:BasketItem
      * @description
      * Set person according to per parameter
      *
      * @param {object} per A hash representing a person object
      
      * @param {boolean} set_selected The returned set resource for basket item
       */

      BasketItem.prototype.setPerson = function(per, set_selected) {
        if (set_selected == null) {
          set_selected = true;
        }
        if (set_selected && this.earliest_time) {
          delete this.earliest_time;
        }
        if (!per) {
          this.person = true;
          if (set_selected) {
            this.settings.person = -1;
          }
          this.parts_links.person = null;
          if (this.service) {
            this.setService(this.service);
          }
          if (this.resource && !this.anyResource()) {
            this.setResource(this.resource, false);
          }
          if (this.event_id) {
            delete this.event_id;
            if (this.resource && this.defaults && this.defaults.merge_resources) {
              return this.setResource(null);
            }
          }
        } else {
          this.person = per;
          if (set_selected) {
            this.settings.person = this.person.id;
          }
          this.parts_links.person = this.person.$href('self');
          if (per.$has('days')) {
            this.days_link = per;
          }
          if (per.$has('book')) {
            this.book_link = per;
          }
          if (this.event_id && this.$has('person') && this.$href('person') !== this.person.self) {
            delete this.event_id;
            if (this.resource && this.defaults && this.defaults.merge_resources) {
              return this.setResource(null);
            }
          }
        }
      };


      /***
      * @ngdoc method
      * @name setResource
      * @methodOf BB.Models:BasketItem
      * @description
      * Set resource in according of res parameter, if set_selected is true
      *
      * @returns {object} The returned set resource for basket item
       */

      BasketItem.prototype.setResource = function(res, set_selected) {
        if (set_selected == null) {
          set_selected = true;
        }
        if (set_selected && this.earliest_time) {
          delete this.earliest_time;
        }
        if (!res) {
          this.resource = true;
          if (set_selected) {
            this.settings.resource = -1;
          }
          this.parts_links.resource = null;
          if (this.service) {
            this.setService(this.service);
          }
          if (this.person && !this.anyPerson()) {
            this.setPerson(this.person, false);
          }
          if (this.event_id) {
            delete this.event_id;
            if (this.person && this.defaults && this.defaults.merge_people) {
              return this.setPerson(null);
            }
          }
        } else {
          this.resource = res;
          if (set_selected) {
            this.settings.resource = this.resource.id;
          }
          this.parts_links.resource = this.resource.$href('self');
          if (res.$has('days')) {
            this.days_link = res;
          }
          if (res.$has('book')) {
            this.book_link = res;
          }
          if (this.event_id && this.$has('resource') && this.$href('resource') !== this.resource.self) {
            delete this.event_id;
            if (this.person && this.defaults && this.defaults.merge_people) {
              return this.setPerson(null);
            }
          }
        }
      };


      /***
      * @ngdoc method
      * @name setDuration
      * @methodOf BB.Models:BasketItem
      * @description
      * Set duration in according of dur parameter
      *
      * @returns {integer} The returned set duration for basket item
       */

      BasketItem.prototype.setDuration = function(dur) {
        this.duration = dur;
        if (this.service) {
          this.base_price = this.service.getPriceByDuration(dur);
        } else if (this.time && this.time.price) {
          this.base_price = this.time.price;
        } else if (this.price) {
          this.base_price = this.price;
        }
        return this.setPrice(this.base_price);
      };


      /***
      * @ngdoc method
      * @name print_time
      * @methodOf BB.Models:BasketItem
      * @description
      * Get to print time
      *
      * @returns {date} The returned print time
       */

      BasketItem.prototype.print_time = function() {
        if (this.time) {
          return this.time.print_time();
        }
      };


      /***
      * @ngdoc method
      * @name print_end_time
      * @methodOf BB.Models:BasketItem
      * @description
      * Get to print end time
      *
      * @returns {date} The returned print end time
       */

      BasketItem.prototype.print_end_time = function() {
        if (this.time) {
          return this.time.print_end_time(this.duration);
        }
      };


      /***
      * @ngdoc method
      * @name print_time12
      * @methodOf BB.Models:BasketItem
      * @description
      * Get to print time12 if show suffix is true
      *
      * @returns {date} The returned print time12
       */

      BasketItem.prototype.print_time12 = function(show_suffix) {
        if (show_suffix == null) {
          show_suffix = true;
        }
        if (this.time) {
          return this.time.print_time12(show_suffix);
        }
      };


      /***
      * @ngdoc method
      * @name print_end_time12
      * @methodOf BB.Models:BasketItem
      * @description
      * Get to print end time12 if show_suffix is true
      *
      * @returns {date} The returned print end time12
       */

      BasketItem.prototype.print_end_time12 = function(show_suffix) {
        if (show_suffix == null) {
          show_suffix = true;
        }
        if (this.time) {
          return this.time.print_end_time12(show_suffix, this.duration);
        }
      };


      /***
      * @ngdoc method
      * @name setTime
      * @methodOf BB.Models:BasketItem
      * @description
      * Set time in according of time parameter
      *
      * @returns {date} The returned set time
       */

      BasketItem.prototype.setTime = function(time) {
        var hours, mins, val;
        if (this.time) {
          this.time.unselect();
        }
        this.time = time;
        if (this.time) {
          this.time.select();
          if (this.datetime) {
            val = parseInt(time.time);
            hours = parseInt(val / 60);
            mins = val % 60;
            this.datetime.hour(hours);
            this.datetime.minutes(mins);
          }
          if (this.price && this.time.price && (this.price !== this.time.price)) {
            this.setPrice(this.price);
          } else if (this.price && !this.time.price) {
            this.setPrice(this.price);
          } else if (this.time.price && !this.price) {
            this.setPrice(this.time.price);
          } else if (this.price && this.time.price) {
            this.setPrice(this.price);
          } else {
            this.setPrice(null);
          }
        }
        return this.checkReady();
      };


      /***
      * @ngdoc method
      * @name setDate
      * @methodOf BB.Models:BasketItem
      * @description
      * Set date in according of date parameter
      *
      * @returns {date} The returned set date
       */

      BasketItem.prototype.setDate = function(date) {
        this.date = date;
        if (this.date) {
          this.date.date = moment(this.date.date);
          if (this.datetime) {
            this.datetime.date(this.date.date.date());
            this.datetime.month(this.date.date.month());
            this.datetime.year(this.date.date.year());
          }
        }
        return this.checkReady();
      };


      /***
      * @ngdoc method
      * @name clearDateTime
      * @methodOf BB.Models:BasketItem
      * @description
      * Clear date and time
      *
      * @returns {date} The returned clear date and time
       */

      BasketItem.prototype.clearDateTime = function() {
        delete this.date;
        delete this.time;
        delete this.datetime;
        this.ready = false;
        return this.reserve_ready = false;
      };


      /***
      * @ngdoc method
      * @name clearTime
      * @methodOf BB.Models:BasketItem
      * @description
      * Clear time
      *
      * @returns {date} The returned clear time
       */

      BasketItem.prototype.clearTime = function() {
        delete this.time;
        this.ready = false;
        return this.reserve_ready = false;
      };


      /***
      * @ngdoc method
      * @name clearTime
      * @methodOf BB.Models:BasketItem
      * @description
      * Set group in according of group parameter
      *
      * @returns {object} The returned set group
       */

      BasketItem.prototype.setGroup = function(group) {
        return this.group = group;
      };


      /***
      * @ngdoc method
      * @name setAskedQuestions
      * @methodOf BB.Models:BasketItem
      * @description
      * Set asked questions
      *
      * @returns {object} The returned set asked questions
       */

      BasketItem.prototype.setAskedQuestions = function() {
        this.asked_questions = true;
        return this.checkReady();
      };


      /***
      * @ngdoc method
      * @name checkReady
      * @methodOf BB.Models:BasketItem
      * @description
      * Check if an item is ready for checking out
      *
      * @returns {date} The returned item has been ready for checking out
       */

      BasketItem.prototype.checkReady = function() {
        if (((this.date && this.time && this.service) || this.event || this.product || this.package_item || this.bulk_purchase || this.external_purchase || this.deal || (this.date && this.service && this.service.duration_unit === 'day')) && (this.asked_questions || !this.has_questions)) {
          this.ready = true;
        }
        if (((this.date && this.time && this.service) || this.event || this.product || this.package_item || this.bulk_purchase || this.external_purchase || this.deal || (this.date && this.service && this.service.duration_unit === 'day')) && (this.asked_questions || !this.has_questions || this.reserve_without_questions)) {
          return this.reserve_ready = true;
        }
      };


      /***
      * @ngdoc method
      * @name getPostData
      * @methodOf BB.Models:BasketItem
      * @description
      * Build an array with details for every basket item in items array
      *
      * @returns {array} Newly created details array
       */

      BasketItem.prototype.getPostData = function() {
        var data, i, j, len, len1, m_question, o_question, ref, ref1;
        if (this.cloneAnswersItem) {
          ref = this.cloneAnswersItem.item_details.questions;
          for (i = 0, len = ref.length; i < len; i++) {
            o_question = ref[i];
            ref1 = this.item_details.questions;
            for (j = 0, len1 = ref1.length; j < len1; j++) {
              m_question = ref1[j];
              if (m_question.id === o_question.id) {
                m_question.answer = o_question.answer;
                this.setAskedQuestions();
              }
            }
          }
        }
        data = {};
        if (this.date) {
          data.date = this.date.date.toISODate();
        }
        if (this.time) {
          data.time = this.time.time;
          if (this.time.event_id) {
            data.event_id = this.time.event_id;
          } else if (this.time.event_ids) {
            data.event_ids = this.time.event_ids;
          }
        } else if (this.date && this.date.event_id) {
          data.event_id = this.date.event_id;
        }
        data.price = this.price;
        data.paid = this.paid;
        if (this.book_link) {
          data.book = this.book_link.$href('book');
        }
        data.id = this.id;
        data.duration = this.duration;
        data.settings = this.settings;
        data.settings || (data.settings = {});
        if (this.earliest_time) {
          data.settings.earliest_time = this.earliest_time;
        }
        if (this.item_details && this.asked_questions) {
          data.questions = this.item_details.getPostData();
        }
        if (this.move_item_id) {
          data.move_item_id = this.move_item_id;
        }
        if (this.srcBooking) {
          data.move_item_id = this.srcBooking.id;
        }
        if (this.service) {
          data.service_id = this.service.id;
        }
        if (this.resource) {
          data.resource_id = this.resource.id;
        }
        if (this.person) {
          data.person_id = this.person.id;
        }
        data.length = this.length;
        if (this.event) {
          data.event_id = this.event.id;
          if (this.event.pre_paid_booking_id != null) {
            data.pre_paid_booking_id = this.event.pre_paid_booking_id;
          } else if (this.tickets && (this.tickets.pre_paid_booking_id != null)) {
            data.pre_paid_booking_id = this.tickets.pre_paid_booking_id;
          }
          data.tickets = this.tickets;
        }
        if (this.pre_paid_booking_id != null) {
          data.pre_paid_booking_id = this.pre_paid_booking_id;
        }
        data.event_chain_id = this.event_chain_id;
        data.event_group_id = this.event_group_id;
        data.qty = this.qty;
        if (this.status) {
          data.status = this.status;
        }
        if (this.num_resources != null) {
          data.num_resources = parseInt(this.num_resources);
        }
        if (this.package_item) {
          data.package_id = this.package_item.id;
        }
        if (this.bulk_purchase) {
          data.bulk_purchase_id = this.bulk_purchase.id;
        }
        data.external_purchase = this.external_purchase;
        if (this.deal) {
          data.deal = this.deal;
        }
        if (this.deal && this.recipient) {
          data.recipient = this.recipient;
        }
        if (this.deal && this.recipient && this.recipient_mail) {
          data.recipient_mail = this.recipient_mail;
        }
        data.coupon_id = this.coupon_id;
        data.is_coupon = this.is_coupon;
        if (this.attachment_id) {
          data.attachment_id = this.attachment_id;
        }
        if (this.deal_codes) {
          data.vouchers = this.deal_codes;
        }
        if (this.product) {
          data.product_id = this.product.id;
        }
        if (this.email) {
          data.email = this.email;
        }
        if (this.first_name) {
          data.first_name = this.first_name;
        }
        if (this.last_name) {
          data.last_name = this.last_name;
        }
        if (this.email != null) {
          data.email = this.email;
        }
        if (this.email_admin != null) {
          data.email_admin = this.email_admin;
        }
        if (this.private_note) {
          data.private_note = this.private_note;
        }
        if (this.available_slot) {
          data.available_slot = this.available_slot;
        }
        if (this.clinic_id) {
          data.clinic_id = this.clinic_id;
        }
        return data;
      };


      /***
      * @ngdoc method
      * @name setPrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Set price in according of nprice parameter
      *
      * @returns {integer} The returned set price
       */

      BasketItem.prototype.setPrice = function(nprice) {
        var printed_price;
        if (nprice != null) {
          this.price = parseFloat(nprice);
          printed_price = this.price / 100;
          this.printed_price = printed_price % 1 === 0 ? "£" + parseInt(printed_price) : $window.sprintf("£%.2f", printed_price);
          if (this.company && this.company.settings) {
            this.printed_vat_cal = this.company.settings.payment_tax;
          }
          if (this.printed_vat_cal) {
            this.printed_vat = this.printed_vat_cal / 100 * printed_price;
          }
          if (this.printed_vat_cal) {
            return this.printed_vat_inc = this.printed_vat_cal / 100 * printed_price + printed_price;
          }
        } else {
          this.price = null;
          this.printed_price = null;
          this.printed_vat_cal = null;
          this.printed_vat = null;
          return this.printed_vat_inc = null;
        }
      };


      /***
      * @ngdoc method
      * @name getStep
      * @methodOf BB.Models:BasketItem
      * @description
      * Build a temp object with current step variables
      *
      * @returns {object} Temp hash
       */

      BasketItem.prototype.getStep = function() {
        var temp;
        temp = {};
        temp.service = this.service;
        temp.category = this.category;
        temp.person = this.person;
        temp.resource = this.resource;
        temp.duration = this.duration;
        temp.event = this.event;
        temp.event_group = this.event_group;
        temp.event_chain = this.event_chain;
        temp.time = this.time;
        temp.date = this.date;
        temp.days_link = this.days_link;
        temp.book_link = this.book_link;
        temp.ready = this.ready;
        return temp;
      };


      /***
      * @ngdoc method
      * @name loadStep
      * @methodOf BB.Models:BasketItem
      * @description
      * Build current step variables based on a hash object passed as parameter
      *
      * @param {object} step Hash object representing a step
      *
      * @returns {object} The returned load step
       */

      BasketItem.prototype.loadStep = function(step) {
        if (this.id) {
          return;
        }
        this.service = step.service;
        this.category = step.category;
        this.person = step.person;
        this.resource = step.resource;
        this.duration = step.duration;
        this.event = step.event;
        this.event_chain = step.event_chain;
        this.event_group = step.event_group;
        this.time = step.time;
        this.date = step.date;
        this.days_link = step.days_link;
        this.book_link = step.book_link;
        return this.ready = step.ready;
      };


      /***
      * @ngdoc method
      * @name describe
      * @methodOf BB.Models:BasketItem
      * @description
      * Get information about of the basket item
      *
      * @returns {object} The returned title
       */

      BasketItem.prototype.describe = function() {
        var title;
        title = "-";
        if (this.service) {
          title = this.service.name;
        }
        if (this.event_group && this.event && title === "-") {
          title = this.event_group.name + " - " + this.event.description;
        }
        if (this.product) {
          title = this.product.name;
        }
        if (this.external_purchase) {
          title = this.external_purchase.name;
        }
        if (this.deal) {
          title = this.deal.name;
        }
        if (this.package_item) {
          title = this.package_item.name;
        }
        if (this.bulk_purchase) {
          title = this.bulk_purchase.name;
        }
        return title;
      };


      /***
      * @ngdoc method
      * @name booking_date
      * @methodOf BB.Models:BasketItem
      * @description
      * Get booking date of the basket item, in according of format parameter
      *
      * @returns {date} The returned booking date
       */

      BasketItem.prototype.booking_date = function(format) {
        if (!this.date || !this.date.date) {
          return null;
        }
        return this.date.date.format(format);
      };


      /***
      * @ngdoc method
      * @name booking_time
      * @methodOf BB.Models:BasketItem
      * @description
      * Get booking time of the basket item in according with separator = '-'
      *
      * @returns {date} The returned booking time
       */

      BasketItem.prototype.booking_time = function(seperator) {
        var duration;
        if (seperator == null) {
          seperator = '-';
        }
        if (!this.time) {
          return null;
        }
        duration = this.listed_duration ? this.listed_duration : this.duration;
        return this.time.print_time() + " " + seperator + " " + this.time.print_end_time(duration);
      };


      /***
      * @ngdoc method
      * @name duePrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Get due price for the basket item
      *
      * @returns {string} The returned price
       */

      BasketItem.prototype.duePrice = function() {
        if (this.isWaitlist()) {
          return 0;
        }
        return this.price;
      };


      /***
      * @ngdoc method
      * @name isWaitlist
      * @methodOf BB.Models:BasketItem
      * @description
      * Checks if this is a wait list
      *
      * @returns {boolean} If this is a wait list
       */

      BasketItem.prototype.isWaitlist = function() {
        return this.status && this.status === 8;
      };


      /***
      * @ngdoc method
      * @name start_datetime
      * @methodOf BB.Models:BasketItem
      * @description
      * Get booking start date and time
      *
      * @returns {date} The returned start date time
       */

      BasketItem.prototype.start_datetime = function() {
        var start_datetime;
        if (!this.date || !this.time) {
          return null;
        }
        start_datetime = moment(this.date.date.toISODate());
        start_datetime.minutes(this.time.time);
        return start_datetime;
      };

      BasketItem.prototype.startDatetime = function() {
        return this.start_datetime();
      };


      /***
      * @ngdoc method
      * @name end_datetime
      * @methodOf BB.Models:BasketItem
      * @description
      * Get booking end date and time
      *
      * @returns {date} The returned end date time
       */

      BasketItem.prototype.end_datetime = function() {
        var duration, end_datetime;
        if (!this.date || !this.time || (!this.listed_duration && !this.duration)) {
          return null;
        }
        duration = this.listed_duration ? this.listed_duration : this.duration;
        end_datetime = moment(this.date.date.toISODate());
        end_datetime.minutes(this.time.time + duration);
        return end_datetime;
      };

      BasketItem.prototype.endDatetime = function() {
        return this.end_datetime();
      };


      /***
      * @ngdoc method
      * @name setSrcBooking
      * @methodOf BB.Models:BasketItem
      * @description
      * Set a booking are to be a move if according of booking parameter
      *
      * @returns {object} The returned end date time
       */

      BasketItem.prototype.setSrcBooking = function(booking) {
        this.srcBooking = booking;
        return this.duration = booking.duration;
      };


      /***
      * @ngdoc method
      * @name anyPerson
      * @methodOf BB.Models:BasketItem
      * @description
      * Verify type of any person
      *
      * @returns {boolean} The returned any person
       */

      BasketItem.prototype.anyPerson = function() {
        return this.person && (typeof this.person === 'boolean');
      };


      /***
      * @ngdoc method
      * @name anyResource
      * @methodOf BB.Models:BasketItem
      * @description
      * Verify type of any resorce
      *
      * @returns {boolean} The returned any resource
       */

      BasketItem.prototype.anyResource = function() {
        return this.resource && (typeof this.resource === 'boolean');
      };


      /***
      * @ngdoc method
      * @name isMovingBooking
      * @methodOf BB.Models:BasketItem
      * @description
      * Verify if booking has been moved
      *
      * @returns {boolean} The returned moving booking
       */

      BasketItem.prototype.isMovingBooking = function() {
        return this.srcBooking || this.move_item_id;
      };


      /***
      * @ngdoc method
      * @name setCloneAnswers
      * @methodOf BB.Models:BasketItem
      * @description
      * Set clone answers in according of other item parameter
      *
      * @returns {object} The returned clone answers
       */

      BasketItem.prototype.setCloneAnswers = function(otherItem) {
        return this.cloneAnswersItem = otherItem;
      };


      /***
      * @ngdoc method
      * @name questionPrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Question price for the basket item
      *
      * @returns {integer} The returned question price
       */

      BasketItem.prototype.questionPrice = function() {
        if (!this.item_details) {
          return 0;
        }
        return this.item_details.questionPrice(this.getQty());
      };


      /***
      * @ngdoc method
      * @name getQty
      * @methodOf BB.Models:BasketItem
      * @description
      * Get quantity of tickets
      *
      * @returns {integer} The returned quatity of tickets
       */

      BasketItem.prototype.getQty = function() {
        if (this.qty) {
          return this.qty;
        }
        if (this.tickets) {
          return this.tickets.qty;
        }
        return 1;
      };


      /***
      * @ngdoc method
      * @name totalPrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Total price of the basket item (price including discounts)
      *
      * @returns {integer} The returned total price
       */

      BasketItem.prototype.totalPrice = function() {
        var pr;
        if (this.tickets && this.tickets.pre_paid_booking_id) {
          return 0;
        }
        if (this.pre_paid_booking_id) {
          return 0;
        }
        if (this.discount_price != null) {
          return this.discount_price + this.questionPrice();
        }
        pr = this.total_price;
        if (!angular.isNumber(pr)) {
          pr = this.price;
        }
        if (!angular.isNumber(pr)) {
          pr = 0;
        }
        return pr + this.questionPrice();
      };


      /***
      * @ngdoc method
      * @name fullPrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Full price for the basket item (price not including discounts)
      *
      * @returns {integer} The returned full price
       */

      BasketItem.prototype.fullPrice = function() {
        var pr;
        pr = this.base_price;
        pr || (pr = this.total_price);
        pr || (pr = this.price);
        pr || (pr = 0);
        return pr + this.questionPrice();
      };


      /***
      * @ngdoc method
      * @name setProduct
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply a product to the BasketItem
      *
       */

      BasketItem.prototype.setProduct = function(product) {
        this.product = product;
        if (this.product.$has('book')) {
          this.book_link = this.product;
        }
        if (product.price) {
          return this.setPrice(product.price);
        }
      };


      /***
      * @ngdoc method
      * @name setPackageItem
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply a package to the BasketItem
      *
       */

      BasketItem.prototype.setPackageItem = function(package_item) {
        this.package_item = package_item;
        if (this.package_item.$has('book')) {
          this.book_link = this.package_item;
        }
        if (package_item.price) {
          return this.setPrice(package_item.price);
        }
      };


      /***
      * @ngdoc method
      * @name setBulkPurchase
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply a bulk purchase to the BasketItem
      *
       */

      BasketItem.prototype.setBulkPurchase = function(bulk_purchase) {
        this.bulk_purchase = bulk_purchase;
        if (this.bulk_purchase.$has('book')) {
          this.book_link = this.bulk_purchase;
        }
        if (bulk_purchase.price) {
          return this.setPrice(bulk_purchase.price);
        }
      };


      /***
      * @ngdoc method
      * @name setExternalPurchase
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply an external purchase to the BasketItem
      *
       */

      BasketItem.prototype.setExternalPurchase = function(external_purchase) {
        this.external_purchase = external_purchase;
        this.book_link = this.company;
        if (external_purchase.price) {
          return this.setPrice(external_purchase.price);
        }
      };


      /***
      * @ngdoc method
      * @name setDeal
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply a deal on to BasketItem
      *
       */

      BasketItem.prototype.setDeal = function(deal) {
        this.deal = deal;
        if (this.deal.$has('book')) {
          this.book_link = this.deal;
        }
        if (deal.price) {
          return this.setPrice(deal.price);
        }
      };


      /***
      * @ngdoc method
      * @name hasPrice
      * @methodOf BB.Models:BasketItem
      * @description
      * Checks if the BasketItem has a price
      *
      * @returns {boolean}
       */

      BasketItem.prototype.hasPrice = function() {
        return this.price != null;
      };


      /***
      * @ngdoc method
      * @name getAttachment
      * @methodOf BB.Models:BasketItem
      * @description
      * Get attachment of the basket item
      *
      * @returns {object} The attachment
       */

      BasketItem.prototype.getAttachment = function() {
        if (this.attachment) {
          return this.attachment;
        }
        if (this.$has('attachment') && this.attachment_id) {
          return this._data.$get('attachment').then((function(_this) {
            return function(att) {
              _this.attachment = att;
              return _this.attachment;
            };
          })(this));
        }
      };


      /***
      * @ngdoc method
      * @name setPrepaidBooking
      * @methodOf BB.Models:BasketItem
      * @description
      * Apply a prepaid booking to BasketItem
      *
       */

      BasketItem.prototype.setPrepaidBooking = function(pre_paid_booking) {
        this.pre_paid_booking = pre_paid_booking;
        return this.pre_paid_booking_id = pre_paid_booking.id;
      };


      /***
      * @ngdoc method
      * @name hasPrepaidBooking
      * @methodOf BB.Models:BasketItem
      * @description
      * Indicates if the basket item has a prepaid booking applied
      *
      * @returns {boolean} boolean indicating if the BasketItem has a prepaid booking
       */

      BasketItem.prototype.hasPrepaidBooking = function() {
        return this.pre_paid_booking_id != null;
      };


      /***
      * @ngdoc method
      * @name getEventId
      * @methodOf BB.Models:BasketItem
      * @description
      * Get the event id for the BasketItem
      *
      * @returns {string} The Event ID
       */

      BasketItem.prototype.getEventId = function() {
        if (this.time && this.time.event_id) {
          return this.time.event_id;
        } else if (this.date && this.date.event_id) {
          return this.date.event_id;
        } else if (this.event) {
          return this.event.id;
        }
      };


      /***
      * @ngdoc method
      * @name isExternalPurchase
      * @methodOf BB.Models:BasketItem
      * @description
      * Indicates if the BasketItem is an external purchase
      *
      * @returns {boolean}
       */

      BasketItem.prototype.isExternalPurchase = function() {
        return this.external_purchase != null;
      };


      /***
      * @ngdoc method
      * @name getName
      * @methodOf BB.Models:BasketItem
      * @description
      * Returns the name
      *
      * @returns {String}
       */

      BasketItem.prototype.getName = function(client) {
        if (this.first_name) {
          return this.first_name + " " + this.last_name;
        } else if (client) {
          return client.getName();
        }
      };


      /***
      * @ngdoc method
      * @name isTimeItem
      * @methodOf BB.Models:BasketItem
      * @description
      * Indicates if the BasketItem is a time item (i.e. either an event
      * or appointment booking)
      *
      * @returns {boolean}
       */

      BasketItem.prototype.isTimeItem = function() {
        return this.service || this.event;
      };

      return BasketItem;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:BookableItem
  *
  * @description
  * Representation of an BookableItem Object
  *
  * @property {string} name Property name display "-Waiting-"
  * @property {string} ready The ready
  * @property {string} promise The promise
  * @property {string} item Bookable item
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BookableItemModel", function($q, BBModel, BaseModel) {
    var BookableItem;
    return BookableItem = (function(superClass) {
      extend(BookableItem, superClass);

      BookableItem.prototype.item = null;

      BookableItem.prototype.promise = null;

      function BookableItem(data) {
        BookableItem.__super__.constructor.apply(this, arguments);
        this.name = "-Waiting-";
        this.ready = $q.defer();
        this.promise = this._data.$get('item');
        this.promise.then((function(_this) {
          return function(val) {
            var m, n, ref, ref1, ref2;
            if (val.type === "person") {
              _this.item = new BBModel.Person(val);
              if (_this.item) {
                ref = _this.item._data;
                for (n in ref) {
                  m = ref[n];
                  if (_this.item._data.hasOwnProperty(n) && typeof m !== 'function') {
                    _this[n] = m;
                  }
                }
                return _this.ready.resolve();
              } else {
                return _this.ready.resolve();
              }
            } else if (val.type === "resource") {
              _this.item = new BBModel.Resource(val);
              if (_this.item) {
                ref1 = _this.item._data;
                for (n in ref1) {
                  m = ref1[n];
                  if (_this.item._data.hasOwnProperty(n) && typeof m !== 'function') {
                    _this[n] = m;
                  }
                }
                return _this.ready.resolve();
              } else {
                return _this.ready.resolve();
              }
            } else if (val.type === "service") {
              _this.item = new BBModel.Service(val);
              if (_this.item) {
                ref2 = _this.item._data;
                for (n in ref2) {
                  m = ref2[n];
                  if (_this.item._data.hasOwnProperty(n) && typeof m !== 'function') {
                    _this[n] = m;
                  }
                }
                return _this.ready.resolve();
              } else {
                return _this.ready.resolve();
              }
            }
          };
        })(this));
      }

      return BookableItem;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:BulkPurchase
  *
  * @description
  * Representation of a BulkPurchase Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BulkPurchaseModel", function($q, BBModel, BaseModel) {
    var BulkPurchase;
    return BulkPurchase = (function(superClass) {
      extend(BulkPurchase, superClass);

      function BulkPurchase() {
        return BulkPurchase.__super__.constructor.apply(this, arguments);
      }

      return BulkPurchase;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:BussinessQuestion
  *
  * @description
  * Representation of an BussinessQuestion Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BusinessQuestionModel", function($q, $filter, BBModel, BaseModel) {
    var BusinessQuestion;
    return BusinessQuestion = (function(superClass) {
      extend(BusinessQuestion, superClass);

      function BusinessQuestion(data) {
        BusinessQuestion.__super__.constructor.call(this, data);
      }

      return BusinessQuestion;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Category
  *
  * @description
  * Representation of a Category Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("CategoryModel", function($q, BBModel, BaseModel) {
    var Category;
    return Category = (function(superClass) {
      extend(Category, superClass);

      function Category() {
        return Category.__super__.constructor.apply(this, arguments);
      }

      return Category;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Client
  *
  * @description
  * Representation of an Client Object
  *
  * @property {string} first_name Client first name
  * @property {string} last_name Client last name
  * @property {string} email Client email address
  * @property {string} address1 The first line of client address
  * @property {string} address2 The second line of client address
  * @property {string} address3 The third line of client address
  * @property {string} address4 The fourth line of client address
  * @property {string} address4 The fifth line of client address
  * @property {string} postcode Postcode of the client
  * @property {string} country Country of the client
  * @property {integer} phone The phone number of the client
  * @property {integer} mobile The mobile phone number of the client
  * @property {integer} id Id of the client
  * @property {array} answers Answers of the client
  * @property {boolean} deleted Verify if the client account is deleted or not
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ClientModel", function($q, BBModel, BaseModel, LocaleService) {
    var Client;
    return Client = (function(superClass) {
      extend(Client, superClass);

      function Client(data) {
        Client.__super__.constructor.apply(this, arguments);
        this.name = this.getName();
        if (data) {
          if (data.answers && data.$has('questions')) {
            this.waitingQuestions = $q.defer();
            this.gotQuestions = this.waitingQuestions.promise;
            data.$get('questions').then((function(_this) {
              return function(details) {
                _this.client_details = new BBModel.ClientDetails(details);
                _this.client_details.setAnswers(data.answers);
                _this.questions = _this.client_details.questions;
                _this.setAskedQuestions();
                return _this.waitingQuestions.resolve();
              };
            })(this));
          }
        }
      }


      /***
      * @ngdoc method
      * @name setClientDetails
      * @methodOf BB.Models:Client
      * @description
      * Set client details in according to details parameter
      *
      * @returns {object} The returned client details
       */

      Client.prototype.setClientDetails = function(details) {
        this.client_details = details;
        return this.questions = this.client_details.questions;
      };


      /***
      * @ngdoc method
      * @name setDefaults
      * @methodOf BB.Models:Client
      * @description
      * Set client defaults in according of values parameter
      *
      * @returns {object} The returned client defaults
       */

      Client.prototype.setDefaults = function(values) {
        if (values.name) {
          this.name = values.name;
        }
        if (values.first_name) {
          this.first_name = values.first_name;
        }
        if (values.last_name) {
          this.last_name = values.last_name;
        }
        if (values.phone) {
          this.phone = values.phone;
        }
        if (values.mobile) {
          this.mobile = values.mobile;
        }
        if (values.email) {
          this.email = values.email;
        }
        if (values.id) {
          this.id = values.id;
        }
        if (values.ref) {
          this.comp_ref = values.ref;
        }
        if (values.comp_ref) {
          this.comp_ref = values.comp_ref;
        }
        if (values.address1) {
          this.address1 = values.address1;
        }
        if (values.address2) {
          this.address2 = values.address2;
        }
        if (values.address3) {
          this.address3 = values.address3;
        }
        if (values.address4) {
          this.address4 = values.address4;
        }
        if (values.address5) {
          this.address5 = values.address5;
        }
        if (values.postcode) {
          this.postcode = values.postcode;
        }
        if (values.country) {
          this.country = values.country;
        }
        if (values.answers) {
          return this.default_answers = values.answers;
        }
      };


      /***
      * @ngdoc method
      * @name pre_fill_answers
      * @methodOf BB.Models:Client
      * @description
      * Pre fill client answers according of details
      *
      * @returns {object} The returned pre fill answers
       */

      Client.prototype.pre_fill_answers = function(details) {
        var i, len, q, ref, results;
        if (!this.default_answers) {
          return;
        }
        ref = details.questions;
        results = [];
        for (i = 0, len = ref.length; i < len; i++) {
          q = ref[i];
          if (this.default_answers[q.name]) {
            results.push(q.answer = this.default_answers[q.name]);
          } else {
            results.push(void 0);
          }
        }
        return results;
      };


      /***
      * @ngdoc method
      * @name getName
      * @methodOf BB.Models:Client
      * @description
      * Get client first name and last name
      *
      * @returns {string} The returned client name
       */

      Client.prototype.getName = function() {
        var str;
        str = "";
        if (this.first_name) {
          str += this.first_name;
        }
        if (str.length > 0 && this.last_name) {
          str += " ";
        }
        if (this.last_name) {
          str += this.last_name;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name addressSingleLine
      * @methodOf BB.Models:Address
      * @description
      * Get the address and postcode of the client
      *
      * @returns {string} The returned address
       */

      Client.prototype.addressSingleLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        if (this.address2 && str.length > 0) {
          str += ", ";
        }
        if (this.address2) {
          str += this.address2;
        }
        if (this.address3 && str.length > 0) {
          str += ", ";
        }
        if (this.address3) {
          str += this.address3;
        }
        if (this.address4 && str.length > 0) {
          str += ", ";
        }
        if (this.address4) {
          str += this.address4;
        }
        if (this.address5 && str.length > 0) {
          str += ", ";
        }
        if (this.address5) {
          str += this.address5;
        }
        if (this.postcode && str.length > 0) {
          str += ", ";
        }
        if (this.postcode) {
          str += this.postcode;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name hasAddress
      * @methodOf BB.Models:Address
      * @description
      * Checks if this is considered a valid address
      *
      * @returns {boolean} If this is a valid address
       */

      Client.prototype.hasAddress = function() {
        return this.address1 || this.address2 || this.postcode;
      };


      /***
      * @ngdoc method
      * @name addressCsvLine
      * @methodOf BB.Models:Address
      * @description
      * Get all address fields, postcode and country for CSV file
      *
      * @returns {string} The returned address
       */

      Client.prototype.addressCsvLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        str += ", ";
        if (this.address2) {
          str += this.address2;
        }
        str += ", ";
        if (this.address3) {
          str += this.address3;
        }
        str += ", ";
        if (this.address4) {
          str += this.address4;
        }
        str += ", ";
        if (this.address5) {
          str += this.address5;
        }
        str += ", ";
        if (this.postcode) {
          str += this.postcode;
        }
        str += ", ";
        if (this.country) {
          str += this.country;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name addressMultiLine
      * @methodOf BB.Models:Address
      * @description
      * Get address several lines separated by line breaks
      *
      * @returns {string} The returned address
       */

      Client.prototype.addressMultiLine = function() {
        var str;
        str = "";
        if (this.address1) {
          str += this.address1;
        }
        if (this.address2 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address2) {
          str += this.address2;
        }
        if (this.address3 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address3) {
          str += this.address3;
        }
        if (this.address4 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address4) {
          str += this.address4;
        }
        if (this.address5 && str.length > 0) {
          str += "<br/>";
        }
        if (this.address5) {
          str += this.address5;
        }
        if (this.postcode && str.length > 0) {
          str += "<br/>";
        }
        if (this.postcode) {
          str += this.postcode;
        }
        return str;
      };


      /***
      * @ngdoc method
      * @name getPostData
      * @methodOf BB.Models:Address
      * @description
      * Build an array with details of the client
      *
      * @returns {array} newly created details array
       */

      Client.prototype.getPostData = function() {
        var i, len, q, ref, x;
        x = {};
        x.first_name = this.first_name;
        x.last_name = this.last_name;
        if (this.house_number) {
          x.address1 = this.house_number + " " + this.address1;
        } else {
          x.address1 = this.address1;
        }
        x.address2 = this.address2;
        x.address3 = this.address3;
        x.address4 = this.address4;
        x.address5 = this.address5;
        x.postcode = this.postcode;
        x.country = this.country;
        x.email = this.email;
        x.id = this.id;
        x.comp_ref = this.comp_ref;
        x.parent_client_id = this.parent_client_id;
        x.password = this.password;
        x.notifications = this.notifications;
        if (this.member_level_id) {
          x.member_level_id = this.member_level_id;
        }
        if (this.send_welcome_email) {
          x.send_welcome_email = this.send_welcome_email;
        }
        if (this.default_company_id) {
          x.default_company_id = this.default_company_id;
        }
        if (this.phone) {
          x.phone = this.phone;
          if (this.phone_prefix) {
            x.phone_prefix = this.phone_prefix;
          }
        }
        if (this.mobile) {
          this.remove_prefix();
          x.mobile = this.mobile;
          x.mobile_prefix = this.mobile_prefix;
        }
        if (this.questions) {
          x.questions = [];
          ref = this.questions;
          for (i = 0, len = ref.length; i < len; i++) {
            q = ref[i];
            x.questions.push(q.getPostData());
          }
        }
        return x;
      };


      /***
      * @ngdoc method
      * @name valid
      * @methodOf BB.Models:Address
      * @description
      * Checks if this is considered a valid email
      *
      * @returns {boolean} If this is a valid email
       */

      Client.prototype.valid = function() {
        if (this.isValid) {
          return this.isValid;
        }
        if (this.email || this.hasServerId()) {
          return true;
        } else {
          return false;
        }
      };


      /***
      * @ngdoc method
      * @name setValid
      * @methodOf BB.Models:Address
      * @description
      * Set valid client, according of val
      *
      * @returns {object} The returned valid client
       */

      Client.prototype.setValid = function(val) {
        return this.isValid = val;
      };


      /***
      * @ngdoc method
      * @name hasServerId
      * @methodOf BB.Models:Address
      * @description
      * Checks if this has a id
      *
      * @returns {boolean} If this has a id
       */

      Client.prototype.hasServerId = function() {
        return this.id;
      };


      /***
      * @ngdoc method
      * @name setAskedQuestions
      * @methodOf BB.Models:Address
      * @description
      * Set asked questions of the client
      *
      * @returns {boolean} If this is set
       */

      Client.prototype.setAskedQuestions = function() {
        return this.asked_questions = true;
      };


      /***
      * @ngdoc method
      * @name fullMobile
      * @methodOf BB.Models:Address
      * @description
      * Full mobile phone number of the client
      *
      * @returns {object} The returned full mobile number
       */

      Client.prototype.fullMobile = function() {
        if (!this.mobile) {
          return;
        }
        if (!this.mobile_prefix) {
          return this.mobile;
        }
        return "+" + this.mobile_prefix + this.mobile;
      };


      /***
      * @ngdoc method
      * @name remove_prefix
      * @methodOf BB.Models:Address
      * @description
      * Remove prefix from mobile number of the client
      *
      * @returns {array} The returned full mobile number without prefix
       */

      Client.prototype.remove_prefix = function() {
        var pref_arr;
        pref_arr = this.mobile.match(/^(\+|00)(999|998|997|996|995|994|993|992|991|990|979|978|977|976|975|974|973|972|971|970|969|968|967|966|965|964|963|962|961|960|899|898|897|896|895|894|893|892|891|890|889|888|887|886|885|884|883|882|881|880|879|878|877|876|875|874|873|872|871|870|859|858|857|856|855|854|853|852|851|850|839|838|837|836|835|834|833|832|831|830|809|808|807|806|805|804|803|802|801|800|699|698|697|696|695|694|693|692|691|690|689|688|687|686|685|684|683|682|681|680|679|678|677|676|675|674|673|672|671|670|599|598|597|596|595|594|593|592|591|590|509|508|507|506|505|504|503|502|501|500|429|428|427|426|425|424|423|422|421|420|389|388|387|386|385|384|383|382|381|380|379|378|377|376|375|374|373|372|371|370|359|358|357|356|355|354|353|352|351|350|299|298|297|296|295|294|293|292|291|290|289|288|287|286|285|284|283|282|281|280|269|268|267|266|265|264|263|262|261|260|259|258|257|256|255|254|253|252|251|250|249|248|247|246|245|244|243|242|241|240|239|238|237|236|235|234|233|232|231|230|229|228|227|226|225|224|223|222|221|220|219|218|217|216|215|214|213|212|211|210|98|95|94|93|92|91|90|86|84|82|81|66|65|64|63|62|61|60|58|57|56|55|54|53|52|51|49|48|47|46|45|44|43|41|40|39|36|34|33|32|31|30|27|20|7|1)/);
        if (pref_arr) {
          this.mobile.replace(pref_arr[0], "");
          return this.mobile_prefix = pref_arr[0];
        }
      };


      /***
      * @ngdoc method
      * @name getPrePaidBookingsPromise
      * @methodOf BB.Models:Address
      * @description
      * Get pre paid bookings promise of the client
      *
      * @returns {promise} A promise for client pre paid bookings
       */

      Client.prototype.getPrePaidBookingsPromise = function(params) {
        var defer;
        defer = $q.defer();
        if (this.$has('pre_paid_bookings')) {
          this.$get('pre_paid_bookings', params).then(function(collection) {
            return collection.$get('pre_paid_bookings').then(function(prepaids) {
              var prepaid;
              return defer.resolve((function() {
                var i, len, results;
                results = [];
                for (i = 0, len = prepaids.length; i < len; i++) {
                  prepaid = prepaids[i];
                  results.push(new BBModel.PrePaidBooking(prepaid));
                }
                return results;
              })());
            }, function(err) {
              return defer.reject(err);
            });
          }, function(err) {
            return defer.reject(err);
          });
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      return Client;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:ClientDetails
  *
  * @description
  * Representation of an ClientDetails Object
  *
  * @property {array} questions Questions of the client
  * @property {integer} company_id The company id of the client company
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ClientDetailsModel", function($q, BBModel, BaseModel) {
    var ClientDetails;
    return ClientDetails = (function(superClass) {
      extend(ClientDetails, superClass);

      function ClientDetails(data) {
        var i, len, q, ref;
        ClientDetails.__super__.constructor.apply(this, arguments);
        this.questions = [];
        if (this._data) {
          ref = data.questions;
          for (i = 0, len = ref.length; i < len; i++) {
            q = ref[i];
            this.questions.push(new BBModel.Question(q));
          }
        }
        this.hasQuestions = this.questions.length > 0;
      }


      /***
      * @ngdoc method
      * @name getPostData
      * @methodOf BB.Models:ClientDetails
      * @description
      * Get post data from client details according to questions
      *
      * @returns {object} The returned data
       */

      ClientDetails.prototype.getPostData = function(questions) {
        var data, i, len, q;
        data = [];
        for (i = 0, len = questions.length; i < len; i++) {
          q = questions[i];
          data.push({
            answer: q.answer,
            id: q.id,
            price: q.price
          });
        }
        return data;
      };


      /***
      * @ngdoc method
      * @name setAnswers
      * @methodOf BB.Models:ClientDetails
      * @description
      * Set answers of the client details in function of answers
      *
      * @returns {object} The returned answers
       */

      ClientDetails.prototype.setAnswers = function(answers) {
        var a, ahash, i, j, len, len1, q, ref, results;
        ahash = {};
        for (i = 0, len = answers.length; i < len; i++) {
          a = answers[i];
          ahash[a.question_id] = a;
        }
        ref = this.questions;
        results = [];
        for (j = 0, len1 = ref.length; j < len1; j++) {
          q = ref[j];
          if (ahash[q.id]) {
            results.push(q.answer = ahash[q.id].answer);
          } else {
            results.push(void 0);
          }
        }
        return results;
      };

      return ClientDetails;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Clinic
  *
  * @description
  * Representation of an Clinic Object
  *
  * @property {string} setTimes Set times for the clinic
  * @property {string} setResourcesAndPeople Set resources and people for the clinic 
  * @property {object} settings Clinic settings
  * @property {string} resources Clinic resources
  * @property {integer} resource_ids Clinic resources ids
  * @property {string} people Clinic people
  * @property {integer} person_ids Clinic Person ids
  * @property {string} services Clinic services
  * @property {integer} services_ids Clinic service ids
  * @property {string} uncovered The uncovered
  * @property {string} className The class Name
  * @property {string} start_time The clinic start thime
  * @property {string} start The clinic start
  * @property {string} end_time The clinic end time
  * @property {string} end The clinic end
  * @property {string} title The title
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ClinicModel", function($q, BBModel, BaseModel) {
    var Clinic;
    return Clinic = (function(superClass) {
      extend(Clinic, superClass);

      function Clinic(data) {
        Clinic.__super__.constructor.call(this, data);
        this.setTimes();
        this.setResourcesAndPeople();
        this.settings || (this.settings = {});
      }


      /***
      * @ngdoc method
      * @name setResourcesAndPeople
      * @methodOf BB.Models:Clinic
      * @description
      * Set resources and people for clinic
      *
      * @returns {object} The returned resources and people
       */

      Clinic.prototype.setResourcesAndPeople = function() {
        this.resources = _.reduce(this.resource_ids, function(h, id) {
          h[id] = true;
          return h;
        }, {});
        this.people = _.reduce(this.person_ids, function(h, id) {
          h[id] = true;
          return h;
        }, {});
        this.services = _.reduce(this.service_ids, function(h, id) {
          h[id] = true;
          return h;
        }, {});
        this.uncovered = !this.person_ids || this.person_ids.length === 0;
        if (this.uncovered) {
          return this.className = "clinic_uncovered";
        } else {
          return this.className = "clinic_covered";
        }
      };


      /***
      * @ngdoc method
      * @name setTimes
      * @methodOf BB.Models:Clinic
      * @description
      * Set time for clinic
      *
      * @returns {object} The returned time
       */

      Clinic.prototype.setTimes = function() {
        if (this.start_time) {
          this.start_time = moment(this.start_time);
          this.start = this.start_time;
        }
        if (this.end_time) {
          this.end_time = moment(this.end_time);
          this.end = this.end_time;
        }
        return this.title = this.name;
      };

      return Clinic;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("BBCollectionModel", function($q, BBModel, BaseModel) {
    var BBCollection;
    return BBCollection = (function(superClass) {
      extend(BBCollection, superClass);

      function BBCollection() {
        this.getNextPage = bind(this.getNextPage, this);
        return BBCollection.__super__.constructor.apply(this, arguments);
      }

      BBCollection.prototype.getNextPage = function(params) {
        var deferred;
        deferred = $q.defer();
        this.$get('next', params).then(function(collection) {
          return deferred.resolve(new BBModel.BBCollection(collection));
        }, function() {
          return deferred.reject();
        });
        return deferred.promise;
      };

      return BBCollection;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Company
  *
  * @description
  * Representation of an Company Object
  *
  * @constructor
  * @param {HALobject=} data A HAL object to initialise the company from
  * 
  * @property {string} name The company name
  * @property {string} description The company description
  * @property {string} country_code the Country code for thie company
  * @property {string} currency_code A CCY for this company
  * @property {string} reference A custom external reference for the company
  * @property {integer} id The company ID
  * @property {boolean} live If this company is set live
  * @property {array} companies An array of child companies if this is a parent company
  * @property {string} timezone The timezone for the business
   */
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("CompanyModel", function($q, BBModel, BaseModel, halClient, AppConfig, $sessionStorage) {
    var Company;
    return Company = (function(superClass) {
      extend(Company, superClass);

      function Company(data) {
        this.getPusherChannel = bind(this.getPusherChannel, this);
        this.pusherSubscribe = bind(this.pusherSubscribe, this);
        var all_companies, c, child, comp, i, j, len, len1, ref1, ref2;
        Company.__super__.constructor.call(this, data);
        if (this.companies) {
          all_companies = [];
          this.child_companies = [];
          ref1 = this.companies;
          for (i = 0, len = ref1.length; i < len; i++) {
            comp = ref1[i];
            c = new BBModel.Company(halClient.$parse(comp));
            this.child_companies.push(c);
            if (c.companies) {
              ref2 = c.companies;
              for (j = 0, len1 = ref2.length; j < len1; j++) {
                child = ref2[j];
                all_companies.push(child);
              }
            } else {
              all_companies.push(c);
            }
          }
          this.companies = all_companies;
        }
      }


      /***
      * @ngdoc method
      * @name getCompanyByRef
      * @methodOf BB.Models:Company
      * @description
      * Find a child company by reference
      *
      * @returns {promise} A promise for the child company
       */

      Company.prototype.getCompanyByRef = function(ref) {
        var defer;
        defer = $q.defer();
        this.$get('companies').then(function(companies) {
          var company;
          company = _.find(companies, function(c) {
            return c.reference === ref;
          });
          if (company) {
            return defer.resolve(company);
          } else {
            return defer.reject('No company for ref ' + ref);
          }
        }, function(err) {
          console.log('err ', err);
          return defer.reject(err);
        });
        return defer.promise;
      };


      /***
      * @ngdoc method
      * @name findChildCompany
      * @methodOf BB.Models:Company
      * @description
      * Find a child company by id
      *
      * @returns {object} The child company
       */

      Company.prototype.findChildCompany = function(id) {
        var c, cname, i, j, len, len1, name, ref1, ref2;
        if (!this.companies) {
          return null;
        }
        ref1 = this.companies;
        for (i = 0, len = ref1.length; i < len; i++) {
          c = ref1[i];
          if (c.id === parseInt(id)) {
            return c;
          }
          if (c.ref && c.ref === String(id)) {
            return c;
          }
        }
        if (typeof id === "string") {
          name = id.replace(/[\s\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|'’!<>;:,.~`=+-@£&%"]/g, '').toLowerCase();
          ref2 = this.companies;
          for (j = 0, len1 = ref2.length; j < len1; j++) {
            c = ref2[j];
            cname = c.name.replace(/[\s\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|'’!<>;:,.~`=+-@£&%"]/g, '').toLowerCase();
            if (name === cname) {
              return c;
            }
          }
        }
        return null;
      };


      /***
      * @ngdoc method
      * @name getSettings
      * @methodOf BB.Models:Company
      * @description
      * Get settings company
      *
      * @returns {promise} A promise for settings company
       */

      Company.prototype.getSettings = function() {
        var def;
        def = $q.defer();
        if (this.settings) {
          def.resolve(this.settings);
        } else {
          if (this.$has('settings')) {
            this.$get('settings').then((function(_this) {
              return function(set) {
                _this.settings = new BBModel.CompanySettings(set);
                return def.resolve(_this.settings);
              };
            })(this));
          } else {
            def.reject("Company has no settings");
          }
        }
        return def.promise;
      };


      /***
      * @ngdoc method
      * @name pusherSubscribe
      * @methodOf BB.Models:Company
      * @description
      * Push subscribe for company
      *
      * @returns {object} Subscriber company
       */

      Company.prototype.pusherSubscribe = function(callback, options) {
        var channelName;
        if (options == null) {
          options = {};
        }
        if ((typeof Pusher !== "undefined" && Pusher !== null) && (this.pusher == null)) {
          this.pusher = new Pusher('c8d8cea659cc46060608', {
            encrypted: options.hasOwnProperty('encrypted') ? options.encrypted : true,
            authEndpoint: this.$link('pusher').href,
            auth: {
              headers: {
                'App-Id': AppConfig.appId,
                'App-Key': AppConfig.appKey,
                'Auth-Token': $sessionStorage.getItem('auth_token')
              }
            }
          });
          channelName = "private-c" + this.id + "-w" + this.numeric_widget_id;
          if (this.pusher.channel(channelName) == null) {
            this.pusher_channel = this.pusher.subscribe(channelName);
            this.pusher_channel.bind('booking', callback);
            this.pusher_channel.bind('cancellation', callback);
            return this.pusher_channel.bind('updating', callback);
          }
        }
      };


      /***
      * @ngdoc method
      * @name getPusherChannel
      * @methodOf BB.Models:Company
      *
      * @returns {object} Pusher channel
       */

      Company.prototype.getPusherChannel = function(model, options) {
        var channelName;
        if (options == null) {
          options = {};
        }
        if (!this.pusher) {
          this.pusher = new Pusher('c8d8cea659cc46060608', {
            encrypted: options.hasOwnProperty('encrypted') ? options.encrypted : true,
            authEndpoint: this.$link('pusher').href,
            auth: {
              headers: {
                'App-Id': AppConfig.appId,
                'App-Key': AppConfig.appKey,
                'Auth-Token': $sessionStorage.getItem('auth_token')
              }
            }
          });
        }
        if (this.$has(model)) {
          channelName = this.$href(model);
          channelName = channelName.replace(/https?:\/\//, '').replace(/\//g, '-').replace(/:/g, '_');
          if (this.pusher.channel(channelName)) {
            return this.pusher.channel(channelName);
          } else {
            this.pusher.subscribe(channelName);
            return this.pusher.channel(channelName);
          }
        }
      };

      return Company;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:CompanySettings
  *
  * @description
  * Representation of an CompanySettings Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("CompanySettingsModel", function($q, BBModel, BaseModel) {
    var CompanySettings;
    return CompanySettings = (function(superClass) {
      extend(CompanySettings, superClass);

      function CompanySettings() {
        return CompanySettings.__super__.constructor.apply(this, arguments);
      }

      return CompanySettings;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Day
  *
  * @description
  * Representation of an Day Object
  *
  * @property {string} string_date The string date
  * @property {date} date Second The date
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("DayModel", function($q, BBModel, BaseModel) {
    var Day;
    return Day = (function(superClass) {
      extend(Day, superClass);

      function Day(data) {
        Day.__super__.constructor.apply(this, arguments);
        this.string_date = this.date;
        this.date = moment(this.date);
      }


      /***
      * @ngdoc method
      * @name day
      * @methodOf BB.Models:Day
      * @description
      * Get day date
      *
      * @returns {date} The returned day
       */

      Day.prototype.day = function() {
        return this.date.date();
      };


      /***
      * @ngdoc method
      * @name off
      * @methodOf BB.Models:Day
      * @description
      * Get off by month
      *
      * @returns {date} The returned off
       */

      Day.prototype.off = function(month) {
        return this.date.month() !== month;
      };


      /***
      * @ngdoc method
      * @name class
      * @methodOf BB.Models:Day
      * @description
      * Get class in according of month
      *
      * @returns {string} The returned class
       */

      Day.prototype["class"] = function(month) {
        var str;
        str = "";
        if (this.date.month() < month) {
          str += "off off-prev";
        }
        if (this.date.month() > month) {
          str += "off off-next";
        }
        if (this.spaces === 0) {
          str += " not-avail";
        }
        return str;
      };

      return Day;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("DealModel", function($q, BBModel, BaseModel) {
    var Deal;
    return Deal = (function(superClass) {
      extend(Deal, superClass);

      function Deal() {
        return Deal.__super__.constructor.apply(this, arguments);
      }

      return Deal;

    })(BaseModel);
  });

}).call(this);


/***
* @ngdoc service
* @name BB.Models:Event
*
* @description
* This is the event object returned by the API
*
* @property {integer} id The event id
* @property {date} datetime The event date and time
* @property {string} description Description of the event
* @property {integer} status Status of the event
* @property {integer} spaces_booked The booked spaces
* @property {integer} duration Duration of the event
 */

(function() {
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("EventModel", function($q, BBModel, BaseModel, DateTimeUlititiesService) {
    var Event;
    return Event = (function(superClass) {
      extend(Event, superClass);

      function Event(data) {
        Event.__super__.constructor.call(this, data);
        this.date = moment.parseZone(this.datetime);
        this.time = new BBModel.TimeSlot({
          time: DateTimeUlititiesService.convertMomentToTime(this.date)
        });
        if (this.duration) {
          this.end_datetime = this.date.clone().add(this.duration, 'minutes');
        }
        this.date_unix = this.date.unix();
      }


      /***
      * @ngdoc method
      * @name getGroup
      * @methodOf BB.Models:Event
      * @description
      * Get event groups
      *
      * @returns {promise} A promise for the group event
       */

      Event.prototype.getGroup = function() {
        var defer, event_group;
        defer = $q.defer();
        if (this.group) {
          defer.resolve(this.group);
        } else if (this.$has('event_groups') || this.$has('event_group')) {
          event_group = 'event_group';
          if (this.$has('event_groups')) {
            event_group = 'event_groups';
          }
          this.$get(event_group).then((function(_this) {
            return function(group) {
              _this.group = new BBModel.EventGroup(group);
              return defer.resolve(_this.group);
            };
          })(this), function(err) {
            return defer.reject(err);
          });
        } else {
          defer.reject("No event group");
        }
        return defer.promise;
      };


      /***
      * @ngdoc method
      * @name getGroup
      * @methodOf BB.Models:Event
      * @description
      * Get the chains of the event
      *
      * @returns {promise} A promise for the chains event
       */

      Event.prototype.getChain = function() {
        var defer, event_chain;
        defer = $q.defer();
        if (this.chain) {
          defer.resolve(this.chain);
        } else {
          if (this.$has('event_chains') || this.$has('event_chain')) {
            event_chain = 'event_chain';
            if (this.$has('event_chains')) {
              event_chain = 'event_chains';
            }
            this.$get(event_chain).then((function(_this) {
              return function(chain) {
                _this.chain = new BBModel.EventChain(chain);
                return defer.resolve(_this.chain);
              };
            })(this));
          } else {
            defer.reject("No event chain");
          }
        }
        return defer.promise;
      };


      /***
      * @ngdoc method
      * @name getDuration
      * @methodOf BB.Models:Event
      * @description
      * Get duration of the event chains
      *
      * @returns {promise} A promise for duration of the event
       */

      Event.prototype.getDuration = function() {
        var defer;
        defer = new $q.defer();
        if (this.duration) {
          defer.resolve(this.duration);
        } else {
          this.getChain().then((function(_this) {
            return function(chain) {
              _this.duration = chain.duration;
              return defer.resolve(_this.duration);
            };
          })(this));
        }
        return defer.promise;
      };


      /***
      * @ngdoc method
      * @name getNumBooked
      * @methodOf BB.Models:Event
      * @description
      * Get the number booked 
      *
      * @returns {object} The returned number booked
       */

      Event.prototype.getNumBooked = function() {
        return this.spaces_blocked + this.spaces_booked + this.spaces_reserved + this.spaces_held;
      };


      /***
      * @ngdoc method
      * @name getSpacesLeft
      * @methodOf BB.Models:Event
      * @description
      * Get the number of spaces left (possibly limited by a specific ticket pool)
      *
      * @returns {object} The returned spaces left
       */

      Event.prototype.getSpacesLeft = function(pool) {
        if (pool == null) {
          pool = null;
        }
        if (pool && this.ticket_spaces && this.ticket_spaces[pool]) {
          return this.ticket_spaces[pool].left;
        }
        return this.num_spaces - this.getNumBooked();
      };


      /***
      * @ngdoc method
      * @name hasSpace
      * @methodOf BB.Models:Event
      * @description
      * Checks if this considered a valid space
      *
      * @returns {boolean} If this is a valid space
       */

      Event.prototype.hasSpace = function() {
        return this.getSpacesLeft() > 0;
      };


      /***
      * @ngdoc method
      * @name hasWaitlistSpace
      * @methodOf BB.Models:Event
      * @description
      * Checks if this considered a valid waiting list space
      *
      * @returns {boolean} If this is a valid waiting list space
       */

      Event.prototype.hasWaitlistSpace = function() {
        return this.getSpacesLeft() <= 0 && this.getChain().waitlength > this.spaces_wait;
      };


      /***
      * @ngdoc method
      * @name getRemainingDescription
      * @methodOf BB.Models:Event
      * @description
      * Get the remaining description
      *
      * @returns {object} The returned remaining description
       */

      Event.prototype.getRemainingDescription = function() {
        var left;
        left = this.getSpacesLeft();
        if (left > 0 && left < 3) {
          return "Only " + left + " " + (left > 1 ? "spaces" : "space") + " left";
        }
        if (this.hasWaitlistSpace()) {
          return "Join Waitlist";
        }
        return "";
      };


      /***
      * @ngdoc method
      * @name select
      * @methodOf BB.Models:Event
      * @description
      * Checks is this considered a selected
      *
      * @returns {boolean} If this is a selected
       */

      Event.prototype.select = function() {
        return this.selected = true;
      };


      /***
      * @ngdoc method
      * @name unselect
      * @methodOf BB.Models:Event
      * @description
      * Unselect if is selected
      *
      * @returns {boolean} If this is a unselected
       */

      Event.prototype.unselect = function() {
        if (this.selected) {
          return delete this.selected;
        }
      };


      /***
      * @ngdoc method
      * @name prepEvent
      * @methodOf BB.Models:Event
      * @description
      * Prepare the event
      *
      * @returns {promise} A promise for the event
       */

      Event.prototype.prepEvent = function() {
        var def;
        def = $q.defer();
        this.getChain().then((function(_this) {
          return function() {
            if (_this.chain.$has('address')) {
              _this.chain.getAddressPromise().then(function(address) {
                return _this.chain.address = address;
              });
            }
            return _this.chain.getTickets().then(function(tickets) {
              var i, len, ref, ticket;
              _this.tickets = tickets;
              _this.price_range = {};
              if (tickets && tickets.length > 0) {
                ref = _this.tickets;
                for (i = 0, len = ref.length; i < len; i++) {
                  ticket = ref[i];
                  if (!_this.price_range.from || (_this.price_range.from && ticket.price < _this.price_range.from)) {
                    _this.price_range.from = ticket.price;
                  }
                  if (!_this.price_range.to || (_this.price_range.to && ticket.price > _this.price_range.to)) {
                    _this.price_range.to = ticket.price;
                  }
                  ticket.old_price = ticket.price;
                }
              } else {
                _this.price_range.from = _this.price;
                _this.price_range.to = _this.price;
              }
              _this.ticket_prices = _.indexBy(tickets, 'name');
              return def.resolve(_this);
            });
          };
        })(this));
        return def.promise;
      };


      /***
      * @ngdoc method
      * @name updatePrice
      * @methodOf BB.Models:Event
      * @description
      * Update price for the ticket
      *
      * @returns {object} The returned update price
       */

      Event.prototype.updatePrice = function() {
        var i, len, ref, results, ticket;
        ref = this.tickets;
        results = [];
        for (i = 0, len = ref.length; i < len; i++) {
          ticket = ref[i];
          if (ticket.pre_paid_booking_id) {
            results.push(ticket.price = 0);
          } else {
            results.push(ticket.price = ticket.old_price);
          }
        }
        return results;
      };

      return Event;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:EventChain
  *
  * @description
  * Representation of an EventChain Object
  * 
  * @property {integer} id The id of event chain
  * @property {string} name Name of the event chain
  * @property {string} description The description of the event
  * @property {integer} capacity_view The capacity view
  * @property {date} start_date Event chain start date
  * @property {date} finish_date Event chain finish date
  * @property {integer} price The price of the event chain
  * @property {string} ticket_type Type of the ticket
  * @property {boolean} course Verify is couse exist or not
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("EventChainModel", function($q, BBModel, BaseModel) {
    var EventChain;
    return EventChain = (function(superClass) {
      var setCapacityView;

      extend(EventChain, superClass);

      function EventChain(data) {
        EventChain.__super__.constructor.apply(this, arguments);
        this.capacity_view = setCapacityView(this.capacity_view);
      }

      EventChain.prototype.name = function() {
        return this._data.name;
      };


      /***
      * @ngdoc method
      * @name isSingleBooking
      * @methodOf BB.Models:EventChain
      * @description
      * Verify if is a single booking
      *
      * @returns {array} If maximum number of bookings is equal with 1 and not have an ticket sets
       */

      EventChain.prototype.isSingleBooking = function() {
        return this.max_num_bookings === 1 && !this.$has('ticket_sets');
      };


      /***
      * @ngdoc method
      * @name hasTickets
      * @methodOf BB.Models:EventChain
      * @description
      * Checks if this is considered a valid tickets
      *
      * @returns {boolean} If this have an ticket sets
       */

      EventChain.prototype.hasTickets = function() {
        return this.$has('ticket_sets');
      };


      /***
      * @ngdoc method
      * @name getTickets
      * @methodOf BB.Models:EventChain
      * @description
      * Get the tickets of the event
      *
      * @returns {promise} A promise for the tickets
       */

      EventChain.prototype.getTickets = function() {
        var def;
        def = $q.defer();
        if (this.tickets) {
          def.resolve(this.tickets);
        } else {
          if (this.$has('ticket_sets')) {
            this.$get('ticket_sets').then((function(_this) {
              return function(tickets) {
                var i, len, ticket;
                _this.tickets = [];
                for (i = 0, len = tickets.length; i < len; i++) {
                  ticket = tickets[i];
                  _this.tickets.push(new BBModel.EventTicket(ticket));
                }
                _this.adjustTicketsForRemaining();
                return def.resolve(_this.tickets);
              };
            })(this));
          } else {
            this.tickets = [
              new BBModel.EventTicket({
                name: "Admittance",
                min_num_bookings: 1,
                max_num_bookings: this.max_num_bookings,
                type: "normal",
                price: this.price
              })
            ];
            this.adjustTicketsForRemaining();
            def.resolve(this.tickets);
          }
        }
        return def.promise;
      };


      /***
      * @ngdoc method
      * @name adjustTicketsForRemaining
      * @methodOf BB.Models:EventChain
      * @description
      * Adjust the number of tickets that can be booked due to changes in the number of remaining spaces for each ticket set
      *
      * @returns {object} The returned adjust tickets for remaining
       */

      EventChain.prototype.adjustTicketsForRemaining = function() {
        var i, len, ref, results;
        if (this.tickets) {
          ref = this.tickets;
          results = [];
          for (i = 0, len = ref.length; i < len; i++) {
            this.ticket = ref[i];
            results.push(this.ticket.max_spaces = this.spaces);
          }
          return results;
        }
      };


      /***
      * @ngdoc method
      * @name setCapacityView
      * @methodOf BB.Models:EventChain
      * @description
      * Sets the capacity_view (referred to as the "spaces view" in admin console) to a more helpful String
      * @returns {String} code for the capacity_view
       */

      setCapacityView = function(capacity_view) {
        var capacity_view_str;
        switch (capacity_view) {
          case 0:
            capacity_view_str = "DO_NOT_DISPLAY";
            break;
          case 1:
            capacity_view_str = "NUM_SPACES";
            break;
          case 2:
            capacity_view_str = "NUM_SPACES_LEFT";
            break;
          case 3:
            capacity_view_str = "NUM_SPACES_AND_SPACES_LEFT";
            break;
          default:
            capacity_view_str = "NUM_SPACES_AND_SPACES_LEFT";
        }
        return capacity_view_str;
      };

      return EventChain;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:EventGroup
  *
  * @description
  * Representation of an EventGroup Object
  *
  * @property {integer} total_entries The total of entries in  event groupst
  * @property {array} event_chains An array with items of the event
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("EventGroupModel", function($q, BBModel, BaseModel) {
    var EventGroup;
    return EventGroup = (function(superClass) {
      extend(EventGroup, superClass);

      function EventGroup() {
        return EventGroup.__super__.constructor.apply(this, arguments);
      }

      EventGroup.prototype.name = function() {
        return this._data.name;
      };

      EventGroup.prototype.colour = function() {
        return this._data.colour;
      };

      return EventGroup;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:EventSequence
  *
  * @description
  * Representation of an EventSequence Object
  *
  * @property {integer} total_entries The total of entries in  event groupst
  * @property {array} event_chains An array with items of the event
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("EventSequenceModel", function($q, BBModel, BaseModel) {
    var EventSequence;
    return EventSequence = (function(superClass) {
      extend(EventSequence, superClass);

      function EventSequence() {
        return EventSequence.__super__.constructor.apply(this, arguments);
      }

      EventSequence.prototype.name = function() {
        return this._data.name;
      };

      return EventSequence;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:EventTicket
  *
  * @description
  * Representation of an EventTicket Object
  *
  * @property {integer} max The maximum of the event ticket
  * @property {integer} max_num_bookings The maximum number of the bookings
  * @property {integer} max_spaces The maximum spaces of the evenet
  * @property {integer} counts_as The counts as
  * @property {string} pool_name The pool name
  * @property {string} name The name 
  * @property {string} min_num_bookings The minimum number of the bookings
  * @property {string} qty The quantity of the event ticket
  * @property {string} totalQty The total quantity of the event ticket
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("EventTicketModel", function($q, BBModel, BaseModel) {
    var EventTicket;
    return EventTicket = (function(superClass) {
      extend(EventTicket, superClass);

      function EventTicket(data) {
        var ms;
        EventTicket.__super__.constructor.call(this, data);
        this.max = this.max_num_bookings;
        if (this.max_spaces) {
          ms = this.max_spaces;
          if (this.counts_as) {
            ms = this.max_spaces / this.counts_as;
          }
          if (ms < max) {
            this.max = ms;
          }
        }
      }


      /***
      * @ngdoc method
      * @name fullName
      * @methodOf BB.Models:EventTicket
      * @description
      * Get the full name
      *
      * @returns {object} The returned full name
       */

      EventTicket.prototype.fullName = function() {
        if (this.pool_name) {
          return this.pool_name + " - " + this.name;
        }
        return this.name;
      };


      /***
      * @ngdoc method
      * @name getRange
      * @methodOf BB.Models:EventTicket
      * @description
      * Get the range between minimum number of bookings and the maximum number of bookings
      *
      * @returns {array} The returned range
       */

      EventTicket.prototype.getRange = function(cap) {
        var c, i, ref, ref1, results;
        if (cap) {
          c = cap;
          if (this.counts_as) {
            c = cap / this.counts_as;
          }
          if (c + this.min_num_bookings < this.max) {
            this.max = c + this.min_num_bookings;
          }
        }
        return [0].concat((function() {
          results = [];
          for (var i = ref = this.min_num_bookings, ref1 = this.max; ref <= ref1 ? i <= ref1 : i >= ref1; ref <= ref1 ? i++ : i--){ results.push(i); }
          return results;
        }).apply(this));
      };


      /***
      * @ngdoc method
      * @name totalQty
      * @methodOf BB.Models:EventTicket
      * @description
      * Get the total quantity of the event ticket
      *
      * @returns {array} The returned total quantity
       */

      EventTicket.prototype.totalQty = function() {
        if (!this.qty) {
          return 0;
        }
        if (!this.counts_as) {
          return this.qty;
        }
        return this.qty * this.counts_as;
      };


      /***
      * @ngdoc method
      * @name getMax
      * @methodOf BB.Models:EventTicket
      * @description
      * Get the maximum - this looks at an optional cap, the maximum available and potential a running count of tickets already selected (from passing in the event being booked)
      *
      * @returns {array} The returned maximum
       */

      EventTicket.prototype.getMax = function(cap, ev) {
        var c, i, len, live_max, ref, ticket, used;
        if (ev == null) {
          ev = null;
        }
        live_max = this.max;
        if (ev) {
          used = 0;
          ref = ev.tickets;
          for (i = 0, len = ref.length; i < len; i++) {
            ticket = ref[i];
            used += ticket.totalQty();
          }
          if (this.qty) {
            used = used - this.totalQty();
          }
          if (this.counts_as) {
            used = Math.ceil(used / this.counts_as);
          }
          live_max = live_max - used;
          if (live_max < 0) {
            live_max = 0;
          }
        }
        if (cap) {
          c = cap;
          if (this.counts_as) {
            c = cap / this.counts_as;
          }
          if (c + this.min_num_bookings < live_max) {
            return c + this.min_num_bookings;
          }
        }
        return live_max;
      };


      /***
      * @ngdoc method
      * @name add
      * @methodOf BB.Models:EventTicket
      * @description
      * Add to the a quantity a new value
      *
      * @returns {array} The returned new quantity added
       */

      EventTicket.prototype.add = function(value) {
        if (!this.qty) {
          this.qty = 0;
        }
        this.qty = parseInt(this.qty);
        if (angular.isNumber(this.qty) && (this.qty >= this.max && value > 0) || (this.qty === 0 && value < 0)) {
          return;
        }
        return this.qty += value;
      };


      /***
      * @ngdoc method
      * @name subtract
      * @methodOf BB.Models:EventTicket
      * @description
      * Subtract a value from the quantity
      *
      * @returns {array} The returned substract
       */

      EventTicket.prototype.subtract = function(value) {
        return this.add(-value);
      };

      return EventTicket;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ExternalPurchaseModel", function($q, BBModel, BaseModel) {
    var ExternalPurchase;
    return ExternalPurchase = (function(superClass) {
      extend(ExternalPurchase, superClass);

      function ExternalPurchase() {
        return ExternalPurchase.__super__.constructor.apply(this, arguments);
      }

      return ExternalPurchase;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Image
  *
  * @description
  * Representation of an Image Object
  *
  * @property {array} iamges An array with event images
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ImageModel", function($q, $filter, BBModel, BaseModel) {
    var Image;
    return Image = (function(superClass) {
      extend(Image, superClass);

      function Image(data) {
        Image.__super__.constructor.call(this, data);
      }

      return Image;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:ItemDetails
  *
  * @description
  * Representation of an ItemDetails Object
  *
  * @property {string} self The self
  * @property {array} questions The questions
  * @property {array} survey_questions The survey questions
  * @property {string} hasQuestions Has questions about the item details
  * @property {string} hasSurveyQuestions Has survey questions about the item details
  * @property {string} checkConditionalQuestions Check conditional questions about the item details
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ItemDetailsModel", function($q, BBModel, BaseModel, $bbug, QuestionService) {
    var ItemDetails;
    return ItemDetails = (function(superClass) {
      extend(ItemDetails, superClass);

      function ItemDetails(data) {
        var i, len, q, ref;
        this._data = data;
        if (this._data) {
          this.self = this._data.$href("self");
        }
        this.questions = [];
        this.survey_questions = [];
        if (data) {
          ref = data.questions;
          for (i = 0, len = ref.length; i < len; i++) {
            q = ref[i];
            if (q.outcome === false) {
              if (data.currency_code) {
                q.currency_code = data.currency_code;
              }
              this.questions.push(new BBModel.Question(q));
            } else {
              this.survey_questions.push(new BBModel.SurveyQuestion(q));
            }
          }
        }
        this.hasQuestions = this.questions.length > 0;
        this.hasSurveyQuestions = this.survey_questions.length > 0;
      }


      /***
      * @ngdoc method
      * @name questionPrice
      * @methodOf BB.Models:ItemDetails
      * @description
      * Get question about price in according of quantity
      *
      * @returns {integer} The returned price
       */

      ItemDetails.prototype.questionPrice = function(qty) {
        var i, len, price, q, ref;
        qty || (qty = 1);
        this.checkConditionalQuestions();
        price = 0;
        ref = this.questions;
        for (i = 0, len = ref.length; i < len; i++) {
          q = ref[i];
          price += q.selectedPriceQty(qty);
        }
        return price;
      };


      /***
      * @ngdoc method
      * @name checkConditionalQuestions
      * @methodOf BB.Models:ItemDetails
      * @description
      * Checks if exist conditional questions 
      *
      * @returns {boolean} The returned existing conditional questions
       */

      ItemDetails.prototype.checkConditionalQuestions = function() {
        return QuestionService.checkConditionalQuestions(this.questions);
      };


      /***
      * @ngdoc method
      * @name getPostData
      * @methodOf BB.Models:ItemDetails
      * @description
      * Get data 
      *
      * @returns {array} The returned data
       */

      ItemDetails.prototype.getPostData = function() {
        var data, i, len, q, ref;
        data = [];
        ref = this.questions;
        for (i = 0, len = ref.length; i < len; i++) {
          q = ref[i];
          if (q.currentlyShown) {
            data.push(q.getPostData());
          }
        }
        return data;
      };


      /***
      * @ngdoc method
      * @name setAnswers
      * @methodOf BB.Models:ItemDetails
      * @description
      * Load the answers from an answer set - probably from loading an existing basket item
      *
      * @returns {object} The returned answers set
       */

      ItemDetails.prototype.setAnswers = function(answers) {
        var a, ahash, i, j, len, len1, q, ref;
        ahash = {};
        for (i = 0, len = answers.length; i < len; i++) {
          a = answers[i];
          ahash[a.id] = a;
        }
        ref = this.questions;
        for (j = 0, len1 = ref.length; j < len1; j++) {
          q = ref[j];
          if (ahash[q.id]) {
            q.answer = ahash[q.id].answer;
          }
        }
        return this.checkConditionalQuestions();
      };


      /***
      * @ngdoc method
      * @name getQuestion
      * @methodOf BB.Models:ItemDetails
      * @description
      * Get question about item details by id
      *
      * @returns {object} The returned question
       */

      ItemDetails.prototype.getQuestion = function(id) {
        return _.findWhere(this.questions, {
          id: id
        });
      };

      return ItemDetails;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("MembershipLevelModel", function($q, BBModel, BaseModel) {
    var MembershipLevel;
    return MembershipLevel = (function(superClass) {
      extend(MembershipLevel, superClass);

      function MembershipLevel() {
        return MembershipLevel.__super__.constructor.apply(this, arguments);
      }

      return MembershipLevel;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:PackageItem
  *
  * @description
  * Representation of a PackageItem Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("PackageItemModel", function($q, BBModel, BaseModel) {
    var PackageItem;
    return PackageItem = (function(superClass) {
      extend(PackageItem, superClass);

      function PackageItem() {
        return PackageItem.__super__.constructor.apply(this, arguments);
      }

      return PackageItem;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Person
  *
  * @description
  * Representation of an Person Object
  *
  * @property {integer} id Person id
  * @property {string} name Person name
  * @property {boolean} deleted Verify if person is deleted or not
  * @property {boolean} disabled Verify if person is disabled or not
  * @property {integer} order The person order
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("PersonModel", function($q, BBModel, BaseModel) {
    var Person;
    return Person = (function(superClass) {
      extend(Person, superClass);

      function Person() {
        return Person.__super__.constructor.apply(this, arguments);
      }

      return Person;

    })(BaseModel);
  });

}).call(this);


/***
* @ngdoc service
* @name BB.Models:PrePaidBooking
*
* @description
* Representation of an PrePaidBooking Object
 */

(function() {
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("PrePaidBookingModel", function($q, BBModel, BaseModel) {
    var PrePaidBooking;
    return PrePaidBooking = (function(superClass) {
      extend(PrePaidBooking, superClass);

      function PrePaidBooking(data) {
        PrePaidBooking.__super__.constructor.call(this, data);
        if (this.book_by) {
          this.book_by = moment(this.book_by);
        }
        if (this.use_by) {
          this.use_by = moment(this.use_by);
        }
        if (this.use_from) {
          this.use_from = moment(this.use_from);
        }
        this.expired = (this.book_by && moment().isAfter(this.book_by, 'day')) || (this.use_by && moment().isAfter(this.use_by, 'day')) || false;
      }

      PrePaidBooking.prototype.checkValidity = function(item) {
        if (this.service_id && item.service_id && this.service_id !== item.service_id) {
          return false;
        } else if (this.resource_id && item.resource_id && this.resource_id !== item.resource_id) {
          return false;
        } else if (this.person_id && item.person_id && this.person_id !== item.person_id) {
          return false;
        } else {
          return true;
        }
      };

      return PrePaidBooking;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ProductModel", function($q, BBModel, BaseModel) {
    var Product;
    return Product = (function(superClass) {
      extend(Product, superClass);

      function Product() {
        return Product.__super__.constructor.apply(this, arguments);
      }

      return Product;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:PurchaseItem
  *
  * @description
  * Representation of an PurchaseItem Object
  *
  * @property {float} price Price of the purchase item
  * @property {float} paid Purchase item paid
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("PurchaseItemModel", function($q, BBModel, BaseModel) {
    var PurchaseItem;
    return PurchaseItem = (function(superClass) {
      extend(PurchaseItem, superClass);

      function PurchaseItem(data) {
        PurchaseItem.__super__.constructor.call(this, data);
        this.parts_links = {};
        if (data) {
          if (data.$has('service')) {
            this.parts_links.service = data.$href('service');
          }
          if (data.$has('resource')) {
            this.parts_links.resource = data.$href('resource');
          }
          if (data.$has('person')) {
            this.parts_links.person = data.$href('person');
          }
          if (data.$has('company')) {
            this.parts_links.company = data.$href('company');
          }
        }
      }


      /***
      * @ngdoc method
      * @name describe
      * @methodOf BB.Models:PurchaseItem
      * @description
      * Describe the item for purchase
      *
      * @returns {object} The returned describe
       */

      PurchaseItem.prototype.describe = function() {
        return this.get('describe');
      };


      /***
      * @ngdoc method
      * @name full_describe
      * @methodOf BB.Models:PurchaseItem
      * @description
      * Full description of the item purchase
      *
      * @returns {object} The returned full describe
       */

      PurchaseItem.prototype.full_describe = function() {
        return this.get('full_describe');
      };


      /***
      * @ngdoc method
      * @name hasPrice
      * @methodOf BB.Models:PurchaseItem
      * @description
      * Checks if the item for purchase have a price
      *
      * @returns {boolean} If the item for purchase have a price
       */

      PurchaseItem.prototype.hasPrice = function() {
        return this.price && this.price > 0;
      };

      return PurchaseItem;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:PurchaseTotal
  *
  * @description
  * Representation of an PurchaseTotal Object
  *
  * @property {float} total_price The total price of items
  * @property {float} price Price of items
  * @property {float} tax_payable_on_price The tax payable on price of the item
  * @property {float} due_now The due now
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("PurchaseTotalModel", function($q, BBModel, BaseModel) {
    var PurchaseTotal;
    return PurchaseTotal = (function(superClass) {
      extend(PurchaseTotal, superClass);

      function PurchaseTotal(data) {
        var cprom;
        PurchaseTotal.__super__.constructor.call(this, data);
        this.promise = this._data.$get('purchase_items');
        this.purchase_items = [];
        this.promise.then((function(_this) {
          return function(items) {
            var i, item, len, results;
            results = [];
            for (i = 0, len = items.length; i < len; i++) {
              item = items[i];
              results.push(_this.purchase_items.push(new BBModel.PurchaseItem(item)));
            }
            return results;
          };
        })(this));
        if (this._data.$has('client')) {
          cprom = data.$get('client');
          cprom.then((function(_this) {
            return function(client) {
              return _this.client = new BBModel.Client(client);
            };
          })(this));
        }
        this.created_at = moment.parseZone(this.created_at);
        if (this.time_zone) {
          this.created_at.tz(this.time_zone);
        }
      }


      /***
      * @ngdoc method
      * @name icalLink
      * @methodOf BB.Models:PurchaseTotal
      * @description
      * Get the icalLink
      *
      * @returns {object} The returned icalLink
       */

      PurchaseTotal.prototype.icalLink = function() {
        return this._data.$href('ical');
      };


      /***
      * @ngdoc method
      * @name webcalLink
      * @methodOf BB.Models:PurchaseTotal
      * @description
      * Get webcalLink
      *
      * @returns {object} The returned webcalLink
       */

      PurchaseTotal.prototype.webcalLink = function() {
        return this._data.$href('ical');
      };


      /***
      * @ngdoc method
      * @name gcalLink
      * @methodOf BB.Models:PurchaseTotal
      * @description
      * Get the gcalLink
      *
      * @returns {object} The returned gcalLink
       */

      PurchaseTotal.prototype.gcalLink = function() {
        return this._data.$href('gcal');
      };


      /***
      * @ngdoc method
      * @name id
      * @methodOf BB.Models:PurchaseTotal
      * @description
      * Get the id
      *
      * @returns {object} The returned id
       */

      PurchaseTotal.prototype.id = function() {
        return this.get('id');
      };

      return PurchaseTotal;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Question
  *
  * @description
  * Representation of an Question Object
  *
  * @property {integer} company_id The company id
  * @property {array} question An array with questions
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("QuestionModel", function($q, $filter, BBModel, BaseModel) {
    var Question;
    return Question = (function(superClass) {
      extend(Question, superClass);

      function Question(data) {
        var currency, i, len, option, ref;
        Question.__super__.constructor.call(this, data);
        if (this.price) {
          this.price = parseFloat(this.price);
        }
        if (this._data["default"]) {
          this.answer = this._data["default"];
        }
        if (this._data.options) {
          ref = this._data.options;
          for (i = 0, len = ref.length; i < len; i++) {
            option = ref[i];
            if (option.is_default) {
              this.answer = option.name;
            }
            if (this.hasPrice()) {
              option.price = parseFloat(option.price);
              currency = data.currency_code ? data.currency_code : 'GBP';
              option.display_name = option.name + " (" + ($filter('currency')(option.price, currency)) + ")";
            } else {
              option.display_name = option.name;
            }
          }
        }
        if (this._data.detail_type === "check" || this._data.detail_type === "check-price") {
          this.answer = this._data["default"] && this._data["default"] === "1";
        }
        this.currentlyShown = true;
      }


      /***
      * @ngdoc method
      * @name hasPrice
      * @methodOf BB.Models:Question
      * @description
      * Check if it contains one of the following: "check-price", "select-price", "radio-price"
      *
      * @returns {boolean} If this contains detail_type
       */

      Question.prototype.hasPrice = function() {
        return this.detail_type === "check-price" || this.detail_type === "select-price" || this.detail_type === "radio-price";
      };


      /***
      * @ngdoc method
      * @name selectedPrice
      * @methodOf BB.Models:Question
      * @description
      * Select price if detail type si equal with check-price
      *
      * @returns {float} The returned selected price
       */

      Question.prototype.selectedPrice = function() {
        var i, len, option, ref;
        if (!this.hasPrice()) {
          return 0;
        }
        if (this.detail_type === "check-price") {
          return (this.answer ? this.price : 0);
        }
        ref = this._data.options;
        for (i = 0, len = ref.length; i < len; i++) {
          option = ref[i];
          if (this.answer === option.name) {
            return option.price;
          }
        }
        return 0;
      };


      /***
      * @ngdoc method
      * @name selectedPriceQty
      * @methodOf BB.Models:Question
      * @description
      * Select price quantity if selected price has been selected
      *
      * @returns {object} The returned selected price quantity
       */

      Question.prototype.selectedPriceQty = function(qty) {
        var p;
        qty || (qty = 1);
        p = this.selectedPrice();
        if (this.price_per_booking) {
          p = p * qty;
        }
        return p;
      };


      /***
      * @ngdoc method
      * @name getAnswerId
      * @methodOf BB.Models:Question
      * @description
      * Get answer id
      *
      * @returns {object} The returned answer id
       */

      Question.prototype.getAnswerId = function() {
        var i, len, o, ref;
        if (!this.answer || !this.options || this.options.length === 0) {
          return null;
        }
        ref = this.options;
        for (i = 0, len = ref.length; i < len; i++) {
          o = ref[i];
          if (this.answer === o.name) {
            return o.id;
          }
        }
        return null;
      };


      /***
      * @ngdoc method
      * @name showElement
      * @methodOf BB.Models:Question
      * @description
      * Show element
      *
      * @returns {boolean} If element is displayed
       */

      Question.prototype.showElement = function() {
        return this.currentlyShown = true;
      };


      /***
      * @ngdoc hideElement
      * @name showElement
      * @methodOf BB.Models:Question
      * @description
      * Hide element
      *
      * @returns {boolean} If element is hidden
       */

      Question.prototype.hideElement = function() {
        return this.currentlyShown = false;
      };


      /***
      * @ngdoc hideElement
      * @name getPostData
      * @methodOf BB.Models:Question
      * @description
      * Get post data
      *
      * @returns {object} The returned post data
       */

      Question.prototype.getPostData = function() {
        var p, x;
        x = {};
        x.id = this.id;
        x.answer = this.answer;
        if (this.detail_type === "date" && this.answer) {
          x.answer = moment(this.answer).toISODate();
        }
        p = this.selectedPrice();
        if (p) {
          x.price = p;
        }
        return x;
      };

      return Question;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Resource
  *
  * @description
  * Representation of an Resource Object
  *
  * @property {integer} total_entries The total entries
  * @property {array} resources An array with resources elements
  * @property {integer} id The resources id
  * @property {string} name Name of resources
  * @propertu {string} type Type of resources
  * @property {boolean} deleted Verify if resources is deleted or not
  * @property {boolean} disabled Verify if resources is disabled or not
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ResourceModel", function($q, BBModel, BaseModel) {
    var Resource;
    return Resource = (function(superClass) {
      extend(Resource, superClass);

      function Resource() {
        return Resource.__super__.constructor.apply(this, arguments);
      }

      return Resource;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Service
  *
  * @description
  * Representation of an Service Object
  *
  * @property {integer} id Id of the service
  * @property {string} name The name of service
  * @property {date} duration Duration of the service
  * @property {float} prices The prices of the service
  * @property {integer} detail_group_id The detail group id
  * @property {date} booking_time_step The time step of the booking
  * @property {integer} min_bookings The minimum number of bookings
  * @property {integer} max_booings The maximum number of bookings
   */
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("ServiceModel", function($q, BBModel, BaseModel) {
    var Service;
    return Service = (function(superClass) {
      extend(Service, superClass);

      function Service(data) {
        this.days_array = bind(this.days_array, this);
        this.getCategoryPromise = bind(this.getCategoryPromise, this);
        Service.__super__.constructor.apply(this, arguments);
        if (this.prices && this.prices.length > 0) {
          this.price = this.prices[0];
        }
        if (this.durations && this.durations.length > 0) {
          this.duration = this.durations[0];
        }
        if (!this.listed_durations) {
          this.listed_durations = this.durations;
        }
        if (this.listed_durations && this.listed_durations.length > 0) {
          this.listed_duration = this.listed_durations[0];
        }
        this.min_advance_datetime = moment().add(this.min_advance_period, 'seconds');
        this.max_advance_datetime = moment().add(this.max_advance_period, 'seconds');
      }


      /***
      * @ngdoc method
      * @name getPriceByDuration
      * @methodOf BB.Models:Service
      * @description
      * Get price by duration in function of duration
      *
      * @returns {object} The returning price by duration
       */

      Service.prototype.getPriceByDuration = function(dur) {
        var d, i, j, len, ref;
        ref = this.durations;
        for (i = j = 0, len = ref.length; j < len; i = ++j) {
          d = ref[i];
          if (d === dur) {
            return this.prices[i];
          }
        }
      };


      /***
      * @ngdoc method
      * @name getCategoryPromise
      * @methodOf BB.Models:Service
      * @description
      * Get category promise
      *
      * @returns {object} The returning category promise
       */

      Service.prototype.getCategoryPromise = function() {
        var prom;
        if (!this.$has('category')) {
          return null;
        }
        prom = this.$get('category');
        prom.then((function(_this) {
          return function(cat) {
            return _this.category = new BBModel.Category(cat);
          };
        })(this));
        return prom;
      };


      /***
      * @ngdoc method
      * @name days_array
      * @methodOf BB.Models:Service
      * @description
      * Put days in array
      *
      * @returns {array} The returning days array
       */

      Service.prototype.days_array = function() {
        var arr, j, ref, ref1, str, x;
        arr = [];
        for (x = j = ref = this.min_bookings, ref1 = this.max_bookings; ref <= ref1 ? j <= ref1 : j >= ref1; x = ref <= ref1 ? ++j : --j) {
          str = "" + x + " day";
          if (x > 1) {
            str += "s";
          }
          arr.push({
            name: str,
            val: x
          });
        }
        return arr;
      };

      return Service;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Slot
  *
  * @description
  * Representation of an Slot Object
  *
  * @property {integer} total_entries The The total entries of the slot
  * @property {array} slots An array with slots
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("SlotModel", function($q, BBModel, BaseModel) {
    var Slot;
    return Slot = (function(superClass) {
      extend(Slot, superClass);

      function Slot(data) {
        Slot.__super__.constructor.call(this, data);
        this.datetime = moment(data.datetime);
      }

      return Slot;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:Space
  *
  * @description
  * Representation of an Space Object
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("SpaceModel", function($q, BBModel, BaseModel) {
    var Space;
    return Space = (function(superClass) {
      extend(Space, superClass);

      function Space() {
        return Space.__super__.constructor.apply(this, arguments);
      }

      return Space;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:SurveyQuestion
  *
  * @description
  * Representation of an SurveyQuestion Object
  *
  * @property {integer} company_id The company id
  * @property {array} questions An array with questions
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("SurveyQuestionModel", function($q, $window, BBModel, BaseModel, QuestionModel) {
    var SurveyQuestion;
    return SurveyQuestion = (function(superClass) {
      extend(SurveyQuestion, superClass);

      function SurveyQuestion() {
        return SurveyQuestion.__super__.constructor.apply(this, arguments);
      }

      return SurveyQuestion;

    })(QuestionModel);
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:TimeSlot
  *
  * @description
  * Representation of an TimeSlot Object
  *
  * @property {string} service The service
  * @property {date} time_12 The time_12 of time slot
  * @property {date} time_24 The time_24 of time slot
  * @property {date} start The start time of the slot
  * @property {date} end The end time of the slot
  * @property {string} service The service of time slot
  * @property {string} get Get the time slot
  * @property {string} selected The selected
  * @property {boolean} disabled Verify if time slot are disabled or not
  * @property {string} disabled_reason The disabled reason
  * @property {string} availability The availability of time slot
  * @property {string} avail The avail of time slot
   */
  var extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("TimeSlotModel", function($q, $window, BBModel, BaseModel, DateTimeUlititiesService) {
    var TimeSlot;
    return TimeSlot = (function(superClass) {
      extend(TimeSlot, superClass);

      function TimeSlot(data, service) {
        TimeSlot.__super__.constructor.call(this, data);
        this.service = service;
        this.time_12 = this.print_time12();
        this.time_24 = this.print_time();
        this.time_moment = DateTimeUlititiesService.convertTimeSlotToMoment({
          date: moment()
        }, this);
      }


      /***
      * @ngdoc method
      * @name print_time
      * @methodOf BB.Models:TimeSlot
      * @description
      * Print time of the slot
      *
      * @returns {date} The returning time
       */

      TimeSlot.prototype.print_time = function() {
        var min, t;
        if (this.start) {
          return this.start.format("h:mm");
        } else {
          t = this.get('time');
          if (t % 60 < 10) {
            min = "0" + t % 60;
          } else {
            min = t % 60;
          }
          return "" + Math.floor(t / 60) + ":" + min;
        }
      };


      /***
      * @ngdoc method
      * @name print_end_time
      * @methodOf BB.Models:TimeSlot
      * @description
      * Print end time of the slot
      *
      * @returns {date} The returning end time
       */

      TimeSlot.prototype.print_end_time = function(dur) {
        var min, t;
        if (this.end) {
          return this.end.format("h:mm");
        } else {
          if (!dur) {
            dur = this.service.listed_durations[0];
          }
          t = this.get('time') + dur;
          if (t % 60 < 10) {
            min = "0" + t % 60;
          } else {
            min = t % 60;
          }
          return "" + Math.floor(t / 60) + ":" + min;
        }
      };


      /***
      * @ngdoc method
      * @name print_time12
      * @methodOf BB.Models:TimeSlot
      * @description
      * Print 12 hour time
      *
      * @returns {date} The returning 12 hour time
       */

      TimeSlot.prototype.print_time12 = function(show_suffix) {
        var h, m, suffix, t, time;
        if (show_suffix == null) {
          show_suffix = true;
        }
        t = this.get('time');
        h = Math.floor(t / 60);
        m = t % 60;
        suffix = 'am';
        if (h >= 12) {
          suffix = 'pm';
        }
        if (h > 12) {
          h -= 12;
        }
        time = $window.sprintf("%d.%02d", h, m);
        if (show_suffix) {
          time += suffix;
        }
        return time;
      };


      /***
      * @ngdoc method
      * @name print_end_time12
      * @methodOf BB.Models:TimeSlot
      * @description
      * Print 12 hour end time
      *
      * @returns {date} The returning 12 hour end time
       */

      TimeSlot.prototype.print_end_time12 = function(show_suffix, dur) {
        var end_time, h, m, suffix, t;
        if (show_suffix == null) {
          show_suffix = true;
        }
        dur = null;
        if (!dur) {
          if (this.service.listed_duration != null) {
            dur = this.service.listed_duration;
          } else {
            dur = this.service.listed_durations[0];
          }
        }
        t = this.get('time') + dur;
        h = Math.floor(t / 60);
        m = t % 60;
        suffix = 'am';
        if (h >= 12) {
          suffix = 'pm';
        }
        if (h > 12) {
          h -= 12;
        }
        end_time = $window.sprintf("%d.%02d", h, m);
        if (show_suffix) {
          end_time += suffix;
        }
        return end_time;
      };


      /***
      * @ngdoc method
      * @name availability
      * @methodOf BB.Models:TimeSlot
      * @description
      * Get availability
      *
      * @returns {object} The returning availability
       */

      TimeSlot.prototype.availability = function() {
        return this.avail;
      };


      /***
      * @ngdoc method
      * @name select
      * @methodOf BB.Models:TimeSlot
      * @description
      * Checks if selected is true
      *
      * @returns {boolean} If this is checked
       */

      TimeSlot.prototype.select = function() {
        return this.selected = true;
      };


      /***
      * @ngdoc method
      * @name unselect
      * @methodOf BB.Models:TimeSlot
      * @description
      * Unselect if is selected
      *
      * @returns {boolean} If this is unselect
       */

      TimeSlot.prototype.unselect = function() {
        if (this.selected) {
          return delete this.selected;
        }
      };


      /***
      * @ngdoc method
      * @name disable
      * @methodOf BB.Models:TimeSlot
      * @description
      * Disable time slot by reason
      *
      * @returns {boolean} If this is a disabled
       */

      TimeSlot.prototype.disable = function(reason) {
        this.disabled = true;
        return this.disabled_reason = reason;
      };


      /***
      * @ngdoc method
      * @name enable
      * @methodOf BB.Models:TimeSlot
      * @description
      * Enable time slot
      *
      * @returns {boolean} If this is a enable
       */

      TimeSlot.prototype.enable = function() {
        if (this.disabled) {
          delete this.disabled;
        }
        if (this.disabled_reason) {
          return delete this.disabled_reason;
        }
      };


      /***
      * @ngdoc method
      * @name status
      * @methodOf BB.Models:TimeSlot
      * @description
      * Get status of the time slot
      *
      * @returns {object} The returned status
       */

      TimeSlot.prototype.status = function() {
        if (this.selected) {
          return "selected";
        }
        if (this.disabled) {
          return "disabled";
        }
        if (this.availability() > 0) {
          return "enabled";
        }
        return "disabled";
      };

      return TimeSlot;

    })(BaseModel);
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("AddressListService", function($q, $window, halClient, UriTemplate) {
    return {
      query: function(prms) {
        var deferred, href, uri;
        deferred = $q.defer();
        href = "/api/v1/company/{company_id}/addresses/{post_code}";
        uri = new UriTemplate(href).fillFromObject({
          company_id: prms.company.id,
          post_code: prms.post_code
        });
        halClient.$get(uri, {}).then(function(addressList) {
          return deferred.resolve(addressList);
        }, (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      getAddress: function(prms) {
        var deferred, href, uri;
        deferred = $q.defer();
        href = "/api/v1/company/{company_id}/addresses/address/{id}";
        uri = new UriTemplate(href).fillFromObject({
          company_id: prms.company.id,
          id: prms.id
        });
        halClient.$get(uri, {}).then(function(customerAddress) {
          return deferred.resolve(customerAddress);
        }, (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

}).call(this);


/***
* @ngdoc service
* @name BB.Services:Airbrake
*
* @description
* JavaScript notifier for capturing errors in web browsers and reporting them to Airbrake.
*
 */

(function() {
  angular.module('BB.Services').factory('$exceptionHandler', function($log, AirbrakeConfig) {
    var airbrake;
    airbrake = new airbrakeJs.Client({
      projectId: AirbrakeConfig.projectId,
      projectKey: AirbrakeConfig.projectKey
    });
    airbrake.addFilter(function(notice) {
      if (AirbrakeConfig.environment === 'development') {
        return;
      }
      notice.context.environment = 'production';
      return notice;
    });
    return function(exception, cause) {
      $log.error(exception);
      airbrake.notify({
        error: exception,
        params: {
          angular_cause: cause
        }
      });
    };
  });

}).call(this);


/***
* @ngdoc service
* @name BB.Services:Alert
*
* @description
* Representation of an Alert Object
*
* @property {array} alerts The array with all types of alerts
* @property {string} add Add alert message
 */

(function() {
  angular.module('BB.Services').factory('AlertService', function($rootScope, ErrorService, $timeout) {
    var alertService, titleLookup;
    $rootScope.alerts = [];

    /***
      * @ngdoc method
      * @name titleLookup
      * @methodOf BB.Services:Alert
      * @description
      * Title look up in according of type and title parameters
      *
      * @returns {boolean} The returned title
     */
    titleLookup = function(type, title) {
      if (title) {
        return title;
      }
      switch (type) {
        case "error":
        case "danger":
          title = "Error";
          break;
        default:
          title = null;
      }
      return title;
    };
    return alertService = {
      add: function(type, arg) {
        var alert, msg, persist, title;
        title = arg.title, msg = arg.msg, persist = arg.persist;
        if (persist == null) {
          persist = true;
        }
        $rootScope.alerts = [];
        alert = {
          type: type,
          title: titleLookup(type, title),
          msg: msg,
          close: function() {
            return alertService.closeAlert(this);
          }
        };
        $rootScope.alerts.push(alert);
        if (!persist) {
          $timeout(function() {
            return $rootScope.alerts.splice($rootScope.alerts.indexOf(alert), 1);
          }, 3000);
        }
        return $rootScope.$broadcast("alert:raised");
      },

      /***
      * @ngdoc method
      * @name closeAlert
      * @methodOf BB.Services:Alert
      * @description
      * Close alert
      *
      * @returns {boolean}  close alert
       */
      closeAlert: function(alert) {
        return this.closeAlertIdx($rootScope.alerts.indexOf(alert));
      },

      /***
      * @ngdoc method
      * @name closeAlertIdx
      * @methodOf BB.Services:Alert
      * @description
      * Close alert index
      *
      * @returns {boolean}  The returned close alert index
       */
      closeAlertIdx: function(index) {
        return $rootScope.alerts.splice(index, 1);
      },

      /***
      * @ngdoc method
      * @name clear
      * @methodOf BB.Services:Alert
      * @description
      * Clear alert message
      *
      * @returns {array} Newly clear array of the alert messages
       */
      clear: function() {
        return $rootScope.alerts = [];
      },

      /***
      * @ngdoc error
      * @name clear
      * @methodOf BB.Services:Alert
      * @description
      * Error alert
      *
      * @returns {array} The returned error alert
       */
      error: function(alert) {
        if (!alert) {
          return;
        }
        return this.add('error', {
          title: alert.title,
          msg: alert.msg,
          persist: alert.persist
        });
      },

      /***
      * @ngdoc error
      * @name danger
      * @methodOf BB.Services:Alert
      * @description
      * Danger alert
      *
      * @returns {array} The returned danger alert
       */
      danger: function(alert) {
        if (!alert) {
          return;
        }
        return this.add('danger', {
          title: alert.title,
          msg: alert.msg,
          persist: alert.persist
        });
      },

      /***
      * @ngdoc error
      * @name info
      * @methodOf BB.Services:Alert
      * @description
      * Info alert
      *
      * @returns {array} The returned info alert
       */
      info: function(alert) {
        if (!alert) {
          return;
        }
        return this.add('info', {
          title: alert.title,
          msg: alert.msg,
          persist: alert.persist
        });
      },

      /***
      * @ngdoc error
      * @name warning
      * @methodOf BB.Services:Alert
      * @description
      * Warning alert
      *
      * @returns {array} The returned warning alert
       */
      warning: function(alert) {
        if (!alert) {
          return;
        }
        return this.add('warning', {
          title: alert.title,
          msg: alert.msg,
          persist: alert.persist
        });
      },

      /***
      * @ngdoc error
      * @name success
      * @methodOf BB.Services:Alert
      * @description
      * Success alert
      *
      * @returns {array} The returned warning alert
       */
      success: function(alert) {
        if (!alert) {
          return;
        }
        return this.add('success', {
          title: alert.title,
          msg: alert.msg,
          persist: alert.persist
        });
      },

      /***
      * @ngdoc error
      * @name raise
      * @methodOf BB.Services:Alert
      * @description
      * Raise alert
      *
      * @returns {array} The returned raise alert
       */
      raise: function(key) {
        var alert;
        if (!key) {
          return;
        }
        alert = ErrorService.getAlert(key);
        if (alert) {
          return this.add(alert.type, {
            title: alert.title,
            msg: alert.msg,
            persist: alert.persist
          });
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("BasketService", function($q, $rootScope, BBModel, MutexService) {
    return {
      addItem: function(company, params) {
        var data, deferred, lnk;
        deferred = $q.defer();
        lnk = params.item.book_link;
        data = params.item.getPostData();
        if (!lnk) {
          deferred.reject("rel book not found for event");
        } else {
          MutexService.getLock().then(function(mutex) {
            return lnk.$post('book', params, data).then(function(basket) {
              var mbasket;
              MutexService.unlock(mutex);
              company.$flush('basket');
              mbasket = new BBModel.Basket(basket, params.bb);
              return basket.$get('items').then(function(items) {
                var i, item, j, len, promises;
                promises = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  item = new BBModel.BasketItem(i, params.bb);
                  mbasket.addItem(item);
                  promises = promises.concat(item.promises);
                }
                if (promises.length > 0) {
                  return $q.all(promises).then(function() {
                    return deferred.resolve(mbasket);
                  });
                } else {
                  return deferred.resolve(mbasket);
                }
              }, function(err) {
                return deferred.reject(err);
              });
            }, function(err) {
              MutexService.unlock(mutex);
              return deferred.reject(err);
            });
          });
        }
        return deferred.promise;
      },
      applyCoupon: function(company, params) {
        var deferred;
        deferred = $q.defer();
        MutexService.getLock().then(function(mutex) {
          return company.$post('coupon', {}, {
            coupon: params.coupon
          }).then(function(basket) {
            var mbasket;
            MutexService.unlock(mutex);
            company.$flush('basket');
            mbasket = new BBModel.Basket(basket, params.bb);
            return basket.$get('items').then(function(items) {
              var i, item, j, len, promises;
              promises = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                item = new BBModel.BasketItem(i, params.bb);
                mbasket.addItem(item);
                promises = promises.concat(item.promises);
              }
              if (promises.length > 0) {
                return $q.all(promises).then(function() {
                  return deferred.resolve(mbasket);
                });
              } else {
                return deferred.resolve(mbasket);
              }
            }, function(err) {
              return deferred.reject(err);
            });
          }, function(err) {
            MutexService.unlock(mutex);
            return deferred.reject(err);
          });
        });
        return deferred.promise;
      },
      updateBasket: function(company, params) {
        var data, deferred, item, j, len, lnk, ref, xdata;
        deferred = $q.defer();
        data = {
          entire_basket: true,
          items: []
        };
        ref = params.items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.book_link) {
            lnk = item.book_link;
          }
          xdata = item.getPostData();
          data.items.push(xdata);
        }
        if (!lnk) {
          deferred.reject("rel book not found for event");
          return deferred.promise;
        }
        MutexService.getLock().then(function(mutex) {
          return lnk.$post('book', params, data).then(function(basket) {
            var mbasket;
            MutexService.unlock(mutex);
            company.$flush('basket');
            mbasket = new BBModel.Basket(basket, params.bb);
            return basket.$get('items').then(function(items) {
              var i, k, len1, promises;
              promises = [];
              for (k = 0, len1 = items.length; k < len1; k++) {
                i = items[k];
                item = new BBModel.BasketItem(i, params.bb);
                mbasket.addItem(item);
                promises = promises.concat(item.promises);
              }
              if (promises.length > 0) {
                return $q.all(promises).then(function() {
                  $rootScope.$broadcast("basket:updated", mbasket);
                  return deferred.resolve(mbasket);
                });
              } else {
                $rootScope.$broadcast("basket:updated", mbasket);
                return deferred.resolve(mbasket);
              }
            }, function(err) {
              return deferred.reject(err);
            });
          }, function(err) {
            MutexService.unlock(mutex);
            return deferred.reject(err);
          });
        });
        return deferred.promise;
      },
      checkPrePaid: function(item, pre_paid_bookings) {
        var booking, j, len, valid_pre_paid;
        valid_pre_paid = null;
        for (j = 0, len = pre_paid_bookings.length; j < len; j++) {
          booking = pre_paid_bookings[j];
          if (booking.checkValidity(item)) {
            valid_pre_paid = booking;
            break;
          }
        }
        return valid_pre_paid;
      },
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('basket')) {
          deferred.reject("rel basket not found for company");
        } else {
          company.$get('basket').then(function(basket) {
            basket = new BBModel.Basket(basket, params.bb);
            if (basket.$has('items')) {
              basket.$get('items').then(function(items) {
                var item, j, len, results;
                results = [];
                for (j = 0, len = items.length; j < len; j++) {
                  item = items[j];
                  results.push(basket.addItem(new BBModel.BasketItem(item, params.bb)));
                }
                return results;
              });
            }
            return deferred.resolve(basket);
          }, function(err) {
            return deferred.reject(err);
          });
        }
        return deferred.promise;
      },
      deleteItem: function(item, company, params) {
        var deferred;
        if (!params) {
          params = {};
        }
        deferred = $q.defer();
        if (!item.$has('self')) {
          deferred.reject("rel self not found for item");
        } else {
          MutexService.getLock().then(function(mutex) {
            return item.$del('self', params).then(function(basket) {
              MutexService.unlock(mutex);
              company.$flush('basket');
              basket = new BBModel.Basket(basket, params.bb);
              if (basket.$has('items')) {
                basket.$get('items').then(function(items) {
                  var j, len, results;
                  results = [];
                  for (j = 0, len = items.length; j < len; j++) {
                    item = items[j];
                    results.push(basket.addItem(new BBModel.BasketItem(item, params.bb)));
                  }
                  return results;
                });
              }
              return deferred.resolve(basket);
            }, function(err) {
              return deferred.reject(err);
            });
          }, function(err) {
            MutexService.unlock(mutex);
            return deferred.reject(err);
          });
        }
        return deferred.promise;
      },
      checkout: function(company, basket, params) {
        var data, deferred;
        deferred = $q.defer();
        if (!basket.$has('checkout')) {
          deferred.reject("rel checkout not found for basket");
        } else {
          data = basket.getPostData();
          if (params.bb.qudini_booking_id) {
            data.qudini_booking_id = params.bb.qudini_booking_id;
          }
          if (params.bb.no_notifications) {
            data.no_notifications = params.bb.no_notifications;
          }
          data.affiliate_id = $rootScope.affiliate_id;
          basket.waiting_for_checkout = true;
          MutexService.getLock().then(function(mutex) {
            return basket.$post('checkout', params, data).then(function(total) {
              var tot;
              MutexService.unlock(mutex);
              $rootScope.$broadcast('updateBookings');
              tot = new BBModel.Purchase.Total(total);
              $rootScope.$broadcast('newCheckout', tot);
              basket.clear();
              basket.waiting_for_checkout = false;
              return deferred.resolve(tot);
            }, function(err) {
              basket.waiting_for_checkout = false;
              return deferred.reject(err);
            });
          }, function(err) {
            basket.waiting_for_checkout = false;
            MutexService.unlock(mutex);
            return deferred.reject(err);
          });
        }
        return deferred.promise;
      },
      empty: function(bb) {
        var deferred;
        deferred = $q.defer();
        MutexService.getLock().then(function(mutex) {
          return bb.company.$del('basket').then(function(basket) {
            MutexService.unlock(mutex);
            bb.company.$flush('basket');
            return deferred.resolve(new BBModel.Basket(basket, bb));
          }, function(err) {
            return deferred.reject(err);
          });
        }, function(err) {
          MutexService.unlock(mutex);
          return deferred.reject(err);
        });
        return deferred.promise;
      },
      memberCheckout: function(basket, params) {
        var data, deferred, item;
        deferred = $q.defer();
        if (!basket.$has('checkout')) {
          deferred.reject("rel checkout not found for basket");
        } else if ($rootScope.member === null) {
          deferred.reject("member not set");
        } else {
          basket._data.setOption('auth_token', $rootScope.member._data.getOption('auth_token'));
          data = {
            items: (function() {
              var j, len, ref, results;
              ref = basket.items;
              results = [];
              for (j = 0, len = ref.length; j < len; j++) {
                item = ref[j];
                results.push(item._data);
              }
              return results;
            })()
          };
          basket.$post('checkout', params, data).then(function(total) {
            if (total.$has('member')) {
              total.$get('member').then(function(member) {
                $rootScope.member.flushBookings();
                return $rootScope.member = new BBModel.Member.Member(member);
              });
            }
            return deferred.resolve(total);
          }, function(err) {
            return deferred.reject(err);
          });
        }
        return deferred.promise;
      },
      applyDeal: function(company, params) {
        var deferred;
        deferred = $q.defer();
        MutexService.getLock().then(function(mutex) {
          return params.bb.basket.$post('deal', {}, {
            deal_code: params.deal_code
          }).then(function(basket) {
            var mbasket;
            MutexService.unlock(mutex);
            company.$flush('basket');
            mbasket = new BBModel.Basket(basket, params.bb);
            return basket.$get('items').then(function(items) {
              var i, item, j, len, promises;
              promises = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                item = new BBModel.BasketItem(i, params.bb);
                mbasket.addItem(item);
                promises = promises.concat(item.promises);
              }
              if (promises.length > 0) {
                return $q.all(promises).then(function() {
                  return deferred.resolve(mbasket);
                });
              } else {
                return deferred.resolve(mbasket);
              }
            }, function(err) {
              return deferred.reject(err);
            });
          }, function(err) {
            MutexService.unlock(mutex);
            return deferred.reject(err);
          });
        });
        return deferred.promise;
      },
      removeDeal: function(company, params) {
        var deferred;
        if (!params) {
          params = {};
        }
        deferred = $q.defer();
        if (!params.bb.basket.$has('deal')) {
          return deferred.reject("No Remove Deal link found");
        } else {
          MutexService.getLock().then(function(mutex) {
            return params.bb.basket.$put('deal', {}, {
              deal_code_id: params.deal_code_id.toString()
            }).then(function(basket) {
              MutexService.unlock(mutex);
              company.$flush('basket');
              basket = new BBModel.Basket(basket, params.bb);
              if (basket.$has('items')) {
                return basket.$get('items').then(function(items) {
                  var item, j, len;
                  for (j = 0, len = items.length; j < len; j++) {
                    item = items[j];
                    basket.addItem(new BBModel.BasketItem(item, params.bb));
                  }
                  return deferred.resolve(basket);
                }, function(err) {
                  return deferred.reject(err);
                });
              }
            }, function(err) {
              MutexService.unlock(mutex);
              return deferred.reject(err);
            });
          });
          return deferred.promise;
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("BreadcrumbService", function() {
    var current_step;
    current_step = 1;
    return {
      setCurrentStep: function(step) {
        return current_step = step;
      },
      getCurrentStep: function() {
        return current_step;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("BulkPurchaseService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('bulk_purchases')) {
          deferred.reject("No bulk purchases found");
        } else {
          company.$get('bulk_purchases').then(function(resource) {
            return resource.$get('bulk_purchases').then(function(bulk_purchases) {
              var i;
              return deferred.resolve((function() {
                var j, len, results;
                results = [];
                for (j = 0, len = bulk_purchases.length; j < len; j++) {
                  i = bulk_purchases[j];
                  results.push(new BBModel.BulkPurchase(i));
                }
                return results;
              })());
            });
          }, (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("CategoryService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('categories')) {
          deferred.reject("No categories found");
        } else {
          company.$get('named_categories').then((function(_this) {
            return function(resource) {
              return resource.$get('categories').then(function(items) {
                var _i, cat, categories, i, j, len;
                categories = [];
                for (_i = j = 0, len = items.length; j < len; _i = ++j) {
                  i = items[_i];
                  cat = new BBModel.Category(i);
                  cat.order || (cat.order = _i);
                  categories.push(cat);
                }
                return deferred.resolve(categories);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ClientService", function($q, BBModel, MutexService) {
    return {
      create: function(company, client) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('client')) {
          deferred.reject("Cannot create new people for this company");
        } else {
          MutexService.getLock().then(function(mutex) {
            return company.$post('client', {}, client.getPostData()).then((function(_this) {
              return function(cl) {
                deferred.resolve(new BBModel.Client(cl));
                return MutexService.unlock(mutex);
              };
            })(this), (function(_this) {
              return function(err) {
                deferred.reject(err);
                return MutexService.unlock(mutex);
              };
            })(this));
          });
        }
        return deferred.promise;
      },
      update: function(company, client) {
        var deferred;
        deferred = $q.defer();
        MutexService.getLock().then(function(mutex) {
          return client.$put('self', {}, client.getPostData()).then((function(_this) {
            return function(cl) {
              deferred.resolve(new BBModel.Client(cl));
              return MutexService.unlock(mutex);
            };
          })(this), (function(_this) {
            return function(err) {
              deferred.reject(err);
              return MutexService.unlock(mutex);
            };
          })(this));
        });
        return deferred.promise;
      },
      create_or_update: function(company, client) {
        if (client.$has('self')) {
          return this.update(company, client);
        } else {
          return this.create(company, client);
        }
      },
      query_by_email: function(company, email) {
        var deferred;
        deferred = $q.defer();
        if ((company != null) && (email != null)) {
          company.$get("client_by_email", {
            email: email
          }).then((function(_this) {
            return function(client) {
              if (client != null) {
                return deferred.resolve(new BBModel.Client(client));
              } else {
                return deferred.resolve({});
              }
            };
          })(this), function(err) {
            return deferred.reject(err);
          });
        } else {
          deferred.reject("No company or email defined");
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ClientDetailsService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('client_details')) {
          deferred.reject("No client_details found");
        } else {
          company.$get('client_details').then((function(_this) {
            return function(details) {
              return deferred.resolve(new BBModel.ClientDetails(details));
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('ClinicService', function($q, BBModel, $window) {
    return {
      query: function(params) {
        var company, defer;
        company = params.company;
        defer = $q.defer();
        if (params.id) {
          company.$get('clinics', params).then(function(clinic) {
            clinic = new BBModel.Clinic(clinic);
            return defer.resolve(clinic);
          }, function(err) {
            return defer.reject(err);
          });
        } else {
          company.$get('clinics', params).then(function(collection) {
            return collection.$get('clinics').then(function(clinics) {
              var s;
              clinics = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = clinics.length; i < len; i++) {
                  s = clinics[i];
                  results.push(new BBModel.Clinic(s));
                }
                return results;
              })();
              return defer.resolve(clinics);
            }, function(err) {
              return defer.reject(err);
            });
          }, function(err) {
            return defer.reject(err);
          });
        }
        return defer.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("CompanyService", function($q, halClient, BBModel) {
    return {
      query: function(company_id, options) {
        var deferred, url;
        options['root'] || (options['root'] = "");
        url = options['root'] + "/api/v1/company/" + company_id;
        deferred = $q.defer();
        halClient.$get(url, options).then((function(_this) {
          return function(company) {
            return deferred.resolve(company);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      queryChildren: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('companies')) {
          deferred.reject("No child companies found");
        } else {
          company.$get('companies').then((function(_this) {
            return function(resource) {
              return resource.$get('companies').then(function(items) {
                var companies, i, j, len;
                companies = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  companies.push(new BBModel.Company(i));
                }
                return deferred.resolve(companies);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("CustomTextService", function($q, BBModel) {
    return {
      BookingText: function(company, basketItem) {
        var deferred;
        deferred = $q.defer();
        company.$get('booking_text').then((function(_this) {
          return function(emb) {
            return emb.$get('booking_text').then(function(details) {
              var detail, i, len, link, msgs, name, ref;
              msgs = [];
              for (i = 0, len = details.length; i < len; i++) {
                detail = details[i];
                if (detail.message_type === "Booking") {
                  ref = basketItem.parts_links;
                  for (name in ref) {
                    link = ref[name];
                    if (detail.$href('item') === link) {
                      if (msgs.indexOf(detail.message) === -1) {
                        msgs.push(detail.message);
                      }
                    }
                  }
                }
              }
              return deferred.resolve(msgs);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      confirmationText: function(company, total) {
        var deferred;
        deferred = $q.defer();
        company.$get('booking_text').then(function(emb) {
          return emb.$get('booking_text').then(function(details) {
            return total.getMessages(details, "Confirm").then(function(msgs) {
              return deferred.resolve(msgs);
            });
          });
        }, function(err) {
          return deferred.reject(err);
        });
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("DateTimeUlititiesService", function(AlertService) {
    return {
      convertTimeSlotToMoment: function(day, time_slot) {
        var datetime, hours, mins, val;
        if (!day && !time_slot) {
          return;
        }
        datetime = moment();
        val = parseInt(time_slot.time);
        hours = parseInt(val / 60);
        mins = val % 60;
        datetime.hour(hours);
        datetime.minutes(mins);
        datetime.seconds(0);
        datetime.date(day.date.date());
        datetime.month(day.date.month());
        datetime.year(day.date.year());
        return datetime;
      },
      convertMomentToTime: function(datetime) {
        return datetime.minutes() + datetime.hours() * 60;
      },
      checkRequestedTime: function(day, time_slots, current_item) {
        var found_time, i, len, slot;
        if ((current_item.requested_time || current_item.time) && current_item.requested_date && day.date.isSame(current_item.requested_date)) {
          found_time = false;
          for (i = 0, len = time_slots.length; i < len; i++) {
            slot = time_slots[i];
            if (slot.time === current_item.requested_time) {
              current_item.requestedTimeUnavailable();
              $scope.selectSlot(day, slot);
              found_time = true;
              $scope.days = [];
              return;
            }
            if (current_item.time && current_item.time.time === slot.time && slot.avail === 1) {
              if ($scope.selected_slot && $scope.selected_slot.time !== current_item.time.time) {
                $scope.selected_slot = current_item.time;
              }
              current_item.setTime(slot);
              found_time = true;
            }
          }
          if (!found_time) {
            return current_item.requestedTimeUnavailable();
          }
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("DayService", function($q, BBModel) {
    return {
      query: function(prms) {
        var deferred, extra;
        deferred = $q.defer();
        if (prms.cItem.days_link) {
          extra = {};
          extra.month = prms.month;
          extra.date = prms.date;
          extra.edate = prms.edate;
          if (prms.client) {
            extra.location = prms.client.addressCsvLine();
          }
          if (prms.cItem.person && !prms.cItem.anyPerson()) {
            extra.person_id = prms.cItem.person.id;
          }
          if (prms.cItem.resource && !prms.cItem.anyResource()) {
            extra.resource_id = prms.cItem.resource.id;
          }
          prms.cItem.days_link.$get('days', extra).then((function(_this) {
            return function(found) {
              var afound, days, i, j, len;
              afound = found.days;
              days = [];
              for (j = 0, len = afound.length; j < len; j++) {
                i = afound[j];
                if (i.type === prms.item) {
                  days.push(new BBModel.Day(i));
                }
              }
              return deferred.resolve(days);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        } else {
          deferred.reject("No Days Link found");
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("DealService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('deals')) {
          deferred.reject("No Deals found");
        } else {
          company.$get('deals').then((function(_this) {
            return function(resource) {
              return resource.$get('deals').then(function(deals) {
                var deal;
                deals = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = deals.length; i < len; i++) {
                    deal = deals[i];
                    results.push(new BBModel.Deal(deal));
                  }
                  return results;
                })();
                return deferred.resolve(deals);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB').config(function($logProvider, $injector) {
    return $logProvider.debugEnabled(true);
  });

  angular.module('BB.Services').factory("DebugUtilsService", function($rootScope, $location, $window, $log, BBModel, $bbug) {
    var logObjectKeys, showScopeChain;
    logObjectKeys = function(obj, showValue) {
      var key, value;
      for (key in obj) {
        value = obj[key];
        if (obj.hasOwnProperty(key) && !_.isFunction(value) && !(/^\$\$/.test(key))) {
          console.log(key);
          if (showValue) {
            console.log('\t', value, '\n');
          }
        }
      }
    };
    showScopeChain = function() {
      var $root, data, f;
      $root = $('[ng-app]');
      data = $root.data();
      if (data && data.$scope) {
        f = function(scope) {
          console.log(scope.$id);
          console.log(scope);
          if (scope.$$nextSibling) {
            return f(scope.$$nextSibling);
          } else {
            if (scope.$$childHead) {
              return f(scope.$$childHead);
            }
          }
        };
        f(data.$scope);
      }
    };
    (function() {
      if (($location.host() === 'localhost' || $location.host() === '127.0.0.1') && $location.port() === 3000) {
        return window.setTimeout(function() {
          var scope;
          scope = $rootScope;
          while (scope) {
            if (scope.controller === 'public.controllers.BBCtrl') {
              break;
            }
            scope = scope.$$childHead;
          }
          $bbug($window).on('dblclick', function(e) {
            var controller, controllerName, pscope;
            scope = angular.element(e.target).scope();
            controller = scope.hasOwnProperty('controller');
            pscope = scope;
            if (controller) {
              controllerName = scope.controller;
            }
            while (!controller) {
              pscope = pscope.$parent;
              controllerName = pscope.controller;
              controller = pscope.hasOwnProperty('controller');
            }
            $window.bbScope = scope;
            $log.log(e.target);
            $log.log($window.bbScope);
            return $log.log('Controller ->', controllerName);
          });
          $window.bbBBCtrlScopeKeyNames = function(prop) {
            return logObjectKeys(scope, prop);
          };
          $window.bbBBCtrlScope = function() {
            return scope;
          };
          $window.bbCurrentItem = function() {
            return scope.current_item;
          };
          return $window.bbShowScopeChain = showScopeChain;
        }, 10);
      }
    })();
    return {
      logObjectKeys: logObjectKeys
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('Dialog', function($modal, $log) {
    var controller;
    controller = function($scope, $modalInstance, model, title, success, fail, body) {
      $scope.body = body;
      $scope.ok = function() {
        return $modalInstance.close(model);
      };
      $scope.cancel = function() {
        event.preventDefault();
        event.stopPropagation();
        return $modalInstance.dismiss('cancel');
      };
      return $modalInstance.result.then(function() {
        if (success) {
          return success(model);
        }
      }, function() {
        if (fail) {
          return fail();
        }
      });
    };
    return {
      confirm: function(config) {
        var templateUrl;
        if (config.templateUrl) {
          templateUrl = config.templateUrl;
        }
        templateUrl || (templateUrl = 'dialog.html');
        return $modal.open({
          templateUrl: templateUrl,
          controller: controller,
          size: config.size || 'sm',
          resolve: {
            model: function() {
              return config.model;
            },
            title: function() {
              return config.title;
            },
            success: function() {
              return config.success;
            },
            fail: function() {
              return config.fail;
            },
            body: function() {
              return config.body;
            }
          }
        });
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('ErrorService', function(SettingsService) {
    var alerts;
    alerts = [
      {
        key: 'GENERIC',
        type: 'error',
        title: '',
        persist: true,
        msg: "Sorry, it appears that something went wrong. Please try again or call the business you're booking with if the problem persists."
      }, {
        key: 'LOCATION_NOT_FOUND',
        type: 'warning',
        title: '',
        persist: true,
        msg: "Sorry, we don't recognise that location"
      }, {
        key: 'MISSING_LOCATION',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Please enter your location'
      }, {
        key: 'MISSING_POSTCODE',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Please enter a postcode'
      }, {
        key: 'INVALID_POSTCODE',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Please enter a valid postcode'
      }, {
        key: 'ITEM_NO_LONGER_AVAILABLE',
        type: 'error',
        title: '',
        persist: true,
        msg: 'Sorry. The item you were trying to book is no longer available. Please try again.'
      }, {
        key: 'FORM_INVALID',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Please complete all required fields'
      }, {
        key: 'GEOLOCATION_ERROR',
        type: 'error',
        title: '',
        persist: true,
        msg: 'Sorry, we could not determine your location. Please try searching instead.'
      }, {
        key: 'EMPTY_BASKET_FOR_CHECKOUT',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'You need to add some items to the basket before you can checkout.'
      }, {
        key: 'MAXIMUM_TICKETS',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, the maximum number of tickets per person has been reached.'
      }, {
        key: 'GIFT_CERTIFICATE_REQUIRED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'A valid Gift Certificate is required to proceed with this booking'
      }, {
        key: 'TIME_SLOT_NOT_SELECTED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'You need to select a time slot'
      }, {
        key: 'APPT_AT_SAME_TIME',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Your appointment is already booked for this time'
      }, {
        key: 'REQ_TIME_NOT_AVAIL',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'The requested time slot is not available. Please choose a different time.'
      }, {
        key: 'TOPUP_SUCCESS',
        type: 'success',
        title: '',
        persist: true,
        msg: 'Your wallet has been topped up'
      }, {
        key: 'TOPUP_FAILED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, your topup failed. Please try again.'
      }, {
        key: 'UPDATE_SUCCESS',
        type: 'success',
        title: '',
        persist: true,
        msg: 'Updated'
      }, {
        key: 'UPDATE_FAILED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Update failed. Please try again'
      }, {
        key: 'ALREADY_REGISTERED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'You have already registered with this email address. Please login or reset your password.'
      }, {
        key: 'LOGIN_FAILED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, your email or password was not recognised. Please try again or reset your password.'
      }, {
        key: 'PASSWORD_INVALID',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, your chosen password is invalid'
      }, {
        key: 'PASSWORD_RESET_REQ_SUCCESS',
        type: 'success',
        title: '',
        persist: true,
        msg: 'We have sent you an email with instructions on how to reset your password.'
      }, {
        key: 'PASSWORD_RESET_REQ_FAILED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, we didn\'t find an account registered with that email.'
      }, {
        key: 'PASSWORD_RESET_SUCESS',
        type: 'success',
        title: '',
        persist: true,
        msg: 'Your password has been updated.'
      }, {
        key: 'PASSWORD_RESET_FAILED',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Sorry, we couldn\'t update your password. Please try again.'
      }, {
        key: 'PASSWORD_MISMATCH',
        type: 'warning',
        title: '',
        persist: true,
        msg: 'Your passwords don\'t match'
      }, {
        key: 'ATTENDEES_CHANGED',
        type: 'info',
        title: '',
        persist: true,
        msg: 'Your booking has been successfully updated'
      }, {
        key: 'PAYMENT_FAILED',
        type: 'danger',
        title: '',
        persist: true,
        msg: 'We were unable to take payment. Please contact your card issuer or try again using a different card'
      }, {
        key: 'ACCOUNT_DISABLED',
        type: 'warning',
        title: '',
        persist: true,
        msg: "Your account appears to be disabled. Please contact the business you're booking with if the problem persists."
      }, {
        key: 'FB_LOGIN_NOT_A_MEMBER',
        type: 'warning',
        title: '',
        persist: true,
        msg: "Sorry, we couldn't find a login linked with your Facebook account. You will need to sign up using Facebook first."
      }
    ];
    return {
      getError: function(key) {
        var error, translate;
        error = _.findWhere(alerts, {
          key: key
        });
        error.persist = true;
        translate = SettingsService.isInternationalizatonEnabled();
        if (error && translate) {
          return {
            msg: "ERROR." + key
          };
        } else if (error && !translate) {
          return error;
        } else if (translate) {
          return {
            msg: 'GENERIC'
          };
        } else {
          return alerts[0];
        }
      },
      getAlert: function(key) {
        var alert, translate;
        alert = _.findWhere(alerts, {
          key: key
        });
        translate = SettingsService.isInternationalizatonEnabled();
        if (alert && translate) {
          return {
            msg: "ALERT." + key
          };
        } else if (alert && !translate) {
          return alert;
        } else {
          return null;
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("EventService", function($q, BBModel) {
    return {
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('events')) {
          deferred.resolve([]);
        } else {
          if (params.item) {
            if (params.item.event_group) {
              params.event_group_id = params.item.event_group.id;
            }
            if (params.item.event_chain) {
              params.event_chain_id = params.item.event_chain.id;
            }
            if (params.item.resource) {
              params.resource_id = params.item.resource.id;
            }
            if (params.item.person) {
              params.person_id = params.item.person.id;
            }
          }
          company.$get('events', params).then((function(_this) {
            return function(resource) {
              return resource.$get('events', params).then(function(events) {
                var event;
                events = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = events.length; i < len; i++) {
                    event = events[i];
                    results.push(new BBModel.Event(event));
                  }
                  return results;
                })();
                return deferred.resolve(events);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      },
      summary: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('events')) {
          deferred.resolve([]);
        } else {
          if (params.item) {
            if (params.item.event_group) {
              params.event_group_id = params.item.event_group.id;
            }
            if (params.item.event_chain) {
              params.event_chain_id = params.item.event_chain.id;
            }
            if (params.item.resource) {
              params.resource_id = params.item.resource.id;
            }
            if (params.item.person) {
              params.person_id = params.item.person.id;
            }
          }
          params.summary = true;
          company.$get('events', params).then((function(_this) {
            return function(resource) {
              return deferred.resolve(resource.events);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      },
      queryEventCollection: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('events')) {
          deferred.resolve([]);
        } else {
          if (params.item) {
            if (params.item.event_group) {
              params.event_group_id = params.item.event_group.id;
            }
            if (params.item.event_chain) {
              params.event_chain_id = params.item.event_chain.id;
            }
            if (params.item.resource) {
              params.resource_id = params.item.resource.id;
            }
            if (params.item.person) {
              params.person_id = params.item.person.id;
            }
          }
          company.$get('events', params).then((function(_this) {
            return function(resource) {
              var collection;
              collection = new BBModel.BBCollection(resource);
              return deferred.resolve(collection);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("EventChainService", function($q, BBModel) {
    return {
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('event_chains')) {
          deferred.reject("company does not have event_chains");
        } else {
          company.$get('event_chains', params).then((function(_this) {
            return function(resource) {
              return resource.$get('event_chains', params).then(function(event_chains) {
                var event_chain;
                event_chains = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = event_chains.length; i < len; i++) {
                    event_chain = event_chains[i];
                    results.push(new BBModel.EventChain(event_chain));
                  }
                  return results;
                })();
                return deferred.resolve(event_chains);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      },
      queryEventChainCollection: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('event_chains')) {
          deferred.resolve([]);
        } else {
          company.$get('event_chains', params).then((function(_this) {
            return function(resource) {
              var collection;
              collection = new BBModel.BBCollection(resource);
              return deferred.resolve(collection);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("EventGroupService", function($q, BBModel) {
    return {
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('event_groups')) {
          deferred.reject("company does not have event_groups");
        } else {
          company.$get('event_groups', params).then((function(_this) {
            return function(resource) {
              return resource.$get('event_groups', params).then(function(event_groups) {
                var event_group;
                event_groups = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = event_groups.length; i < len; i++) {
                    event_group = event_groups[i];
                    results.push(new BBModel.EventGroup(event_group));
                  }
                  return results;
                })();
                return deferred.resolve(event_groups);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("EventSequenceService", function($q, BBModel) {
    return {
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('event_sequences')) {
          deferred.reject("company does not have event_sequences");
        } else {
          company.$get('event_sequences', params).then((function(_this) {
            return function(resource) {
              return resource.$get('event_sequences', params).then(function(event_sequences) {
                var event_sequence;
                event_sequences = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = event_sequences.length; i < len; i++) {
                    event_sequence = event_sequences[i];
                    results.push(new BBModel.EventSequence(event_sequence));
                  }
                  return results;
                })();
                return deferred.resolve(event_sequences);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('PathSvc', function($sce, AppConfig) {
    return {
      directivePartial: function(fileName) {
        var partial_url;
        if (AppConfig.partial_url) {
          partial_url = AppConfig.partial_url;
          return $sce.trustAsResourceUrl(partial_url + "/" + fileName + ".html");
        } else {
          return $sce.trustAsResourceUrl(fileName + ".html");
        }
      }
    };
  });

}).call(this);

(function() {
  "use strict";
  angular.module('BB.Services').factory('FormDataStoreService', function($rootScope, $window, $log, $parse) {
    var checkForListeners, checkRegisteredWidgets, clear, dataStore, div, getParentScope, init, log, register, registeredWidgetArr, removeWidget, resetValuesOnScope, setIfUndefined, setListeners, setValuesOnScope, showInfo, storeFormData, toId;
    registeredWidgetArr = [];
    dataStore = {};
    toId = 0;
    div = '___';
    log = function() {};
    showInfo = function() {
      return log(dataStore);
    };
    setIfUndefined = function(keyName, val) {
      var getter, scope;
      scope = this;
      getter = $parse(keyName);
      if (typeof getter(scope) === 'undefined') {
        return getter.assign(scope, val);
      }
    };
    resetValuesOnScope = function(scope, props) {
      var i, len, prop, setter;
      for (i = 0, len = props.length; i < len; i++) {
        prop = props[i];
        prop = $parse(prop);
        setter = prop.assign;
        setter(scope, null);
      }
    };
    clear = function(scope, keepScopeValues) {
      var data, key, widgetId;
      if (!scope) {
        throw new Error('Missing scope object. Cannot clear form data without scope');
      }
      if (_.isString(scope)) {
        data = dataStore[scope];
        if (!keepScopeValues) {
          resetValuesOnScope(data[0], data[1]);
        }
        delete dataStore[scope];
        return;
      }
      scope = getParentScope(scope);
      if (scope && scope.bb) {
        widgetId = scope.bb.uid;
        removeWidget(scope);
        for (key in dataStore) {
          data = dataStore[key];
          if (key.indexOf(widgetId) !== -1) {
            if (data[3]) {
              _.each(data[3], function(func) {
                if (_.isFunction(func)) {
                  return func();
                }
              });
            }
            if (!keepScopeValues) {
              resetValuesOnScope(data[0], data[1]);
            }
            delete dataStore[key];
          }
        }
      }
    };
    storeFormData = function() {
      var i, key, len, ndata, prop, props, scope, step, val;
      log('formDataStore ->', dataStore);
      for (key in dataStore) {
        step = dataStore[key];
        log('\t', key);
        scope = step[0];
        props = step[1];
        ndata = step[2];
        if (!ndata) {
          ndata = step[2] = {};
        }
        for (i = 0, len = props.length; i < len; i++) {
          prop = props[i];
          val = ndata[prop];
          if (val === 'data:destroyed') {
            ndata[prop] = null;
          } else {
            val = angular.copy(scope.$eval(prop));
            ndata[prop] = val;
          }
          log('\t\t', prop, val);
        }
        log('\n');
      }
    };
    setValuesOnScope = function(currentPage, scope) {
      var cpage, storedValues;
      cpage = dataStore[currentPage];
      storedValues = cpage[2];
      log('Decorating scope ->', currentPage, storedValues);
      if (_.isObject(storedValues)) {
        _.each(_.keys(storedValues), function(keyName) {
          var getter;
          if (typeof storedValues[keyName] !== 'undefined' && storedValues[keyName] !== 'data:destroyed') {
            getter = $parse(keyName);
            return getter.assign(scope, storedValues[keyName]);
          }
        });
      }
      cpage[0] = scope;
      log(scope);
      log('\n');
    };
    getParentScope = function(scope) {
      while (scope) {
        if (scope.hasOwnProperty('cid') && scope.cid === 'BBCtrl') {
          return scope;
        }
        scope = scope.$parent;
      }
    };
    checkRegisteredWidgets = function(scope) {
      var i, isRegistered, len, rscope;
      isRegistered = false;
      scope = getParentScope(scope);
      for (i = 0, len = registeredWidgetArr.length; i < len; i++) {
        rscope = registeredWidgetArr[i];
        if (rscope === scope) {
          isRegistered = true;
        }
      }
      return isRegistered;
    };
    checkForListeners = function(propsArr) {
      var watchArr;
      watchArr = [];
      _.each(propsArr, function(propName, index) {
        var split;
        split = propName.split('->');
        if (split.length === 2) {
          watchArr.push(split);
          return propsArr[index] = split[0];
        }
      });
      return watchArr;
    };
    setListeners = function(scope, listenerArr, currentPage) {
      var cpage, listenersArr;
      if (listenerArr.length) {
        cpage = dataStore[currentPage];
        listenersArr = cpage[3] || [];
        _.each(listenerArr, function(item, index) {
          var func;
          func = $rootScope.$on(item[1], function() {
            var e, error;
            try {
              return cpage[2][item[0]] = 'data:destroyed';
            } catch (error) {
              e = error;
              return log(e);
            }
          });
          return listenersArr.push(func);
        });
        return cpage[3] = listenersArr;
      }
    };
    init = function(uid, scope, propsArr) {
      var currentPage, watchArr;
      if (checkRegisteredWidgets(scope)) {
        currentPage = scope.bb.uid + div + scope.bb.current_page + div + uid;
        currentPage = currentPage.toLowerCase();
        watchArr = checkForListeners(propsArr);
        scope.clearStoredData = (function(currentPage) {
          return function() {
            clear(currentPage);
          };
        })(currentPage);
        if (!currentPage) {
          throw new Error("Missing current step");
        }
        if (dataStore[currentPage]) {
          setValuesOnScope(currentPage, scope);
          return;
        }
        log('Controller registered ->', currentPage, scope, '\n\n');
        dataStore[currentPage] = [scope, propsArr];
        setListeners(scope, watchArr, currentPage);
      }
    };
    removeWidget = function(scope) {
      registeredWidgetArr = _.without(registeredWidgetArr, scope);
    };
    register = function(scope) {
      var registered;
      registered = false;
      if (scope && scope.$$childHead) {
        scope = scope.$$childHead;
      }
      while (!_.has(scope, 'cid')) {
        scope = scope.$parent;
      }
      if (!scope) {
        return;
      }
      if (scope.cid !== 'BBCtrl') {
        throw new Error("This directive can only be used with the BBCtrl");
      }
      _.each(registeredWidgetArr, function(stored) {
        if (scope === stored) {
          return registered = true;
        }
      });
      if (!registered) {
        log('Scope registered ->', scope);
        scope.$on('destroy', removeWidget);
        return registeredWidgetArr.push(scope);
      }
    };
    $rootScope.$watch(function() {
      $window.clearTimeout(toId);
      toId = setTimeout(storeFormData, 300);
    });
    $rootScope.$on('save:formData', storeFormData);
    $rootScope.$on('clear:formData', clear);
    return {
      init: init,
      destroy: function(scope) {
        return clear(scope, true);
      },
      showInfo: showInfo,
      register: register,
      setIfUndefined: setIfUndefined
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('GeolocationService', function($q) {
    return {
      haversine: function(position1, position2) {
        var R, a, c, chLat, chLon, d, dLat, dLon, distance, distances, lat1, lat2, lon1, lon2, pi, rLat1, rLat2;
        pi = Math.PI;
        R = 6371;
        distances = [];
        lat1 = position1.lat;
        lon1 = position1.long;
        lat2 = position2.lat;
        lon2 = position2.long;
        chLat = lat2 - lat1;
        chLon = lon2 - lon1;
        dLat = chLat * (pi / 180);
        dLon = chLon * (pi / 180);
        rLat1 = lat1 * (pi / 180);
        rLat2 = lat2 * (pi / 180);
        a = Math.sin(dLat / 2) * Math.sin(dLat / 2) + Math.sin(dLon / 2) * Math.sin(dLon / 2) * Math.cos(rLat1) * Math.cos(rLat2);
        c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
        d = R * c;
        d = d * 0.621371192;
        distance = Math.round(d);
        return distance;
      },
      geocode: function(address, prms) {
        var deferred, ne, request, sw;
        if (prms == null) {
          prms = {};
        }
        deferred = $q.defer();
        request = {
          address: address
        };
        if (prms.region) {
          request.region = prms.region;
        }
        if (prms.componentRestrictions) {
          request.componentRestrictions = prms.componentRestrictions;
        }
        if (prms.bounds) {
          sw = new google.maps.LatLng(prms.bounds.sw.x, prms.bounds.sw.y);
          ne = new google.maps.LatLng(prms.bounds.ne.x, prms.bounds.ne.y);
          request.bounds = new google.maps.LatLngBounds(sw, ne);
        }
        new google.maps.Geocoder().geocode(request, function(results, status) {
          if (results && status === 'OK') {
            return deferred.resolve({
              results: results,
              status: status
            });
          } else {
            return deferred.reject(status);
          }
        });
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ItemService", function($q, BBModel) {
    return {
      query: function(prms) {
        var deferred;
        deferred = $q.defer();
        if (prms.cItem.service && prms.item !== 'service') {
          if (!prms.cItem.service.$has('items')) {
            prms.cItem.service.$get('item').then((function(_this) {
              return function(base_item) {
                return _this.build_items(base_item.$get('items'), prms, deferred);
              };
            })(this));
          } else {
            this.build_items(prms.cItem.service.$get('items'), prms, deferred);
          }
        } else if (prms.cItem.resource && !prms.cItem.anyResource() && prms.item !== 'resource') {
          if (!prms.cItem.resource.$has('items')) {
            prms.cItem.resource.$get('item').then((function(_this) {
              return function(base_item) {
                return _this.build_items(base_item.$get('items'), prms, deferred);
              };
            })(this));
          } else {
            this.build_items(prms.cItem.resource.$get('items'), prms, deferred);
          }
        } else if (prms.cItem.person && !prms.cItem.anyPerson() && prms.item !== 'person') {
          if (!prms.cItem.person.$has('items')) {
            prms.cItem.person.$get('item').then((function(_this) {
              return function(base_item) {
                return _this.build_items(base_item.$get('items'), prms, deferred);
              };
            })(this));
          } else {
            this.build_items(prms.cItem.person.$get('items'), prms, deferred);
          }
        } else {
          deferred.reject("No service link found");
        }
        return deferred.promise;
      },
      build_items: function(base_items, prms, deferred) {
        var wait_items;
        wait_items = [base_items];
        if (prms.wait) {
          wait_items.push(prms.wait);
        }
        return $q.all(wait_items).then((function(_this) {
          return function(resources) {
            var resource;
            resource = resources[0];
            return resource.$get('items').then(function(found) {
              var i, len, m, matching, v, wlist;
              matching = [];
              wlist = [];
              for (i = 0, len = found.length; i < len; i++) {
                v = found[i];
                if (v.type === prms.item) {
                  matching.push(new BBModel.BookableItem(v));
                }
              }
              return $q.all((function() {
                var j, len1, results;
                results = [];
                for (j = 0, len1 = matching.length; j < len1; j++) {
                  m = matching[j];
                  results.push(m.ready.promise);
                }
                return results;
              })()).then(function() {
                return deferred.resolve(matching);
              });
            });
          };
        })(this));
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ItemDetailsService", function($q, BBModel) {
    return {
      query: function(prms) {
        var deferred;
        deferred = $q.defer();
        if (prms.cItem.service) {
          if (!prms.cItem.service.$has('questions')) {
            deferred.resolve(new BBModel.ItemDetails());
          } else {
            prms.cItem.service.$get('questions').then((function(_this) {
              return function(details) {
                return deferred.resolve(new BBModel.ItemDetails(details));
              };
            })(this), (function(_this) {
              return function(err) {
                return deferred.reject(err);
              };
            })(this));
          }
        } else if (prms.cItem.event_chain) {
          if (!prms.cItem.event_chain.$has('questions')) {
            deferred.resolve(new BBModel.ItemDetails());
          } else {
            prms.cItem.event_chain.$get('questions').then((function(_this) {
              return function(details) {
                return deferred.resolve(new BBModel.ItemDetails(details));
              };
            })(this), (function(_this) {
              return function(err) {
                return deferred.reject(err);
              };
            })(this));
          }
        } else if (prms.cItem.deal) {
          if (!prms.cItem.deal.$has('questions')) {
            deferred.resolve(new BBModel.ItemDetails());
          } else {
            prms.cItem.deal.$get('questions').then((function(_this) {
              return function(details) {
                return deferred.resolve(new BBModel.ItemDetails(details));
              };
            })(this), (function(_this) {
              return function(err) {
                return deferred.reject(err);
              };
            })(this));
          }
        } else {
          deferred.resolve();
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('LoadingService', function($q, $window, $log, $rootScope, AlertService) {
    return {
      $loader: function(scope) {
        var item, lservice;
        lservice = this;
        item = {
          scope: scope,
          setLoaded: function() {
            return lservice.setLoaded(scope);
          },
          setLoadedAndShowError: function(err, error_string) {
            return lservice.setLoadedAndShowError(scope, err, error_string);
          },
          notLoaded: function() {
            lservice.notLoaded(scope);
            return this;
          }
        };
        return item;
      },
      setLoaded: function(cscope) {
        var loadingFinished;
        cscope.$emit('hide:loader', cscope);
        cscope.isLoaded = true;
        loadingFinished = true;
        while (cscope) {
          if (cscope.hasOwnProperty('scopeLoaded')) {
            if (this.areScopesLoaded(cscope)) {
              cscope.scopeLoaded = true;
            } else {
              loadingFinished = false;
            }
          }
          cscope = cscope.$parent;
        }
        if (loadingFinished) {
          $rootScope.$broadcast('loading:finished');
        }
      },
      setLoadedAndShowError: function(scope, err, error_string) {
        $log.warn(err, error_string);
        scope.setLoaded(scope);
        if (err && err.status === 409) {
          return AlertService.danger(ErrorService.getError('ITEM_NO_LONGER_AVAILABLE'));
        } else if (err.data && err.data.error === "Number of Bookings exceeds the maximum") {
          return AlertService.danger(ErrorService.getError('MAXIMUM_TICKETS'));
        } else {
          return AlertService.danger(ErrorService.getError('GENERIC'));
        }
      },
      areScopesLoaded: function(cscope) {
        var child;
        if (cscope.hasOwnProperty('isLoaded') && !cscope.isLoaded) {
          return false;
        } else {
          child = cscope.$$childHead;
          while (child) {
            if (!this.areScopesLoaded(child)) {
              return false;
            }
            child = child.$$nextSibling;
          }
          return true;
        }
      },
      notLoaded: function(cscope) {
        cscope.$emit('show:loader', cscope);
        cscope.isLoaded = false;
        while (cscope) {
          if (cscope.hasOwnProperty('scopeLoaded')) {
            cscope.scopeLoaded = false;
          }
          cscope = cscope.$parent;
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('LocaleService', function($window) {
    var locale;
    locale = $window.getURIparam('locale');
    if (locale) {
      return locale;
    } else if ($window.navigator.language) {
      return $window.navigator.language;
    } else {
      return "en";
    }
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("LoginService", function($q, halClient, $rootScope, BBModel, $sessionStorage, $localStorage) {
    return {
      companyLogin: function(company, params, form) {
        var deferred;
        deferred = $q.defer();
        company.$post('login', params, form).then((function(_this) {
          return function(login) {
            return login.$get('member').then(function(member) {
              _this.setLogin(member);
              return deferred.resolve(member);
            }, function(err) {
              return deferred.reject(err);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      login: function(form, options) {
        var deferred, url;
        deferred = $q.defer();
        options['root'] || (options['root'] = "");
        url = options['root'] + "/api/v1/login";
        halClient.$post(url, options, form).then((function(_this) {
          return function(login) {
            var params;
            params = {
              auth_token: login.auth_token
            };
            return login.$get('member').then(function(member) {
              _this.setLogin(member);
              return deferred.resolve(member);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      FBLogin: function(company, prms) {
        var deferred;
        deferred = $q.defer();
        company.$post('facebook_login', {}, prms).then((function(_this) {
          return function(login) {
            return login.$get('member').then(function(member) {
              member = new BBModel.Member.Member(member);
              $sessionStorage.setItem("fb_user", true);
              _this.setLogin(member);
              return deferred.resolve(member);
            }, function(err) {
              return deferred.reject(err);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      companyQuery: (function(_this) {
        return function(id) {
          var comp_promise;
          if (id) {
            comp_promise = halClient.$get(location.protocol + '//' + location.host + '/api/v1/company/' + id);
            return comp_promise.then(function(company) {
              return company = new BBModel.Company(company);
            });
          }
        };
      })(this),
      memberQuery: (function(_this) {
        return function(params) {
          var member_promise;
          if (params.member_id && params.company_id) {
            member_promise = halClient.$get(location.protocol + '//' + location.host + ("/api/v1/" + params.company_id + "/") + "members/" + params.member_id);
            return member_promise.then(function(member) {
              return member = new BBModel.Member.Member(member);
            });
          }
        };
      })(this),
      ssoLogin: function(options, data) {
        var deferred, url;
        deferred = $q.defer();
        options['root'] || (options['root'] = "");
        url = options['root'] + "/api/v1/login/sso/" + options['company_id'];
        halClient.$post(url, {}, data).then((function(_this) {
          return function(login) {
            var params;
            params = {
              auth_token: login.auth_token
            };
            return login.$get('member').then(function(member) {
              member = new BBModel.Member.Member(member);
              _this.setLogin(member);
              return deferred.resolve(member);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      isLoggedIn: function() {
        this.checkLogin();
        return $rootScope.member && (!$rootScope.user || $rootScope.user === void 0);
      },
      setLogin: function(member, persist) {
        var auth_token;
        auth_token = member.getOption('auth_token');
        member = new BBModel.Member.Member(member);
        $sessionStorage.setItem("login", member.$toStore());
        $sessionStorage.setItem("auth_token", auth_token);
        $rootScope.member = member;
        if (persist) {
          $localStorage.setItem("auth_token", auth_token);
        }
        return member;
      },
      member: function() {
        this.checkLogin();
        return $rootScope.member;
      },
      checkLogin: function() {
        var member;
        if ($rootScope.member) {
          return true;
        }
        member = $sessionStorage.getItem("login");
        if (member) {
          member = halClient.createResource(member);
          $rootScope.member = new BBModel.Member.Member(member);
          return true;
        } else {
          return false;
        }
      },
      logout: function(options) {
        var deferred, url;
        $rootScope.member = null;
        deferred = $q.defer();
        options || (options = {});
        options['root'] || (options['root'] = "");
        url = options['root'] + "/api/v1/logout";
        $sessionStorage.clear();
        $localStorage.clear();
        halClient.$del(url, options, {}).then((function(_this) {
          return function(logout) {
            $sessionStorage.clear();
            $localStorage.clear();
            return deferred.resolve(true);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      FBLogout: function(options) {
        $sessionStorage.removeItem("fb_user");
        return this.logout(options);
      },
      sendPasswordReset: function(company, params) {
        var deferred;
        deferred = $q.defer();
        company.$post('email_password_reset', {}, params).then((function(_this) {
          return function() {
            return deferred.resolve(true);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      updatePassword: function(member, params) {
        var deferred;
        params.auth_token = member.getOption('auth_token');
        if (member && params['new_password'] && params['confirm_new_password']) {
          deferred = $q.defer();
          member.$post('update_password', {}, params).then((function(_this) {
            return function(login) {
              return login.$get('member').then(function(member) {
                _this.setLogin(member, params.persist_login);
                return deferred.resolve(member);
              }, function(err) {
                return deferred.reject(err);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
          return deferred.promise;
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("MembershipLevelsService", function($q, BBModel) {
    return {
      getMembershipLevels: function(company) {
        var deferred;
        deferred = $q.defer();
        company.$get("member_levels").then(function(resource) {
          return resource.$get('membership_levels').then((function(_this) {
            return function(membership_levels) {
              var level, levels;
              levels = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = membership_levels.length; i < len; i++) {
                  level = membership_levels[i];
                  results.push(new BBModel.MembershipLevel(level));
                }
                return results;
              })();
              return deferred.resolve(levels);
            };
          })(this));
        }, (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('ModalForm', function($modal, $log, Dialog) {
    var editForm, newForm;
    newForm = function($scope, $modalInstance, company, title, new_rel, post_rel, success, fail) {
      $scope.loading = true;
      $scope.title = title;
      $scope.company = company;
      if ($scope.company.$has(new_rel)) {
        $scope.company.$get(new_rel).then(function(schema) {
          $scope.form = _.reject(schema.form, function(x) {
            return x.type === 'submit';
          });
          $scope.schema = schema.schema;
          $scope.form_model = {};
          return $scope.loading = false;
        });
      } else {
        $log.warn("company does not have '" + new_rel + "' rel");
      }
      $scope.submit = function(form) {
        $scope.$broadcast('schemaFormValidate');
        $scope.loading = true;
        return $scope.company.$post(post_rel, {}, $scope.form_model).then(function(model) {
          $scope.loading = false;
          $modalInstance.close(model);
          if (success) {
            return success(model);
          }
        }, function(err) {
          $scope.loading = false;
          $modalInstance.close(err);
          $log.error('Failed to create');
          if (fail) {
            return fail(err);
          }
        });
      };
      return $scope.cancel = function(event) {
        event.preventDefault();
        event.stopPropagation();
        return $modalInstance.dismiss('cancel');
      };
    };
    editForm = function($scope, $modalInstance, model, title, success, fail) {
      $scope.loading = true;
      $scope.title = title;
      $scope.model = model;
      if ($scope.model.$has('edit')) {
        $scope.model.$get('edit').then(function(schema) {
          $scope.form = _.reject(schema.form, function(x) {
            return x.type === 'submit';
          });
          $scope.schema = schema.schema;
          $scope.form_model = $scope.model;
          return $scope.loading = false;
        });
      } else {
        $log.warn("model does not have 'edit' rel");
      }
      $scope.submit = function(form) {
        $scope.$broadcast('schemaFormValidate');
        $scope.loading = true;
        if ($scope.model.$update) {
          return $scope.model.$update($scope.form_model).then(function() {
            $scope.loading = false;
            $modalInstance.close($scope.model);
            if (success) {
              return success($scope.model);
            }
          }, function(err) {
            $scope.loading = false;
            $modalInstance.close(err);
            $log.error('Failed to create');
            if (fail) {
              return fail();
            }
          });
        } else {
          return $scope.model.$put('self', {}, $scope.form_model).then(function(model) {
            $scope.loading = false;
            $modalInstance.close(model);
            if (success) {
              return success(model);
            }
          }, function(err) {
            $scope.loading = false;
            $modalInstance.close(err);
            $log.error('Failed to create');
            if (fail) {
              return fail();
            }
          });
        }
      };
      $scope.cancel = function(event) {
        event.preventDefault();
        event.stopPropagation();
        return $modalInstance.dismiss('cancel');
      };
      return $scope.cancelBooking = function(event) {
        event.preventDefault();
        event.stopPropagation();
        $modalInstance.close();
        return Dialog.confirm({
          model: model,
          body: "Are you sure you want to cancel this booking?",
          success: function(model) {
            return model.$del('self').then(function(response) {
              if (success) {
                return success(response);
              }
            });
          }
        });
      };
    };
    return {
      "new": function(config) {
        var templateUrl;
        if (config.templateUrl) {
          templateUrl = config.templateUrl;
        }
        templateUrl || (templateUrl = 'modal_form.html');
        return $modal.open({
          templateUrl: templateUrl,
          controller: newForm,
          size: config.size,
          resolve: {
            company: function() {
              return config.company;
            },
            title: function() {
              return config.title;
            },
            new_rel: function() {
              return config.new_rel;
            },
            post_rel: function() {
              return config.post_rel;
            },
            success: function() {
              return config.success;
            },
            fail: function() {
              return config.fail;
            }
          }
        });
      },
      edit: function(config) {
        var templateUrl;
        if (config.templateUrl) {
          templateUrl = config.templateUrl;
        }
        templateUrl || (templateUrl = 'modal_form.html');
        return $modal.open({
          templateUrl: templateUrl,
          controller: editForm,
          size: config.size,
          resolve: {
            model: function() {
              return config.model;
            },
            title: function() {
              return config.title;
            },
            success: function() {
              return config.success;
            },
            fail: function() {
              return config.fail;
            }
          }
        });
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("MutexService", function($q, $window, $rootScope) {
    return {
      getLock: function(prms) {
        var iprom, mprom;
        mprom = $q.defer();
        iprom = $q.defer();
        mprom.promise.then(function() {
          var next_mux;
          $rootScope.mutexes.shift();
          if ($rootScope.mutexes.length > 0) {
            next_mux = $rootScope.mutexes[0];
            return next_mux.iprom.resolve(next_mux.mprom);
          }
        });
        if (!$rootScope.mutexes || $rootScope.mutexes.length === 0) {
          $rootScope.mutexes = [
            {
              mprom: mprom,
              iprom: iprom
            }
          ];
          iprom.resolve(mprom);
          return iprom.promise;
        } else {
          $rootScope.mutexes.push({
            mprom: mprom,
            iprom: iprom
          });
          return iprom.promise;
        }
      },
      unlock: function(mutex) {
        return mutex.resolve();
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("PackageItemService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('packages')) {
          deferred.reject("No packages found");
        } else {
          company.$get('packages').then(function(resource) {
            return resource.$get('packages').then(function(package_items) {
              var i;
              return deferred.resolve((function() {
                var j, len, results;
                results = [];
                for (j = 0, len = package_items.length; j < len; j++) {
                  i = package_items[j];
                  results.push(new BBModel.PackageItem(i));
                }
                return results;
              })());
            });
          }, function(err) {
            return deferred.reject(err);
          });
        }
        return deferred.promise;
      },
      getPackageServices: function(package_item) {
        var deferred;
        deferred = $q.defer();
        if (!package_item.$has('services')) {
          deferred.reject("No services found");
        } else {
          package_item.$get('services').then(function(services) {
            var s;
            return deferred.resolve((function() {
              var j, len, results;
              results = [];
              for (j = 0, len = services.length; j < len; j++) {
                s = services[j];
                results.push(new BBModel.Service(s));
              }
              return results;
            })());
          }, (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("PaginationService", function() {
    return {
      initialise: function(options) {
        var paginator;
        if (!options) {
          return;
        }
        paginator = {
          current_page: 1,
          page_size: options.page_size,
          num_pages: null,
          max_size: options.max_size,
          num_items: null
        };
        return paginator;
      },
      update: function(paginator, length) {
        var end, start, total;
        if (!paginator || !length) {
          return;
        }
        paginator.num_items = length;
        start = ((paginator.page_size - 1) * paginator.current_page) - ((paginator.page_size - 1) - paginator.current_page);
        end = paginator.current_page * paginator.page_size;
        total = end < paginator.page_size ? end : length;
        end = end > total ? total : end;
        total = total >= 100 ? "100+" : total;
        return paginator.summary = start + " - " + end + " of " + total;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("PersonService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('people')) {
          deferred.reject("No people found");
        } else {
          company.$get('people').then((function(_this) {
            return function(resource) {
              return resource.$get('people').then(function(items) {
                var i, j, len, people;
                people = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  people.push(new BBModel.Person(i));
                }
                return deferred.resolve(people);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ProductService", function($q, $window, halClient, UriTemplate, BBModel, $log, $rootScope) {
    return {
      getProduct: function(prms) {
        var deferred, href, uri;
        deferred = $q.defer();
        if (prms.id) {
          href = $rootScope.bb.api_url + "/api/v1/{company_id}/products/{id}";
          uri = new UriTemplate(href).fillFromObject({
            company_id: prms.company_id,
            id: prms.product_id
          });
        } else if (prms.sku) {
          href = $rootScope.bb.api_url + "/api/v1/{company_id}/products/find_by_sku/{sku}";
          uri = new UriTemplate(href).fillFromObject({
            company_id: prms.company_id,
            sku: prms.sku
          });
        } else {
          $log.warn("id or sku is required");
          deferred.reject();
        }
        halClient.$get(uri, {}).then(function(product) {
          return deferred.resolve(new BBModel.Product(product));
        }, (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('products')) {
          deferred.reject("No products found");
        } else {
          company.$get('products').then((function(_this) {
            return function(resource) {
              return resource.$get('products').then(function(items) {
                var i, j, len, resources;
                resources = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  resources.push(new BBModel.Product(i));
                }
                return deferred.resolve(resources);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("PurchaseTotalService", function($q, BBModel) {
    return {
      query: function(prms) {
        var deferred;
        deferred = $q.defer();
        if (!prms.company.$has('total')) {
          deferred.reject("No Total link found");
        } else {
          prms.company.$get('total', {
            total_id: prms.total_id
          }).then((function(_this) {
            return function(total) {
              return deferred.resolve(new BBModel.PurchaseTotal(total));
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('QueryStringService', function($window) {
    return function(keyName) {
      var hash, hashes, href, i, isNum, len, val, varObj;
      varObj = {};
      href = $window.location.href;
      if (href.indexOf('?') < 0) {
        return;
      }
      hashes = href.slice(href.indexOf('?') + 1).split(/[#&]/);
      isNum = function(num) {
        if (num == null) {
          return;
        }
        if (num.substr(0, 1) === '0') {
          return;
        }
        if (/[a-zA-Z\-\_\+\.\#\%\*\,]/.test(num)) {
          return;
        }
        if (window.isNaN(window.parseInt(num, 10))) {
          return;
        }
        return true;
      };
      for (i = 0, len = hashes.length; i < len; i++) {
        hash = hashes[i];
        hash = hash.split('=');
        val = hash[1];
        if (isNum(val)) {
          val = window.parseInt(val, 10);
        } else {
          if (val === 'true') {
            val = true;
          } else if (val === 'false') {
            val = false;
          } else {
            val = window.decodeURIComponent(val);
          }
        }
        varObj[hash[0]] = val;
      }
      if (keyName) {
        return varObj[keyName];
      }
      return varObj;
    };
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Services').factory('QuestionService', function($window, QueryStringService, $bbug) {
    var addAnswersById, addAnswersByName, addAnswersFromDefaults, addDynamicAnswersByName, checkConditionalQuestions, convertDates, convertToSnakeCase, defaults, findByQuestionId, storeDefaults;
    defaults = QueryStringService() || {};
    convertDates = function(obj) {
      return _.each(obj, function(val, key) {
        var date;
        date = $window.moment(obj[key]);
        if (_.isString(obj[key]) && date.isValid()) {
          return obj[key] = date;
        }
      });
    };
    if ($window.bb_setup) {
      convertDates($window.bb_setup);
      angular.extend(defaults, $window.bb_setup);
    }
    addAnswersById = function(questions) {
      if (!questions) {
        return;
      }
      if (angular.isArray(questions)) {
        return _.each(questions, function(question) {
          var id;
          id = question.id + '';
          if (!question.answer && defaults[id]) {
            return question.answer = defaults[id];
          }
        });
      } else {
        if (defaults[questions.id + '']) {
          return questions.answer = defaults[questions.id + ''];
        }
      }
    };
    convertToSnakeCase = function(str) {
      str = str.toLowerCase();
      str = $.trim(str);
      str = str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|'’!<>;:,.~`=+-@£&%"]/g, '');
      str = str.replace(/\s{2,}/g, ' ');
      str = str.replace(/\s/g, '_');
      return str;
    };
    addDynamicAnswersByName = function(questions) {
      var keys;
      if (angular.isArray(questions)) {
        keys = _.keys(defaults);
        return _.each(questions, function(question) {
          var name;
          name = convertToSnakeCase(question.name);
          return _.each(keys, function(key) {
            if (name.indexOf("_" + key) >= 0 || name.indexOf("_" + key + "_") >= 0 || name.indexOf(key + "_") >= 0) {
              if (defaults[key] && !question.answer) {
                question.answer = defaults[key];
                delete defaults[key];
              }
            }
          });
        });
      }
    };
    addAnswersByName = function(obj, keys) {
      var i, key, len, type;
      type = Object.prototype.toString.call(obj).slice(8, -1);
      if (type === 'Object' && angular.isArray(keys)) {
        for (i = 0, len = keys.length; i < len; i++) {
          key = keys[i];
          if (defaults[key] && !obj[key]) {
            obj[key] = defaults[key];
            delete defaults[key];
          }
        }
      }
    };
    addAnswersFromDefaults = function(questions, answers) {
      var i, len, name, question, results;
      results = [];
      for (i = 0, len = questions.length; i < len; i++) {
        question = questions[i];
        name = question.help_text;
        if (answers[name]) {
          question.answer = answers[name];
        }
        if (answers[question.id + '']) {
          results.push(question.answer = answers[question.id + '']);
        } else {
          results.push(void 0);
        }
      }
      return results;
    };
    storeDefaults = function(obj) {
      return angular.extend(defaults, obj.bb_setup || {});
    };
    checkConditionalQuestions = function(questions) {
      var a, ans, cond, found, i, len, q, ref, results, v;
      results = [];
      for (i = 0, len = questions.length; i < len; i++) {
        q = questions[i];
        if (q.settings && q.settings.conditional_question) {
          cond = findByQuestionId(questions, parseInt(q.settings.conditional_question));
          if (cond) {
            ans = cond.getAnswerId();
            found = false;
            if ($bbug.isEmptyObject(q.settings.conditional_answers) && cond.detail_type === "check" && !cond.answer) {
              found = true;
            }
            ref = q.settings.conditional_answers;
            for (a in ref) {
              v = ref[a];
              if (a[0] === 'c' && parseInt(v) === 1 && cond.answer) {
                found = true;
              } else if (parseInt(a) === ans && parseInt(v) === 1) {
                found = true;
              }
            }
            if (found) {
              results.push(q.showElement());
            } else {
              results.push(q.hideElement());
            }
          } else {
            results.push(void 0);
          }
        } else {
          results.push(void 0);
        }
      }
      return results;
    };
    findByQuestionId = function(questions, qid) {
      var i, len, q;
      for (i = 0, len = questions.length; i < len; i++) {
        q = questions[i];
        if (q.id === qid) {
          return q;
        }
      }
      return null;
    };
    return {
      getStoredData: function() {
        return defaults;
      },
      storeDefaults: storeDefaults,
      addAnswersById: addAnswersById,
      addAnswersByName: addAnswersByName,
      addDynamicAnswersByName: addDynamicAnswersByName,
      addAnswersFromDefaults: addAnswersFromDefaults,
      convertToSnakeCase: convertToSnakeCase,
      checkConditionalQuestions: checkConditionalQuestions
    };
  });

}).call(this);

(function() {
  angular.module("BB.Services").factory("RecaptchaService", function($q, halClient, UriTemplate) {
    return {
      validateResponse: function(params) {
        var deferred, href, prms, uri;
        deferred = $q.defer();
        href = params.api_url + "/api/v1/recaptcha";
        uri = new UriTemplate(href);
        prms = {};
        prms.response = params.response;
        halClient.$post(uri, {}, prms).then(function(response) {
          return deferred.resolve(response);
        }, function(err) {
          return deferred.reject(err);
        });
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ResourceService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('resources')) {
          deferred.reject("No resource found");
        } else {
          company.$get('resources').then((function(_this) {
            return function(resource) {
              return resource.$get('resources').then(function(items) {
                var i, j, len, resources;
                resources = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  resources.push(new BBModel.Resource(i));
                }
                return deferred.resolve(resources);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("ServiceService", function($q, BBModel) {
    return {
      query: function(company) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('services')) {
          deferred.reject("No services found");
        } else {
          company.$get('services').then((function(_this) {
            return function(resource) {
              return resource.$get('services').then(function(items) {
                var i, j, len, services;
                services = [];
                for (j = 0, len = items.length; j < len; j++) {
                  i = items[j];
                  services.push(new BBModel.Service(i));
                }
                return deferred.resolve(services);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('SettingsService', function() {
    var country_code, i18n, scroll_offset;
    i18n = false;
    scroll_offset = 0;
    country_code = "";
    return {
      enableInternationalizaton: function() {
        return i18n = true;
      },
      isInternationalizatonEnabled: function() {
        return i18n;
      },
      setScrollOffset: function(value) {
        return scroll_offset = parseInt(value);
      },
      getScrollOffset: function() {
        return scroll_offset;
      },
      setCountryCode: function(value) {
        return country_code = value;
      },
      getCountryCode: function() {
        return country_code;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("SlotService", function($q, BBModel) {
    return {
      query: function(company, params) {
        var deferred;
        deferred = $q.defer();
        if (!company.$has('slots')) {
          deferred.resolve([]);
        } else {
          if (params.item) {
            if (params.item.resource) {
              params.resource_id = params.item.resource.id;
            }
            if (params.item.person) {
              params.person_id = params.item.person.id;
            }
          }
          company.$get('slots', params).then((function(_this) {
            return function(resource) {
              return resource.$get('slots', params).then(function(slots) {
                var slot;
                slots = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = slots.length; i < len; i++) {
                    slot = slots[i];
                    results.push(new BBModel.Slot(slot));
                  }
                  return results;
                })();
                return deferred.resolve(slots);
              });
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').config(function($provide) {
    return $provide.decorator('$sniffer', function($delegate) {
      var regexp, result, webkit_version;
      regexp = /Safari\/([\d.]+)/;
      result = regexp.exec(navigator.userAgent);
      webkit_version = result ? parseFloat(result[1]) : null;
      _.extend($delegate, {
        webkit: webkit_version
      });
      return $delegate;
    });
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("SpaceService", [
    '$q', function($q, BBModel) {
      return {
        query: function(company) {
          var deferred;
          deferred = $q.defer();
          if (!company.$has('spaces')) {
            deferred.reject("No spaces found");
          } else {
            company.$get('spaces').then((function(_this) {
              return function(resource) {
                return resource.$get('spaces').then(function(items) {
                  var i, j, len, spaces;
                  spaces = [];
                  for (j = 0, len = items.length; j < len; j++) {
                    i = items[j];
                    spaces.push(new BBModel.Space(i));
                  }
                  return deferred.resolve(spaces);
                });
              };
            })(this), (function(_this) {
              return function(err) {
                return deferred.reject(err);
              };
            })(this));
          }
          return deferred.promise;
        }
      };
    }
  ]);

}).call(this);

(function() {
  angular.module('BB.Services').factory("SSOService", function($q, $rootScope, halClient, LoginService) {
    return {
      memberLogin: function(options) {
        var data, deferred, url;
        deferred = $q.defer();
        options.root || (options.root = "");
        url = options.root + "/api/v1/login/sso/" + options.company_id;
        data = {
          token: options.member_sso
        };
        halClient.$post(url, {}, data).then((function(_this) {
          return function(login) {
            var params;
            params = {
              auth_token: login.auth_token
            };
            return login.$get('member').then(function(member) {
              member = LoginService.setLogin(member);
              return deferred.resolve(member);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      },
      adminLogin: function(options) {
        var data, deferred, url;
        deferred = $q.defer();
        options.root || (options.root = "");
        url = options.root + "/api/v1/login/admin_sso/" + options.company_id;
        data = {
          token: options.admin_sso
        };
        halClient.$post(url, {}, data).then((function(_this) {
          return function(login) {
            var params;
            params = {
              auth_token: login.auth_token
            };
            return login.$get('administrator').then(function(admin) {
              return deferred.resolve(admin);
            });
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("TemplateSvc", function($q, $http, $templateCache, BBModel) {
    return {
      get: function(path) {
        var cacheTmpl, deferred;
        deferred = $q.defer();
        cacheTmpl = $templateCache.get(path);
        if (cacheTmpl) {
          deferred.resolve(angular.element(cacheTmpl));
        } else {
          $http({
            method: 'GET',
            url: path
          }).success(function(tmpl, status) {
            $templateCache.put(path, tmpl);
            return deferred.resolve(angular.element(tmpl));
          }).error(function(data, status) {
            return deferred.reject(data);
          });
        }
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("TimeService", function($q, BBModel, halClient) {
    return {
      query: function(prms) {
        var date, deferred, extra, item_link;
        deferred = $q.defer();
        if (prms.date) {
          date = prms.date.toISODate();
        } else {
          if (!prms.cItem.date) {
            deferred.reject("No date set");
            return deferred.promise;
          } else {
            date = prms.cItem.date.date.toISODate();
          }
        }
        if (prms.duration == null) {
          if (prms.cItem && prms.cItem.duration) {
            prms.duration = prms.cItem.duration;
          }
        }
        item_link = prms.item_link;
        if (prms.cItem && prms.cItem.days_link && !item_link) {
          item_link = prms.cItem.days_link;
        }
        if (item_link) {
          extra = {
            date: date
          };
          if (prms.location) {
            extra.location = prms.location;
          }
          if (prms.cItem.event_id) {
            extra.event_id = prms.cItem.event_id;
          }
          if (prms.cItem.person && !prms.cItem.anyPerson() && !item_link.event_id && !extra.event_id) {
            extra.person_id = prms.cItem.person.id;
          }
          if (prms.cItem.resource && !prms.cItem.anyResource() && !item_link.event_id && !extra.event_id) {
            extra.resource_id = prms.cItem.resource.id;
          }
          if (prms.end_date) {
            extra.end_date = prms.end_date.toISODate();
          }
          extra.duration = prms.duration;
          extra.resource_ids = prms.resource_ids;
          extra.num_resources = prms.num_resources;
          if (extra.event_id) {
            item_link = prms.company;
          }
          item_link.$get('times', extra).then((function(_this) {
            return function(results) {
              var times;
              if (results.$has('date_links')) {
                return results.$get('date_links').then(function(all_days) {
                  var all_days_def, date_times, day, fn, j, len;
                  date_times = {};
                  all_days_def = [];
                  fn = function(day) {
                    var times;
                    day.elink = $q.defer();
                    all_days_def.push(day.elink.promise);
                    if (day.$has('event_links')) {
                      return day.$get('event_links').then(function(all_events) {
                        var times;
                        times = _this.merge_times(all_events, prms.cItem.service, prms.cItem);
                        if (prms.available) {
                          times = _.filter(times, function(t) {
                            return t.avail >= prms.available;
                          });
                        }
                        date_times[day.date] = times;
                        return day.elink.resolve();
                      });
                    } else if (day.times) {
                      times = _this.merge_times([day], prms.cItem.service, prms.cItem);
                      if (prms.available) {
                        times = _.filter(times, function(t) {
                          return t.avail >= prms.available;
                        });
                      }
                      date_times[day.date] = times;
                      return day.elink.resolve();
                    }
                  };
                  for (j = 0, len = all_days.length; j < len; j++) {
                    day = all_days[j];
                    fn(day);
                  }
                  return $q.all(all_days_def).then(function() {
                    return deferred.resolve(date_times);
                  });
                });
              } else if (results.$has('event_links')) {
                return results.$get('event_links').then(function(all_events) {
                  var times;
                  times = _this.merge_times(all_events, prms.cItem.service, prms.cItem);
                  if (prms.available) {
                    times = _.filter(times, function(t) {
                      return t.avail >= prms.available;
                    });
                  }
                  return deferred.resolve(times);
                });
              } else if (results.times) {
                times = _this.merge_times([results], prms.cItem.service, prms.cItem);
                if (prms.available) {
                  times = _.filter(times, function(t) {
                    return t.avail >= prms.available;
                  });
                }
                return deferred.resolve(times);
              }
            };
          })(this), function(err) {
            return deferred.reject(err);
          });
        } else {
          deferred.reject("No day data");
        }
        return deferred.promise;
      },
      merge_times: function(all_events, service, item) {
        var date_times, ev, i, j, k, l, len, len1, len2, ref, sorted_times, times;
        if (!all_events || all_events.length === 0) {
          return [];
        }
        all_events = _.shuffle(all_events);
        sorted_times = [];
        for (j = 0, len = all_events.length; j < len; j++) {
          ev = all_events[j];
          if (ev.times) {
            ref = ev.times;
            for (k = 0, len1 = ref.length; k < len1; k++) {
              i = ref[k];
              if (!sorted_times[i.time] || sorted_times[i.time].avail === 0 || (Math.floor(Math.random() * all_events.length) === 0 && i.avail > 0)) {
                i.event_id = ev.event_id;
                sorted_times[i.time] = i;
              }
            }
            if (item.held) {
              this.checkCurrentItem(item.held, sorted_times, ev);
            }
            this.checkCurrentItem(item, sorted_times, ev);
          }
        }
        times = [];
        date_times = {};
        for (l = 0, len2 = sorted_times.length; l < len2; l++) {
          i = sorted_times[l];
          if (i) {
            times.push(new BBModel.TimeSlot(i, service));
          }
        }
        return times;
      },
      checkCurrentItem: function(item, sorted_times, ev) {
        if (item && item.id && item.event_id === ev.event_id && item.time && !sorted_times[item.time.time] && item.date && item.date.date.toISODate() === ev.date) {
          sorted_times[item.time.time] = item.time;
          return halClient.clearCache(ev.$href("self"));
        } else if (item && item.id && item.event_id === ev.event_id && item.time && sorted_times[item.time.time] && item.date && item.date.date.toISODate() === ev.date) {
          return sorted_times[item.time.time].avail = 1;
        }
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory('TimeSlotService', function($q, BBModel) {
    return {
      query: function(params) {
        var company, defer;
        defer = $q.defer();
        company = params.company;
        company.$get('slots', params).then(function(collection) {
          return collection.$get('slots').then(function(slots) {
            var s;
            slots = (function() {
              var i, len, results;
              results = [];
              for (i = 0, len = slots.length; i < len; i++) {
                s = slots[i];
                results.push(new BBModel.TimeSlot(s));
              }
              return results;
            })();
            return defer.resolve(slots);
          }, function(err) {
            return defer.reject(err);
          });
        }, function(err) {
          return defer.reject(err);
        });
        return defer.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("BB.Service.address", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Address(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.person", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Person(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.people", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('people').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Person(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.resource", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Resource(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.resources", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('resources').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Resource(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.service", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Service(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.services", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred, models, service;
        deferred = $q.defer();
        if (angular.isArray(resource)) {
          models = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = resource.length; j < len; j++) {
              service = resource[j];
              results.push(new BBModel.Service(service));
            }
            return results;
          })();
          deferred.resolve(models);
        } else {
          resource.$get('services').then((function(_this) {
            return function(items) {
              var i, j, len;
              models = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                models.push(new BBModel.Service(i));
              }
              return deferred.resolve(models);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.package_item", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.PackageItem(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.package_items", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('package_items').then((function(_this) {
          return function(package_items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = package_items.length; j < len; j++) {
              i = package_items[j];
              models.push(new BBModel.PackageItem(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.bulk_purchase", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.BulkPurchase(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.bulk_purchases", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var bulk_purchase, deferred, models;
        deferred = $q.defer();
        if (angular.isArray(resource)) {
          models = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = resource.length; j < len; j++) {
              bulk_purchase = resource[j];
              results.push(new BBModel.BulkPurchase(bulk_purchase));
            }
            return results;
          })();
          deferred.resolve(models);
        } else {
          resource.$get('bulk_purchases').then((function(_this) {
            return function(bulk_purchases) {
              var i, j, len;
              models = [];
              for (j = 0, len = bulk_purchases.length; j < len; j++) {
                i = bulk_purchases[j];
                models.push(new BBModel.BulkPurchase(i));
              }
              return deferred.resolve(models);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.event_group", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.EventGroup(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.event_groups", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('event_groups').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.EventGroup(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.event_chain", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.EventChain(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.event_chains", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.EventChain(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.category", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Category(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.categories", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('categories').then((function(_this) {
          return function(items) {
            var cat, i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              cat = new BBModel.Category(i);
              cat.order || (cat.order = _i);
              models.push(cat);
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.client", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Client(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.child_clients", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('clients').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Client(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.clients", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('clients').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Client(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.questions", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        var defer, i, j, k, len, len1, ref, results, results1;
        if (resource.questions) {
          ref = resource.questions;
          results = [];
          for (j = 0, len = ref.length; j < len; j++) {
            i = ref[j];
            results.push(new BBModel.Question(i));
          }
          return results;
        } else if (resource.$has('questions')) {
          defer = $q.defer();
          resource.$get('questions').then(function(items) {
            return defer.resolve((function() {
              var k, len1, results1;
              results1 = [];
              for (k = 0, len1 = items.length; k < len1; k++) {
                i = items[k];
                results1.push(new BBModel.Question(i));
              }
              return results1;
            })());
          }, function(err) {
            return defer.reject(err);
          });
          return defer.promise;
        } else {
          results1 = [];
          for (k = 0, len1 = resource.length; k < len1; k++) {
            i = resource[k];
            results1.push(new BBModel.Question(i));
          }
          return results1;
        }
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.question", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Question(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.answers", function($q, BBModel) {
    return {
      promise: false,
      unwrap: function(items) {
        var answers, i, j, len, models;
        models = [];
        for (j = 0, len = items.length; j < len; j++) {
          i = items[j];
          models.push(new BBModel.Answer(i));
        }
        answers = {
          answers: models,
          getAnswer: function(question) {
            var a, k, len1, ref;
            ref = this.answers;
            for (k = 0, len1 = ref.length; k < len1; k++) {
              a = ref[k];
              if (a.question_text === question || a.question_id === question) {
                return a.value;
              }
            }
          }
        };
        return answers;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.administrators", function($q, BBModel) {
    return {
      unwrap: function(items) {
        var i, j, len, results;
        results = [];
        for (j = 0, len = items.length; j < len; j++) {
          i = items[j];
          results.push(new BBModel.Admin.User(i));
        }
        return results;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.company", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Company(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.parent", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Company(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.company_questions", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('company_questions').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.BusinessQuestion(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.company_question", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.BusinessQuestion(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.images", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('images').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Image(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.bookings", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('bookings').then((function(_this) {
          return function(items) {
            var i, j, len, models;
            models = [];
            for (j = 0, len = items.length; j < len; j++) {
              i = items[j];
              models.push(new BBModel.Member.Booking(i));
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.wallet", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Member.Wallet(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.product", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.Product(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.products", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred;
        deferred = $q.defer();
        resource.$get('products').then((function(_this) {
          return function(items) {
            var cat, i, index, j, len, models;
            models = [];
            for (index = j = 0, len = items.length; j < len; index = ++j) {
              i = items[index];
              cat = new BBModel.Product(i);
              cat.order || (cat.order = index);
              models.push(cat);
            }
            return deferred.resolve(models);
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err);
          };
        })(this));
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.pre_paid_booking", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.PrePaidBooking(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.pre_paid_bookings", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred, models, pre_paid_booking;
        deferred = $q.defer();
        if (angular.isArray(resource)) {
          models = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = resource.length; j < len; j++) {
              pre_paid_booking = resource[j];
              results.push(new BBModel.PrePaidBooking(pre_paid_booking));
            }
            return results;
          })();
          deferred.resolve(models);
        } else {
          resource.$get('pre_paid_bookings').then((function(_this) {
            return function(items) {
              var i, j, len;
              models = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                models.push(new BBModel.PrePaidBooking(i));
              }
              return deferred.resolve(models);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.external_purchase", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.ExternalPurchase(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.external_purchases", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred, external_purchase, models;
        deferred = $q.defer();
        if (angular.isArray(resource)) {
          models = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = resource.length; j < len; j++) {
              external_purchase = resource[j];
              results.push(new BBModel.ExternalPurchase(external_purchase));
            }
            return results;
          })();
          deferred.resolve(models);
        } else {
          resource.$get('external_purchases').then((function(_this) {
            return function(items) {
              var i, j, len;
              models = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                models.push(new BBModel.ExternalPurchase(i));
              }
              return deferred.resolve(models);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.purchase_item", function($q, BBModel) {
    return {
      unwrap: function(resource) {
        return new BBModel.PurchaseItem(resource);
      }
    };
  });

  angular.module('BB.Services').factory("BB.Service.purchase_items", function($q, BBModel) {
    return {
      promise: true,
      unwrap: function(resource) {
        var deferred, models, purchase_item;
        deferred = $q.defer();
        if (angular.isArray(resource)) {
          models = (function() {
            var j, len, results;
            results = [];
            for (j = 0, len = resource.length; j < len; j++) {
              purchase_item = resource[j];
              results.push(new BBModel.PurchaseItem(purchase_item));
            }
            return results;
          })();
          deferred.resolve(models);
        } else {
          resource.$get('purchase_items').then((function(_this) {
            return function(items) {
              var i, j, len;
              models = [];
              for (j = 0, len = items.length; j < len; j++) {
                i = items[j];
                models.push(new BBModel.PurchaseItem(i));
              }
              return deferred.resolve(models);
            };
          })(this), (function(_this) {
            return function(err) {
              return deferred.reject(err);
            };
          })(this));
        }
        return deferred.promise;
      }
    };
  });

}).call(this);


/***
* @ngdoc service
* @name BB.Services:Validator
*
* @description
* Representation of an Validator Object
*
* @property {string} uk_postcode_regex The UK postcode regex
* @property {string} uk_postcode_regex_lenient The UK postcode regex (lenient)
* @property {string} number_only_regex The number only regex
* @property {integer} uk_mobile_regex_strict The UK mobile regex (strict)
* @property {integer} mobile_regex_lenient Mobile number regex (lenient)
* @property {integer} uk_landline_regex_strict The UK landline regex (strict)
* @property {integer} uk_landline_regex_lenient The UK landline regex (lenient)
* @property {integer} international_number The international number
* @property {string} alphanumeric The alphanumeric
* @property {string} alpha The letters and spaces
* @property {integer} us_phone_number The Us phone number
 */

(function() {
  angular.module('BB.Services').factory('ValidatorService', function($rootScope, AlertService, SettingsService, BBModel, $q, $bbug) {
    var alphanumeric, email_regex, geocode_result, international_number, mobile_regex_lenient, number_only_regex, standard_password, uk_landline_regex_lenient, uk_landline_regex_strict, uk_mobile_regex_strict, uk_postcode_regex, uk_postcode_regex_lenient, us_postcode_regex;
    uk_postcode_regex = /^(((([A-PR-UWYZ][0-9][0-9A-HJKS-UW]?)|([A-PR-UWYZ][A-HK-Y][0-9][0-9ABEHMNPRV-Y]?))\s{0,1}[0-9]([ABD-HJLNP-UW-Z]{2}))|(GIR\s{0,2}0AA))$/i;
    us_postcode_regex = /^\d{5}(?:[-\s]\d{4})?$/;
    uk_postcode_regex_lenient = /^[A-Z]{1,2}[0-9][0-9A-Z]?\s*[0-9][A-Z]{2}$/i;
    number_only_regex = /^\d+$/;
    uk_mobile_regex_strict = /^((\+44\s?|0)7([45789]\d{2}|624)\s?\d{3}\s?\d{3})$/;
    mobile_regex_lenient = /^(0|\+)([\d \(\)]{9,19})$/;
    uk_landline_regex_strict = /^(\(?(0|\+44)[1-9]{1}\d{1,4}?\)?\s?\d{3,4}\s?\d{3,4})$/;
    uk_landline_regex_lenient = /^(0|\+)([\d \(\)]{9,19})$/;
    international_number = /^(\+)([\d \(\)]{9,19})$/;
    email_regex = /^$|^([^@\s]+)@((?:[-a-z0-9]+\.)+[a-z]{2,})$/i;
    standard_password = /^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$/;
    alphanumeric = /^[a-zA-Z0-9]*$/;
    geocode_result = null;
    return {
      alpha: /^[a-zA-Z\s]*$/,
      us_phone_number: /^\(?([0-9]{3})\)?[-. ]?([0-9]{3})[-. ]?([0-9]{4})$/,

      /***
        * @ngdoc method
        * @name getEmailPattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the email pattern
        *
        * @returns {string} The returned the email pattern
       */
      getEmailPattern: function() {
        return email_regex;
      },

      /***
        * @ngdoc method
        * @name getStandardPassword
        * @methodOf BB.Services:Validator
        * @description
        * Get the email pattern
        *
        * @returns {string} Returns Password must contain at least 7 characters and 1 number password pattern
       */
      getStandardPassword: function() {
        return standard_password;
      },

      /***
        * @ngdoc method
        * @name getUKPostcodePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the UK postcode pattern
        *
        * @returns {string} The returned the UK postcode regex lenient
       */

      /***
        * @ngdoc method
        * @name getUKPostcodePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the UK postcode patternt
        *
        * @returns {integer} Return the UK postcode pattern
       */
      getUKPostcodePattern: function() {
        return uk_postcode_regex_lenient;
      },
      getMailingPattern: function() {
        var cc;
        cc = SettingsService.getCountryCode();
        if (cc = "us") {
          return us_postcode_regex;
        } else {
          return uk_postcode_regex_lenient;
        }
      },

      /***
        * @ngdoc method
        * @name getNumberOnlyPattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the number only pattern
        *
        * @returns {integer} Return the number only regex
       */
      getNumberOnlyPattern: function() {
        return number_only_regex;
      },

      /***
        * @ngdoc method
        * @name getAlphaNumbericPattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the alphanumeric pattern
        *
        * @returns {string} The returned the alphanumeric regex
       */
      getAlphaNumbericPattern: function() {
        return alphanumeric;
      },

      /***
        * @ngdoc method
        * @name getUKMobilePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the UK mobile pattern if strict is equals with false
        *
        * @returns {integer} The returned the UK mobile regixt strict if this is strict else return mobile_regex_lenient
       */
      getUKMobilePattern: function(strict) {
        if (strict == null) {
          strict = false;
        }
        if (strict) {
          return uk_mobile_regex_strict;
        }
        return mobile_regex_lenient;
      },

      /***
        * @ngdoc method
        * @name getMobilePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the mobile pattern
        *
        * @returns {integer} The returned the mobile regex lenient
       */
      getMobilePattern: function() {
        return mobile_regex_lenient;
      },

      /***
        * @ngdoc method
        * @name getUKLandlinePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the UK landline patternt if strict is equals with false
        *
        * @returns {integer} The returned the UK landline regex strict if this is strict else return UK landline regex lenient
       */
      getUKLandlinePattern: function(strict) {
        if (strict == null) {
          strict = false;
        }
        if (strict) {
          return uk_landline_regex_strict;
        }
        return uk_landline_regex_lenient;
      },

      /***
        * @ngdoc method
        * @name getIntPhonePattern
        * @methodOf BB.Services:Validator
        * @description
        * Get the international number
        *
        * @returns {integer} The returned the international number
       */
      getIntPhonePattern: function() {
        return international_number;
      },

      /***
        * @ngdoc method
        * @name getGeocodeResult
        * @methodOf BB.Services:Validator
        * @description
        * Get the geocode result
        *
        * @returns {string} The returned geocode result
       */
      getGeocodeResult: function() {
        if (geocode_result) {
          return geocode_result;
        }
      },

      /***
        * @ngdoc method
        * @name validatePostcode
        * @methodOf BB.Services:Validator
        * @description
        * Validate the postcode in according with form and prm parameters
        *
        * @returns {promise} A promise for valid postocde
       */
      validatePostcode: function(form, prms) {
        var deferred, geocoder, ne, postcode, req, sw;
        AlertService.clear();
        if (!form || !form.postcode) {
          return false;
        }
        if (form.$error.required) {
          AlertService.raise('MISSING_POSTCODE');
          return false;
        } else if (form.$error.pattern) {
          AlertService.raise('INVALID_POSTCODE');
          return false;
        } else {
          deferred = $q.defer();
          postcode = form.postcode.$viewValue;
          req = {
            address: postcode
          };
          if (prms.region) {
            req.region = prms.region;
          }
          req.componentRestrictions = {
            'postalCode': req.address
          };
          if (prms.bounds) {
            sw = new google.maps.LatLng(prms.bounds.sw.x, prms.bounds.sw.y);
            ne = new google.maps.LatLng(prms.bounds.ne.x, prms.bounds.ne.y);
            req.bounds = new google.maps.LatLngBounds(sw, ne);
          }
          geocoder = new google.maps.Geocoder();
          geocoder.geocode(req, function(results, status) {
            if (results.length === 1 && status === 'OK') {
              geocode_result = results[0];
              return deferred.resolve(true);
            } else {
              AlertService.raise('INVALID_POSTCODE');
              $rootScope.$apply();
              return deferred.reject(false);
            }
          });
          return deferred.promise;
        }
      },

      /***
        * @ngdoc method
        * @name validateForm
        * @methodOf BB.Services:Validator
        * @description
        * Validate the form in according with form parameter
        *
        * @returns {boolean} Checks if this is valid or not
       */
      validateForm: function(form) {
        if (!form) {
          return false;
        }
        form.submitted = true;
        $rootScope.$broadcast("form:validated", form);
        if (form.$invalid && form.raise_alerts && form.alert) {
          AlertService.danger(form.alert);
          return false;
        } else if (form.$invalid && form.raise_alerts) {
          AlertService.danger(ErrorService.getError('FORM_INVALID'));
          return false;
        } else if (form.$invalid) {
          return false;
        } else {
          return true;
        }
      }

      /***
       * @ngdoc method
       * @name resetForm
       * @methodOf BB.Services:Validator
       * @description
       * Reset the form in according with form parameter
       *
       * @returns {boolean} Checks if this is reset or not
       */
    };
  });

  ({
    resetForm: function(form) {
      if (form) {
        form.submitted = false;
        return form.$setPristine();
      }
    },

    /***
      * @ngdoc method
      * @name resetForms
      * @methodOf BB.Services:Validator
      * @description
      * Reset the forms in according with forms parameter
      *
      * @returns {boolean} Checks if this is reset or not
     */
    resetForms: function(forms) {
      var form, i, len, results1;
      if (forms && $bbug.isArray(forms)) {
        results1 = [];
        for (i = 0, len = forms.length; i < len; i++) {
          form = forms[i];
          form.submitted = false;
          results1.push(form.$setPristine());
        }
        return results1;
      }
    }
  });

}).call(this);

(function() {
  'use strict';

  /***
  * @ngdoc service
  * @name BB.Models:BBWidget
  *
  * @description
  * Representation of an BBWidget Object
  *
  * @property {integer} uid The unique id of the widget
  * @property {string} page_suffix Widget page suffix
  * @property {array} steps The widget steps
  * @property {array} allSteps The all steps of the widget
  * @property {object} item_defaults Widget defaults item
  * @property {boolean} Checks if widget using basket or not
  * @property {boolean} confirmCheckout Checks if widget confirm is checkout or not
  * @property {boolean} isAdm,in Verify if user is admin
  * @property {string} payment_status The payment status
   */
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; };

  angular.module('BB.Models').factory("BBWidget", function($q, BBModel, BasketService, $urlMatcherFactory, $location, BreadcrumbService, $window, $rootScope) {
    var Widget;
    return Widget = (function() {
      function Widget() {
        this.clearAddress = bind(this.clearAddress, this);
        this.emptyStackedItems = bind(this.emptyStackedItems, this);
        this.deleteStackedItemByService = bind(this.deleteStackedItemByService, this);
        this.removeItemFromStack = bind(this.removeItemFromStack, this);
        this.deleteStackedItem = bind(this.deleteStackedItem, this);
        this.sortStackedItems = bind(this.sortStackedItems, this);
        this.setStackedItems = bind(this.setStackedItems, this);
        this.stackItem = bind(this.stackItem, this);
        this.waitForRoutes = bind(this.waitForRoutes, this);
        this.setBasicRoute = bind(this.setBasicRoute, this);
        this.setRoute = bind(this.setRoute, this);
        this.calculatePercentageComplete = bind(this.calculatePercentageComplete, this);
        this.recordStep = bind(this.recordStep, this);
        this.recordCurrentPage = bind(this.recordCurrentPage, this);
        this.uid = _.uniqueId('bbwidget_');
        this.page_suffix = "";
        this.steps = [];
        this.allSteps = [];
        this.item_defaults = {};
        this.usingBasket = false;
        this.confirmCheckout = false;
        this.isAdmin = false;
        this.payment_status = null;
      }


      /***
      * @ngdoc method
      * @name pageURL
      * @methodOf BB.Models:BBWidget
      * @description
      * Get page url in according of route
      *
      * @returns {object} The returned the page url
       */

      Widget.prototype.pageURL = function(route) {
        return route + '.html';
      };


      /***
      * @ngdoc method
      * @name updateRoute
      * @methodOf BB.Models:BBWidget
      * @description
      * Update page route
      *
      * @returns {string} The returned the url
       */

      Widget.prototype.updateRoute = function(page) {
        var company, date, event_group, pattern, prms, service_name, time, url;
        if (!this.routeFormat) {
          return;
        }
        page || (page = this.current_page);
        pattern = $urlMatcherFactory.compile(this.routeFormat);
        service_name = "-";
        event_group = "-";
        if (this.current_item) {
          if (this.current_item.service) {
            service_name = this.convertToDashSnakeCase(this.current_item.service.name);
          }
          if (this.current_item.event_group) {
            event_group = this.convertToDashSnakeCase(this.current_item.event_group.name);
          }
          if (this.current_item.date) {
            date = this.current_item.date.date.toISODate();
          }
          if (this.current_item.time) {
            time = this.current_item.time.time;
          }
          if (this.current_item.company) {
            company = this.convertToDashSnakeCase(this.current_item.company.name);
          }
        }
        if (this.route_values) {
          prms = angular.copy(this.route_values);
        }
        prms || (prms = {});
        angular.extend(prms, {
          page: page,
          company: company,
          service: service_name,
          event_group: event_group,
          date: date,
          time: time
        });
        url = pattern.format(prms);
        url = url.replace(/\/+$/, "");
        $location.path(url);
        this.routing = true;
        return url;
      };


      /***
      * @ngdoc method
      * @name setRouteFormat
      * @methodOf BB.Models:BBWidget
      * @description
      * Set route format
      *
      * @returns {object} The returned the match
       */

      Widget.prototype.setRouteFormat = function(route) {
        var match, match_test, parts, path, pattern;
        this.routeFormat = route;
        if (!this.routeFormat) {
          return;
        }
        this.routing = true;
        path = $location.path();
        if (path) {
          parts = this.routeFormat.split("/");
          while (parts.length > 0 && !match) {
            match_test = parts.join("/");
            pattern = $urlMatcherFactory.compile(match_test);
            match = pattern.exec(path);
            parts.pop();
          }
          if (match) {
            if (match.company) {
              this.item_defaults.company = decodeURIComponent(match.company);
            }
            if (match.service && match.service !== "-") {
              this.item_defaults.service = decodeURIComponent(match.service);
            }
            if (match.event_group && match.event_group !== "-") {
              this.item_defaults.event_group = match.event_group;
            }
            if (match.person) {
              this.item_defaults.person = decodeURIComponent(match.person);
            }
            if (match.resource) {
              this.item_defaults.resource = decodeURIComponent(match.resource);
            }
            if (match.resources) {
              this.item_defaults.resources = decodeURIComponent(match.resoures);
            }
            if (match.date) {
              this.item_defaults.date = match.date;
            }
            if (match.time) {
              this.item_defaults.time = match.time;
            }
            return this.route_matches = match;
          }
        }
      };


      /***
      * @ngdoc method
      * @name matchURLToStep
      * @methodOf BB.Models:BBWidget
      * @description
      * Match url to step
      *
      * @returns {integer} Returns the step number
       */

      Widget.prototype.matchURLToStep = function() {
        var path, step;
        if (!this.routeFormat) {
          return null;
        }
        path = $location.path();
        step = _.findWhere(this.allSteps, {
          page: path.replace(/\//g, '')
        });
        if (step) {
          return step.number;
        } else {
          return null;
        }
      };


      /***
      * @ngdoc method
      * @name convertToDashSnakeCase
      * @methodOf BB.Models:BBWidget
      * @description
      * Convert to dash snake case in according of str parameter
      *
      * @returns {string} The returned str
       */

      Widget.prototype.convertToDashSnakeCase = function(str) {
        str = str.toLowerCase();
        str = $.trim(str);
        str = str.replace(/[\-\[\]\/\{\}\(\)\*\+\?\.\\\^\$\|'’!<>;:,.~`=+-@£&%"]/g, '');
        str = str.replace(/\s{2,}/g, ' ');
        str = str.replace(/\s/g, '-');
        return str;
      };


      /***
      * @ngdoc method
      * @name recordCurrentPage
      * @methodOf BB.Models:BBWidget
      * @description
      * Records the current page and determines the current step from either the predefined steps or the steps that have been passed already
      *
      * @returns {string} The returned record step
       */

      Widget.prototype.recordCurrentPage = function() {
        var j, k, l, len, len1, len2, match, ref, ref1, ref2, step, title;
        if (!this.current_step) {
          this.current_step = 0;
        }
        match = false;
        if (this.allSteps) {
          ref = this.allSteps;
          for (j = 0, len = ref.length; j < len; j++) {
            step = ref[j];
            if (step.page === this.current_page) {
              this.current_step = step.number;
              match = true;
            }
          }
        }
        if (!match) {
          ref1 = this.steps;
          for (k = 0, len1 = ref1.length; k < len1; k++) {
            step = ref1[k];
            if (step && step.page === this.current_page) {
              this.current_step = step.number;
              match = true;
            }
          }
        }
        if (!match) {
          this.current_step += 1;
        }
        title = "";
        if (this.allSteps) {
          ref2 = this.allSteps;
          for (l = 0, len2 = ref2.length; l < len2; l++) {
            step = ref2[l];
            step.active = false;
            step.passed = step.number < this.current_step;
          }
          if (this.allSteps[this.current_step - 1]) {
            this.allSteps[this.current_step - 1].active = true;
            title = this.allSteps[this.current_step - 1].title;
          }
        }
        return this.recordStep(this.current_step, title);
      };


      /***
      * @ngdoc method
      * @name recordStep
      * @methodOf BB.Models:BBWidget
      * @description
      * Record step in according of step and title parameters. Calculate percentile complete
      *
      * @returns {boolean} If is the last step or not
       */

      Widget.prototype.recordStep = function(step, title) {
        var j, len, ref;
        this.steps[step - 1] = {
          url: this.updateRoute(this.current_page),
          current_item: this.current_item.getStep(),
          page: this.current_page,
          number: step,
          title: title,
          stacked_length: this.stacked_items.length
        };
        BreadcrumbService.setCurrentStep(step);
        ref = this.steps;
        for (j = 0, len = ref.length; j < len; j++) {
          step = ref[j];
          if (step) {
            step.passed = step.number < this.current_step;
            step.active = step.number === this.current_step;
          }
        }
        this.calculatePercentageComplete(step.number);
        if ((this.allSteps && this.allSteps.length === step) || this.current_page === 'checkout') {
          return this.last_step_reached = true;
        } else {
          return this.last_step_reached = false;
        }
      };


      /***
      * @ngdoc method
      * @name calculatePercentageComplete
      * @methodOf BB.Models:BBWidget
      * @description
      * Calculate percentage complete in according of step number parameter
      *
      * @returns {integer} The returned percentage complete
       */

      Widget.prototype.calculatePercentageComplete = function(step_number) {
        return this.percentage_complete = step_number && this.allSteps ? step_number / this.allSteps.length * 100 : 0;
      };


      /***
      * @ngdoc method
      * @name setRoute
      * @methodOf BB.Models:BBWidget
      * @description
      * Set route data
      *
      * @returns {object} The returned route set
       */

      Widget.prototype.setRoute = function(rdata) {
        var i, j, k, len, len1, ref, route, step;
        this.allSteps.length = 0;
        this.nextSteps = {};
        if (!(rdata === void 0 || rdata === null || rdata[0] === void 0)) {
          this.firstStep = rdata[0].page;
        }
        for (i = j = 0, len = rdata.length; j < len; i = ++j) {
          step = rdata[i];
          if (step.disable_breadcrumbs) {
            this.disableGoingBackAtStep = i + 1;
          }
          if (rdata[i + 1]) {
            this.nextSteps[step.page] = rdata[i + 1].page;
          }
          this.allSteps.push({
            number: i + 1,
            title: step.title,
            page: step.page
          });
          if (step.when) {
            this.routeSteps || (this.routeSteps = {});
            ref = step.when;
            for (k = 0, len1 = ref.length; k < len1; k++) {
              route = ref[k];
              this.routeSteps[route] = step.page;
            }
          }
        }
        if (this.$wait_for_routing) {
          return this.$wait_for_routing.resolve();
        }
      };


      /***
      * @ngdoc method
      * @name setBasicRoute
      * @methodOf BB.Models:BBWidget
      * @description
      * Set basic route in according of routes parameter
      *
      * @returns {object} The returned route set
       */

      Widget.prototype.setBasicRoute = function(routes) {
        var i, j, len, step;
        this.nextSteps = {};
        this.firstStep = routes[0];
        for (i = j = 0, len = routes.length; j < len; i = ++j) {
          step = routes[i];
          this.nextSteps[step] = routes[i + 1];
        }
        if (this.$wait_for_routing) {
          return this.$wait_for_routing.resolve();
        }
      };


      /***
      * @ngdoc method
      * @name waitForRoutes
      * @methodOf BB.Models:BBWidget
      * @description
      * Wait for route
      *
      * @returns {object}  The returned waiting route
       */

      Widget.prototype.waitForRoutes = function() {
        if (!this.$wait_for_routing) {
          return this.$wait_for_routing = $q.defer();
        }
      };


      /***
      * @ngdoc method
      * @name stackItem
      * @methodOf BB.Models:BBWidget
      * @description
      * Push item in stacked items in according of item parameter
      *
      * @returns {array} The returned sorted stacked items
       */

      Widget.prototype.stackItem = function(item) {
        this.stacked_items.push(item);
        return this.sortStackedItems();
      };


      /***
      * @ngdoc method
      * @name setStackedItems
      * @methodOf BB.Models:BBWidget
      * @description
      * Set stacket items in according of items parameter
      *
      * @returns {array} The returned sorted stacked items
       */

      Widget.prototype.setStackedItems = function(items) {
        this.stacked_items = items;
        return this.sortStackedItems();
      };


      /***
      * @ngdoc method
      * @name sortStackedItems
      * @methodOf BB.Models:BBWidget
      * @description
      * Sort stacked items
      *
      * @returns {array} The returned sorted stacked items
       */

      Widget.prototype.sortStackedItems = function() {
        var arr, item, j, len, ref;
        arr = [];
        ref = this.stacked_items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          arr = arr.concat(item.promises);
        }
        return $q.all(arr)['finally']((function(_this) {
          return function() {
            return _this.stacked_items = _this.stacked_items.sort(function(a, b) {
              var ref1, ref2;
              if (a.time && b.time) {
                return (ref1 = a.time.time > b.time.time) != null ? ref1 : {
                  1: -1
                };
              } else if (a.service.category && !b.service.category) {
                return 1;
              } else if (b.service.category && !a.service.category) {
                return -1;
              } else if (!b.service.category && !a.service.category) {
                return 1;
              } else {
                return (ref2 = a.service.category.order > b.service.category.order) != null ? ref2 : {
                  1: -1
                };
              }
            });
          };
        })(this));
      };


      /***
      * @ngdoc method
      * @name deleteStackedItem
      * @methodOf BB.Models:BBWidget
      * @description
      * Delete stacked item in according of item parameter
      *
      * @returns {array} The returned stacked items
       */

      Widget.prototype.deleteStackedItem = function(item) {
        if (item && item.id) {
          BasketService.deleteItem(item, this.company, {
            bb: this
          });
        }
        return this.stacked_items = this.stacked_items.filter(function(i) {
          return i !== item;
        });
      };


      /***
      * @ngdoc method
      * @name removeItemFromStack
      * @methodOf BB.Models:BBWidget
      * @description
      * Remove item from stack in according of item parameter
      *
      * @returns {array} The returned stacked items
       */

      Widget.prototype.removeItemFromStack = function(item) {
        return this.stacked_items = this.stacked_items.filter(function(i) {
          return i !== item;
        });
      };


      /***
      * @ngdoc method
      * @name deleteStackedItemByService
      * @methodOf BB.Models:BBWidget
      * @description
      * Delete stacked item bu service in according of item parameter
      *
      * @returns {array} The returned stacked items
       */

      Widget.prototype.deleteStackedItemByService = function(item) {
        var i, j, len, ref;
        ref = this.stacked_items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          if (i && i.service && i.service.self === item.self && i.id) {
            BasketService.deleteItem(i, this.company, {
              bb: this
            });
          }
        }
        return this.stacked_items = this.stacked_items.filter(function(i) {
          return i && i.service && i.service.self !== item.self;
        });
      };


      /***
      * @ngdoc method
      * @name emptyStackedItems
      * @methodOf BB.Models:BBWidget
      * @description
      * Empty stacked items
      *
      * @returns {array} The returned stacked items empty
       */

      Widget.prototype.emptyStackedItems = function() {
        return this.stacked_items = [];
      };


      /***
      * @ngdoc method
      * @name pushStackToBasket
      * @methodOf BB.Models:BBWidget
      * @description
      * Push stack to basket
      *
      * @returns {array} The returned stacked items
       */

      Widget.prototype.pushStackToBasket = function() {
        var i, j, len, ref;
        this.basket || (this.basket = new new BBModel.Basket(null, this));
        ref = this.stacked_items;
        for (j = 0, len = ref.length; j < len; j++) {
          i = ref[j];
          this.basket.addItem(i);
        }
        return this.emptyStackedItems();
      };


      /***
      * @ngdoc method
      * @name totalStackedItemsDuration
      * @methodOf BB.Models:BBWidget
      * @description
      * Total stacked items duration
      *
      * @returns {array} The returned duration
       */

      Widget.prototype.totalStackedItemsDuration = function() {
        var duration, item, j, len, ref;
        duration = 0;
        ref = this.stacked_items;
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          if (item.service && item.service.listed_duration) {
            duration += item.service.listed_duration;
          }
        }
        return duration;
      };


      /***
      * @ngdoc method
      * @name clearStackedItemsDateTime
      * @methodOf BB.Models:BBWidget
      * @description
      * Clear stacked items date and time
      *
      * @returns {array} The returned item with date and time clear
       */

      Widget.prototype.clearStackedItemsDateTime = function() {
        var item, j, len, ref, results;
        ref = this.stacked_items;
        results = [];
        for (j = 0, len = ref.length; j < len; j++) {
          item = ref[j];
          results.push(item.clearDateTime());
        }
        return results;
      };


      /***
      * @ngdoc method
      * @name clearAddress
      * @methodOf BB.Models:BBWidget
      * @description
      * Clear address
      *
      * @returns {string} The returned address clear
       */

      Widget.prototype.clearAddress = function() {
        delete this.address1;
        delete this.address2;
        delete this.address3;
        delete this.address4;
        return delete this.address5;
      };

      return Widget;

    })();
  });

}).call(this);

(function() {
  var ModalDelete, ModalDeleteAll;

  angular.module('BB.Directives').directive('bbPurchase', function() {
    return {
      restrict: 'AE',
      replace: true,
      scope: true,
      controller: 'Purchase',
      link: function(scope, element, attrs) {
        scope.init(scope.$eval(attrs.bbPurchase));
      }
    };
  });

  angular.module('BB.Controllers').controller('Purchase', function($scope, $rootScope, CompanyService, PurchaseService, ClientService, $modal, $location, $timeout, BBWidget, BBModel, $q, QueryStringService, SSOService, AlertService, LoginService, $window, $upload, ServiceService, $sessionStorage, SettingsService, $translate) {
    var checkIfMoveBooking, checkIfWaitlistBookings, failMsg, getCompanyID, getPurchaseID, loginRequired, setPurchaseCompany;
    $scope.controller = "Purchase";
    $scope.is_waitlist = false;
    $scope.make_payment = false;
    setPurchaseCompany = function(company) {
      $scope.bb.company_id = company.id;
      $scope.bb.company = new BBModel.Company(company);
      $scope.company = $scope.bb.company;
      $scope.bb.item_defaults.company = $scope.bb.company;
      if (company.settings) {
        if (company.settings.merge_resources) {
          $scope.bb.item_defaults.merge_resources = true;
        }
        if (company.settings.merge_people) {
          return $scope.bb.item_defaults.merge_people = true;
        }
      }
    };
    failMsg = function() {
      if ($scope.fail_msg) {
        return AlertService.danger({
          msg: $scope.fail_msg
        });
      } else {
        if (SettingsService.isInternationalizatonEnabled()) {
          return $translate('ERROR.GENERIC', {}).then(function(translated_text) {
            return AlertService.add("danger", {
              msg: translated_text
            });
          });
        } else {
          return AlertService.raise('GENERIC');
        }
      }
    };
    $scope.init = function(options) {
      if (!options) {
        options = {};
      }
      $scope.notLoaded($scope);
      if (options.move_route) {
        $scope.move_route = options.move_route;
      }
      if (options.move_all) {
        $scope.move_all = options.move_all;
      }
      if (options.fail_msg) {
        $scope.fail_msg = options.fail_msg;
      }
      if ($scope.bb.total) {
        return $scope.load($scope.bb.total.long_id);
      } else if ($scope.bb.purchase) {
        $scope.purchase = $scope.bb.purchase;
        $scope.bookings = $scope.bb.purchase.bookings;
        if ($scope.purchase.confirm_messages) {
          $scope.messages = $scope.purchase.confirm_messages;
        }
        return $scope.setLoaded($scope);
      } else {
        if (options.member_sso) {
          return SSOService.memberLogin(options).then(function(login) {
            return $scope.load();
          }, function(err) {
            $scope.setLoaded($scope);
            return failMsg();
          });
        } else {
          return $scope.load();
        }
      }
    };
    $scope.load = function(id) {
      $scope.notLoaded($scope);
      id = getPurchaseID();
      if (!($scope.loaded || !id)) {
        $rootScope.widget_started.then((function(_this) {
          return function() {
            return $scope.waiting_for_conn_started.then(function() {
              var auth_token, company_id, params;
              company_id = getCompanyID();
              if (company_id) {
                CompanyService.query(company_id, {}).then(function(company) {
                  return setPurchaseCompany(company);
                });
              }
              params = {
                purchase_id: id,
                url_root: $scope.bb.api_url
              };
              auth_token = $sessionStorage.getItem('auth_token');
              if (auth_token) {
                params.auth_token = auth_token;
              }
              return PurchaseService.query(params).then(function(purchase) {
                if ($scope.bb.company == null) {
                  purchase.$get('company').then((function(_this) {
                    return function(company) {
                      return setPurchaseCompany(company);
                    };
                  })(this));
                }
                $scope.purchase = purchase;
                $scope.bb.purchase = purchase;
                $scope.price = !($scope.purchase.price === 0);
                $scope.purchase.getBookingsPromise().then(function(bookings) {
                  var booking, i, len, ref, results;
                  $scope.bookings = bookings;
                  if (bookings[0]) {
                    bookings[0].getCompanyPromise().then(function(company) {
                      $scope.purchase.bookings[0].company = company;
                      return company.getAddressPromise().then(function(address) {
                        return $scope.purchase.bookings[0].company.address = address;
                      });
                    });
                  }
                  $scope.setLoaded($scope);
                  checkIfMoveBooking(bookings);
                  checkIfWaitlistBookings(bookings);
                  ref = $scope.bookings;
                  results = [];
                  for (i = 0, len = ref.length; i < len; i++) {
                    booking = ref[i];
                    results.push(booking.getAnswersPromise().then(function(answers) {
                      return booking.answers = answers;
                    }));
                  }
                  return results;
                }, function(err) {
                  $scope.setLoaded($scope);
                  return failMsg();
                });
                if (purchase.$has('client')) {
                  purchase.$get('client').then((function(_this) {
                    return function(client) {
                      return $scope.setClient(new BBModel.Client(client));
                    };
                  })(this));
                }
                return $scope.purchase.getConfirmMessages().then(function(messages) {
                  $scope.purchase.confirm_messages = messages;
                  return $scope.messages = messages;
                });
              }, function(err) {
                $scope.setLoaded($scope);
                if (err && err.status === 401) {
                  if (LoginService.isLoggedIn()) {
                    return failMsg();
                  } else {
                    return loginRequired();
                  }
                } else {
                  return failMsg();
                }
              });
            }, function(err) {
              return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
            });
          };
        })(this), function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        });
      }
      return $scope.loaded = true;
    };
    checkIfMoveBooking = function(bookings) {
      var b, id, matches, move_booking;
      matches = /^.*(?:\?|&)move_booking=(.*?)(?:&|$)/.exec($location.absUrl());
      if (matches) {
        id = parseInt(matches[1]);
      }
      if (id) {
        move_booking = (function() {
          var i, len, results;
          results = [];
          for (i = 0, len = bookings.length; i < len; i++) {
            b = bookings[i];
            if (b.id === id) {
              results.push(b);
            }
          }
          return results;
        })();
        if (move_booking.length > 0 && $scope.isMovable(bookings[0])) {
          return $scope.move(move_booking[0]);
        }
      }
    };
    checkIfWaitlistBookings = function(bookings) {
      var booking;
      return $scope.waitlist_bookings = (function() {
        var i, len, results;
        results = [];
        for (i = 0, len = bookings.length; i < len; i++) {
          booking = bookings[i];
          if (booking.on_waitlist && booking.settings.sent_waitlist === 1) {
            results.push(booking);
          }
        }
        return results;
      })();
    };
    loginRequired = (function(_this) {
      return function() {
        if (!$scope.bb.login_required) {
          return window.location = window.location.href + "&login=true";
        }
      };
    })(this);
    getCompanyID = function() {
      var company_id, matches;
      matches = /^.*(?:\?|&)company_id=(.*?)(?:&|$)/.exec($location.absUrl());
      if (matches) {
        company_id = matches[1];
      }
      return company_id;
    };
    getPurchaseID = function() {
      var id, matches;
      matches = /^.*(?:\?|&)id=(.*?)(?:&|$)/.exec($location.absUrl());
      if (!matches) {
        matches = /^.*print_purchase\/(.*?)(?:\?|$)/.exec($location.absUrl());
      }
      if (!matches) {
        matches = /^.*print_purchase_jl\/(.*?)(?:\?|$)/.exec($location.absUrl());
      }
      if (matches) {
        id = matches[1];
      } else {
        if (QueryStringService('ref')) {
          id = QueryStringService('ref');
        }
      }
      if (QueryStringService('booking_id')) {
        id = QueryStringService('booking_id');
      }
      return id;
    };
    $scope.move = function(booking, route, options) {
      if (options == null) {
        options = {};
      }
      route || (route = $scope.move_route);
      if ($scope.move_all) {
        return $scope.moveAll(route, options);
      }
      $scope.notLoaded($scope);
      $scope.initWidget({
        company_id: booking.company_id,
        no_route: true
      });
      return $timeout((function(_this) {
        return function() {
          return $rootScope.connection_started.then(function() {
            var new_item, proms;
            proms = [];
            $scope.bb.moving_booking = booking;
            $scope.quickEmptybasket();
            new_item = new BBModel.BasketItem(booking, $scope.bb);
            new_item.setSrcBooking(booking, $scope.bb);
            new_item.ready = false;
            Array.prototype.push.apply(proms, new_item.promises);
            $scope.bb.basket.addItem(new_item);
            $scope.setBasketItem(new_item);
            return $q.all(proms).then(function() {
              $scope.setLoaded($scope);
              $rootScope.$broadcast("booking:move");
              return $scope.decideNextPage(route);
            }, function(err) {
              $scope.setLoaded($scope);
              return failMsg();
            });
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        };
      })(this));
    };
    $scope.moveAll = function(route, options) {
      if (options == null) {
        options = {};
      }
      route || (route = $scope.move_route);
      $scope.notLoaded($scope);
      $scope.initWidget({
        company_id: $scope.bookings[0].company_id,
        no_route: true
      });
      return $timeout((function(_this) {
        return function() {
          return $rootScope.connection_started.then(function() {
            var booking, i, len, new_item, proms, ref;
            proms = [];
            if ($scope.bookings.length === 1) {
              $scope.bb.moving_booking = $scope.bookings[0];
            } else {
              $scope.bb.moving_booking = $scope.purchase;
            }
            if (_.every(_.map($scope.bookings, function(b) {
              return b.event_id;
            }), function(event_id) {
              return event_id === $scope.bookings[0].event_id;
            })) {
              $scope.bb.moving_purchase = $scope.purchase;
            }
            $scope.quickEmptybasket();
            ref = $scope.bookings;
            for (i = 0, len = ref.length; i < len; i++) {
              booking = ref[i];
              new_item = new BBModel.BasketItem(booking, $scope.bb);
              new_item.setSrcBooking(booking);
              new_item.ready = false;
              new_item.move_done = false;
              Array.prototype.push.apply(proms, new_item.promises);
              $scope.bb.basket.addItem(new_item);
            }
            $scope.bb.sortStackedItems();
            $scope.setBasketItem($scope.bb.basket.items[0]);
            return $q.all(proms).then(function() {
              $scope.setLoaded($scope);
              return $scope.decideNextPage(route);
            }, function(err) {
              $scope.setLoaded($scope);
              return failMsg();
            });
          }, function(err) {
            return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
          });
        };
      })(this));
    };
    $scope.bookWaitlistItem = function(booking) {
      var params;
      $scope.notLoaded($scope);
      params = {
        purchase: $scope.purchase,
        booking: booking
      };
      return PurchaseService.bookWaitlistItem(params).then(function(purchase) {
        $scope.purchase = purchase;
        $scope.total = $scope.purchase;
        $scope.bb.purchase = purchase;
        return $scope.purchase.getBookingsPromise().then(function(bookings) {
          $scope.bookings = bookings;
          $scope.waitlist_bookings = (function() {
            var i, len, ref, results;
            ref = $scope.bookings;
            results = [];
            for (i = 0, len = ref.length; i < len; i++) {
              booking = ref[i];
              if (booking.on_waitlist && booking.settings.sent_waitlist === 1) {
                results.push(booking);
              }
            }
            return results;
          })();
          if ($scope.purchase.$has('new_payment') && $scope.purchase.due_now > 0) {
            $scope.make_payment = true;
          }
          return $scope.setLoaded($scope);
        }, function(err) {
          $scope.setLoaded($scope);
          return failMsg();
        });
      }, (function(_this) {
        return function(err) {
          return $scope.setLoadedAndShowError($scope, err, 'Sorry, something went wrong');
        };
      })(this));
    };
    $scope["delete"] = function(booking) {
      var modalInstance;
      modalInstance = $modal.open({
        templateUrl: $scope.getPartial("_cancel_modal"),
        controller: ModalDelete,
        resolve: {
          booking: function() {
            return booking;
          }
        }
      });
      return modalInstance.result.then(function(booking) {
        return booking.$del('self').then((function(_this) {
          return function(service) {
            $scope.bookings = _.without($scope.bookings, booking);
            return $rootScope.$broadcast("booking:cancelled");
          };
        })(this));
      });
    };
    $scope.deleteAll = function() {
      var modalInstance;
      modalInstance = $modal.open({
        templateUrl: $scope.getPartial("_cancel_modal"),
        controller: ModalDeleteAll,
        resolve: {
          purchase: function() {
            return $scope.purchase;
          }
        }
      });
      return modalInstance.result.then(function(purchase) {
        return PurchaseService.deleteAll(purchase).then(function(purchase) {
          $scope.purchase = purchase;
          $scope.bookings = [];
          return $rootScope.$broadcast("booking:cancelled");
        });
      });
    };
    $scope.isMovable = function(booking) {
      if (booking.min_cancellation_time) {
        return moment().isBefore(booking.min_cancellation_time);
      }
      return booking.datetime.isAfter(moment());
    };
    $scope.onFileSelect = function(booking, $file, existing) {
      var att_id, file, method;
      $scope.upload_progress = 0;
      file = $file;
      att_id = null;
      if (existing) {
        att_id = existing.id;
      }
      method = "POST";
      if (att_id) {
        method = "PUT";
      }
      return $scope.upload = $upload.upload({
        url: booking.$href('attachments'),
        method: method,
        data: {
          att_id: att_id
        },
        file: file
      }).progress(function(evt) {
        if ($scope.upload_progress < 100) {
          return $scope.upload_progress = parseInt(99.0 * evt.loaded / evt.total);
        }
      }).success(function(data, status, headers, config) {
        $scope.upload_progress = 100;
        if (data && data.attachments && booking) {
          return booking.attachments = data.attachments;
        }
      });
    };
    $scope.createBasketItem = function(booking) {
      var item;
      item = new BBModel.BasketItem(booking, $scope.bb);
      item.setSrcBooking(booking);
      return item;
    };
    $scope.checkAnswer = function(answer) {
      return typeof answer.value === 'boolean' || typeof answer.value === 'string' || typeof answer.value === "number";
    };
    return $scope.changeAttendees = function(route) {
      return $scope.moveAll(route);
    };
  });

  ModalDelete = function($scope, $rootScope, $modalInstance, booking, AlertService) {
    $scope.controller = "ModalDelete";
    $scope.booking = booking;
    $scope.confirmDelete = function() {
      AlertService.clear();
      return $modalInstance.close(booking);
    };
    return $scope.cancel = function() {
      return $modalInstance.dismiss("cancel");
    };
  };

  ModalDeleteAll = function($scope, $rootScope, $modalInstance, purchase) {
    $scope.controller = "ModalDeleteAll";
    $scope.purchase = purchase;
    $scope.confirmDelete = function() {
      return $modalInstance.close(purchase);
    };
    return $scope.cancel = function() {
      return $modalInstance.dismiss("cancel");
    };
  };

}).call(this);

(function() {
  'use strict';
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("Purchase.BookingModel", function($q, $window, BBModel, BaseModel, $bbug) {
    var Purchase_Booking;
    return Purchase_Booking = (function(superClass) {
      extend(Purchase_Booking, superClass);

      function Purchase_Booking(data) {
        this.getSurveyAnswersPromise = bind(this.getSurveyAnswersPromise, this);
        this.getAnswersPromise = bind(this.getAnswersPromise, this);
        Purchase_Booking.__super__.constructor.call(this, data);
        this.ready = false;
        this.datetime = moment.parseZone(this.datetime);
        if (this.time_zone) {
          this.datetime.tz(this.time_zone);
        }
        this.original_datetime = moment(this.datetime);
        this.end_datetime = moment.parseZone(this.end_datetime);
        if (this.time_zone) {
          this.end_datetime.tz(this.time_zone);
        }
        this.min_cancellation_time = moment(this.min_cancellation_time);
        this.min_cancellation_hours = this.datetime.diff(this.min_cancellation_time, 'hours');
      }

      Purchase_Booking.prototype.getGroup = function() {
        if (this.group) {
          return this.group;
        }
        if (this._data.$has('event_groups')) {
          return this._data.$get('event_groups').then((function(_this) {
            return function(group) {
              _this.group = group;
              return _this.group;
            };
          })(this));
        }
      };

      Purchase_Booking.prototype.getColour = function() {
        if (this.getGroup()) {
          return this.getGroup().colour;
        } else {
          return "#FFFFFF";
        }
      };

      Purchase_Booking.prototype.getCompany = function() {
        if (this.company) {
          return this.company;
        }
        if (this.$has('company')) {
          return this._data.$get('company').then((function(_this) {
            return function(company) {
              _this.company = new BBModel.Company(company);
              return _this.company;
            };
          })(this));
        }
      };

      Purchase_Booking.prototype.getAnswersPromise = function() {
        var defer;
        defer = $q.defer();
        if (this.answers != null) {
          defer.resolve(this.answers);
        } else {
          this.answers = [];
          if (this._data.$has('answers')) {
            this._data.$get('answers').then((function(_this) {
              return function(answers) {
                var a;
                _this.answers = (function() {
                  var i, len, results;
                  results = [];
                  for (i = 0, len = answers.length; i < len; i++) {
                    a = answers[i];
                    results.push(new BBModel.Answer(a));
                  }
                  return results;
                })();
                return defer.resolve(_this.answers);
              };
            })(this));
          } else {
            defer.resolve([]);
          }
        }
        return defer.promise;
      };

      Purchase_Booking.prototype.getSurveyAnswersPromise = function() {
        var defer;
        defer = $q.defer();
        if (this.survey_answers) {
          defer.resolve(this.survey_answers);
        }
        if (this._data.$has('survey_answers')) {
          this._data.$get('survey_answers').then((function(_this) {
            return function(survey_answers) {
              var a;
              _this.survey_answers = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = survey_answers.length; i < len; i++) {
                  a = survey_answers[i];
                  results.push(new BBModel.Answer(a));
                }
                return results;
              })();
              return defer.resolve(_this.survey_answers);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Booking.prototype.answer = function(q) {
        var a, i, len, ref;
        if (this.answers != null) {
          ref = this.answers;
          for (i = 0, len = ref.length; i < len; i++) {
            a = ref[i];
            if (a.name && a.name === q) {
              return a.answer;
            }
            if (a.question_text && a.question_text === q) {
              return a.value;
            }
          }
        } else {
          this.getAnswersPromise();
        }
        return null;
      };

      Purchase_Booking.prototype.getPostData = function() {
        var data, formatted_survey_answers, i, len, q, ref;
        data = {};
        data.attended = this.attended;
        data.client_id = this.client_id;
        data.company_id = this.company_id;
        data.time = (this.datetime.hour() * 60) + this.datetime.minute();
        data.date = this.datetime.toISODate();
        data.deleted = this.deleted;
        data.describe = this.describe;
        data.duration = this.duration;
        data.end_datetime = this.end_datetime;
        if (this.time && this.time.event_id && !this.isEvent()) {
          data.event_id = this.time.event_id;
        } else if (this.event) {
          data.event_id = this.event.id;
        } else {
          data.event_id = this.slot_id;
        }
        data.full_describe = this.full_describe;
        data.id = this.id;
        data.min_cancellation_time = this.min_cancellation_time;
        data.on_waitlist = this.on_waitlist;
        data.paid = this.paid;
        data.person_name = this.person_name;
        data.price = this.price;
        data.purchase_id = this.purchase_id;
        data.purchase_ref = this.purchase_ref;
        data.quantity = this.quantity;
        data.self = this.self;
        if (this.move_item_id) {
          data.move_item_id = this.move_item_id;
        }
        if (this.srcBooking) {
          data.move_item_id = this.srcBooking.id;
        }
        if (this.person) {
          data.person_id = this.person.id;
        }
        if (this.service) {
          data.service_id = this.service.id;
        }
        if (this.resource) {
          data.resource_id = this.resource.id;
        }
        if (this.item_details) {
          data.questions = this.item_details.getPostData();
        }
        data.service_name = this.service_name;
        data.settings = this.settings;
        if (this.status) {
          data.status = this.status;
        }
        if (this.email != null) {
          data.email = this.email;
        }
        if (this.email_admin != null) {
          data.email_admin = this.email_admin;
        }
        if (this.first_name) {
          data.first_name = this.first_name;
        }
        if (this.last_name) {
          data.last_name = this.last_name;
        }
        formatted_survey_answers = [];
        if (this.survey_questions) {
          data.survey_questions = this.survey_questions;
          ref = this.survey_questions;
          for (i = 0, len = ref.length; i < len; i++) {
            q = ref[i];
            formatted_survey_answers.push({
              value: q.answer,
              outcome: q.outcome,
              detail_type_id: q.id,
              price: q.price
            });
          }
          data.survey_answers = formatted_survey_answers;
        }
        return data;
      };

      Purchase_Booking.prototype.checkReady = function() {
        if (this.datetime && this.id && this.purchase_ref) {
          return this.ready = true;
        }
      };

      Purchase_Booking.prototype.printed_price = function() {
        if (parseFloat(this.price) % 1 === 0) {
          return "£" + parseInt(this.price);
        }
        return $window.sprintf("£%.2f", parseFloat(this.price));
      };

      Purchase_Booking.prototype.getDateString = function() {
        return this.datetime.toISODate();
      };

      Purchase_Booking.prototype.getTimeInMins = function() {
        return (this.datetime.hour() * 60) + this.datetime.minute();
      };

      Purchase_Booking.prototype.getAttachments = function() {
        if (this.attachments) {
          return this.attachments;
        }
        if (this.$has('attachments')) {
          return this._data.$get('attachments').then((function(_this) {
            return function(atts) {
              _this.attachments = atts.attachments;
              return _this.attachments;
            };
          })(this));
        }
      };

      Purchase_Booking.prototype.canCancel = function() {
        return moment(this.min_cancellation_time).isAfter(moment());
      };

      Purchase_Booking.prototype.canMove = function() {
        return this.canCancel();
      };

      Purchase_Booking.prototype.getAttendeeName = function() {
        return this.first_name + " " + this.last_name;
      };

      Purchase_Booking.prototype.isEvent = function() {
        return this.event_chain != null;
      };

      return Purchase_Booking;

    })(BaseModel);
  });

}).call(this);

(function() {
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("Purchase.CourseBookingModel", function($q, BBModel, BaseModel) {
    var Purchase_Course_Booking;
    return Purchase_Course_Booking = (function(superClass) {
      extend(Purchase_Course_Booking, superClass);

      function Purchase_Course_Booking(data) {
        this.getBookings = bind(this.getBookings, this);
        Purchase_Course_Booking.__super__.constructor.call(this, data);
      }

      Purchase_Course_Booking.prototype.getBookings = function() {
        var defer;
        defer = $q.defer();
        if (this.bookings) {
          defer.resolve(this.bookings);
        }
        if (this._data.$has('bookings')) {
          this._data.$get('bookings').then((function(_this) {
            return function(bookings) {
              var b;
              _this.bookings = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = bookings.length; i < len; i++) {
                  b = bookings[i];
                  results.push(new BBModel.Purchase.Booking(b));
                }
                return results;
              })();
              _this.bookings.sort(function(a, b) {
                return a.datetime.unix() - b.datetime.unix();
              });
              return defer.resolve(_this.bookings);
            };
          })(this));
        } else {
          this.bookings = [];
          defer.resolve(this.bookings);
        }
        return defer.promise;
      };

      return Purchase_Course_Booking;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  var bind = function(fn, me){ return function(){ return fn.apply(me, arguments); }; },
    extend = function(child, parent) { for (var key in parent) { if (hasProp.call(parent, key)) child[key] = parent[key]; } function ctor() { this.constructor = child; } ctor.prototype = parent.prototype; child.prototype = new ctor(); child.__super__ = parent.prototype; return child; },
    hasProp = {}.hasOwnProperty;

  angular.module('BB.Models').factory("Purchase.TotalModel", function($q, $window, BBModel, BaseModel, $sce) {
    var Purchase_Total;
    return Purchase_Total = (function(superClass) {
      extend(Purchase_Total, superClass);

      function Purchase_Total(data) {
        this.getConfirmMessages = bind(this.getConfirmMessages, this);
        this.getMember = bind(this.getMember, this);
        this.getClient = bind(this.getClient, this);
        this.getMessages = bind(this.getMessages, this);
        this.getDeals = bind(this.getDeals, this);
        this.getProducts = bind(this.getProducts, this);
        this.getPackages = bind(this.getPackages, this);
        this.getCourseBookingsPromise = bind(this.getCourseBookingsPromise, this);
        this.getBookingsPromise = bind(this.getBookingsPromise, this);
        this.getItems = bind(this.getItems, this);
        Purchase_Total.__super__.constructor.call(this, data);
        this.getItems().then((function(_this) {
          return function(items) {
            return _this.items = items;
          };
        })(this));
        this.getClient().then((function(_this) {
          return function(client) {
            return _this.client = client;
          };
        })(this));
        this.getMember().then((function(_this) {
          return function(member) {
            return _this.member = member;
          };
        })(this));
      }

      Purchase_Total.prototype.id = function() {
        return this.get('id');
      };

      Purchase_Total.prototype.icalLink = function() {
        return this._data.$href('ical');
      };

      Purchase_Total.prototype.webcalLink = function() {
        return this._data.$href('ical');
      };

      Purchase_Total.prototype.gcalLink = function() {
        return this._data.$href('gcal');
      };

      Purchase_Total.prototype.getItems = function() {
        var defer;
        defer = $q.defer();
        if (this.items) {
          defer.resolve(this.items);
        }
        $q.all([this.getBookingsPromise(), this.getCourseBookingsPromise(), this.getPackages(), this.getProducts(), this.getDeals()]).then(function(result) {
          var items;
          items = _.flatten(result);
          return defer.resolve(items);
        });
        return defer.promise;
      };

      Purchase_Total.prototype.getBookingsPromise = function() {
        var defer;
        defer = $q.defer();
        if (this.bookings) {
          defer.resolve(this.bookings);
        }
        if (this._data.$has('bookings')) {
          this._data.$get('bookings').then((function(_this) {
            return function(bookings) {
              var b;
              _this.bookings = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = bookings.length; i < len; i++) {
                  b = bookings[i];
                  results.push(new BBModel.Purchase.Booking(b));
                }
                return results;
              })();
              _this.bookings.sort(function(a, b) {
                return a.datetime.unix() - b.datetime.unix();
              });
              return defer.resolve(_this.bookings);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getCourseBookingsPromise = function() {
        var defer;
        defer = $q.defer();
        if (this.course_bookings) {
          defer.resolve(this.course_bookings);
        }
        if (this._data.$has('course_bookings')) {
          this._data.$get('course_bookings').then((function(_this) {
            return function(bookings) {
              var b;
              _this.course_bookings = (function() {
                var i, len, results;
                results = [];
                for (i = 0, len = bookings.length; i < len; i++) {
                  b = bookings[i];
                  results.push(new BBModel.Purchase.CourseBooking(b));
                }
                return results;
              })();
              return $q.all(_.map(_this.course_bookings, function(b) {
                return b.getBookings();
              })).then(function() {
                return defer.resolve(_this.course_bookings);
              });
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getPackages = function() {
        var defer;
        defer = $q.defer();
        if (this.packages) {
          defer.resolve(this.packages);
        }
        if (this._data.$has('packages')) {
          this._data.$get('packages').then((function(_this) {
            return function(packages) {
              _this.packages = packages;
              return defer.resolve(_this.packages);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getProducts = function() {
        var defer;
        defer = $q.defer();
        if (this.products) {
          defer.resolve(this.products);
        }
        if (this._data.$has('products')) {
          this._data.$get('products').then((function(_this) {
            return function(products) {
              _this.products = products;
              return defer.resolve(_this.products);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getDeals = function() {
        var defer;
        defer = $q.defer();
        if (this.deals) {
          defer.resolve(this.deals);
        }
        if (this._data.$has('deals')) {
          this._data.$get('deals').then((function(_this) {
            return function(deals) {
              _this.deals = deals;
              return defer.resolve(_this.deals);
            };
          })(this));
        } else {
          defer.resolve([]);
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getMessages = function(booking_texts, msg_type) {
        var bt, defer;
        defer = $q.defer();
        booking_texts = (function() {
          var i, len, results;
          results = [];
          for (i = 0, len = booking_texts.length; i < len; i++) {
            bt = booking_texts[i];
            if (bt.message_type === msg_type) {
              results.push(bt);
            }
          }
          return results;
        })();
        if (booking_texts.length === 0) {
          defer.resolve([]);
        } else {
          this.getItems().then(function(items) {
            var booking_text, i, item, j, k, len, len1, len2, msgs, ref, type;
            msgs = [];
            for (i = 0, len = booking_texts.length; i < len; i++) {
              booking_text = booking_texts[i];
              for (j = 0, len1 = items.length; j < len1; j++) {
                item = items[j];
                ref = ['company', 'person', 'resource', 'service'];
                for (k = 0, len2 = ref.length; k < len2; k++) {
                  type = ref[k];
                  if (item.$has(type) && item.$href(type) === booking_text.$href('item')) {
                    if (msgs.indexOf(booking_text.message) === -1) {
                      msgs.push(booking_text.message);
                    }
                  }
                }
              }
            }
            return defer.resolve(msgs);
          });
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getClient = function() {
        var defer;
        defer = $q.defer();
        if (this._data.$has('client')) {
          this._data.$get('client').then((function(_this) {
            return function(client) {
              _this.client = new BBModel.Client(client);
              return defer.resolve(_this.client);
            };
          })(this));
        } else {
          defer.reject('No client');
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getMember = function() {
        var defer;
        defer = $q.defer();
        if (this._data.$has('member')) {
          this._data.$get('member').then((function(_this) {
            return function(member) {
              _this.member = new BBModel.Member.Member(member);
              return defer.resolve(_this.member);
            };
          })(this));
        } else {
          defer.reject('No member');
        }
        return defer.promise;
      };

      Purchase_Total.prototype.getConfirmMessages = function() {
        var defer;
        defer = $q.defer();
        if (this._data.$has('confirm_messages')) {
          this._data.$get('confirm_messages').then((function(_this) {
            return function(msgs) {
              return _this.getMessages(msgs, 'Confirm').then(function(filtered_msgs) {
                return defer.resolve(filtered_msgs);
              });
            };
          })(this));
        } else {
          defer.reject('no messages');
        }
        return defer.promise;
      };

      Purchase_Total.prototype.printed_total_price = function() {
        if (parseFloat(this.total_price) % 1 === 0) {
          return "£" + parseInt(this.total_price);
        }
        return $window.sprintf("£%.2f", parseFloat(this.total_price));
      };

      Purchase_Total.prototype.newPaymentUrl = function() {
        if (this._data.$has('new_payment')) {
          return $sce.trustAsResourceUrl(this._data.$href('new_payment'));
        }
      };

      Purchase_Total.prototype.totalDuration = function() {
        var duration, i, item, len, ref;
        duration = 0;
        ref = this.items;
        for (i = 0, len = ref.length; i < len; i++) {
          item = ref[i];
          if (item.duration) {
            duration += item.duration;
          }
        }
        return duration;
      };

      Purchase_Total.prototype.containsWaitlistItems = function() {
        var i, item, len, ref, waitlist;
        waitlist = [];
        ref = this.items;
        for (i = 0, len = ref.length; i < len; i++) {
          item = ref[i];
          if (item.on_waitlist === true) {
            waitlist.push(item);
          }
        }
        if (waitlist.length > 0) {
          return true;
        } else {
          return false;
        }
      };

      return Purchase_Total;

    })(BaseModel);
  });

}).call(this);

(function() {
  'use strict';
  angular.module('BB.Services').factory("PurchaseBookingService", function($q, halClient, BBModel) {
    return {
      update: function(booking) {
        var data, deferred;
        deferred = $q.defer();
        data = booking.getPostData();
        booking.srcBooking.$put('self', {}, data).then((function(_this) {
          return function(booking) {
            return deferred.resolve(new BBModel.Purchase.Booking(booking));
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err, new BBModel.Purchase.Booking(booking));
          };
        })(this));
        return deferred.promise;
      },
      addSurveyAnswersToBooking: function(booking) {
        var data, deferred;
        deferred = $q.defer();
        data = booking.getPostData();
        data.notify = false;
        data.notify_admin = false;
        booking.$put('self', {}, data).then((function(_this) {
          return function(booking) {
            return deferred.resolve(new BBModel.Purchase.Booking(booking));
          };
        })(this), (function(_this) {
          return function(err) {
            return deferred.reject(err, new BBModel.Purchase.Booking(booking));
          };
        })(this));
        return deferred.promise;
      }
    };
  });

}).call(this);

(function() {
  angular.module('BB.Services').factory("PurchaseService", function($q, halClient, BBModel, $window, UriTemplate) {
    return {
      query: function(params) {
        var defer, uri;
        defer = $q.defer();
        uri = params.url_root + "/api/v1/purchases/" + params.purchase_id;
        halClient.$get(uri, params).then(function(purchase) {
          purchase = new BBModel.Purchase.Total(purchase);
          return defer.resolve(purchase);
        }, function(err) {
          return defer.reject(err);
        });
        return defer.promise;
      },
      bookingRefQuery: function(params) {
        var defer, uri;
        defer = $q.defer();
        uri = new UriTemplate(params.url_root + "/api/v1/purchases/booking_ref/{booking_ref}{?raw}").fillFromObject(params);
        halClient.$get(uri, params).then(function(purchase) {
          purchase = new BBModel.Purchase.Total(purchase);
          return defer.resolve(purchase);
        }, function(err) {
          return defer.reject(err);
        });
        return defer.promise;
      },
      update: function(params) {
        var bdata, booking, data, defer, i, len, ref;
        defer = $q.defer();
        if (!params.purchase) {
          defer.reject("No purchase present");
          return defer.promise;
        }
        data = {};
        if (params.bookings) {
          bdata = [];
          ref = params.bookings;
          for (i = 0, len = ref.length; i < len; i++) {
            booking = ref[i];
            bdata.push(booking.getPostData());
          }
          data.bookings = bdata;
        }
        params.purchase.$put('self', {}, data).then((function(_this) {
          return function(purchase) {
            purchase = new BBModel.Purchase.Total(purchase);
            return defer.resolve(purchase);
          };
        })(this), (function(_this) {
          return function(err) {
            return defer.reject(err);
          };
        })(this));
        return defer.promise;
      },
      bookWaitlistItem: function(params) {
        var data, defer;
        defer = $q.defer();
        if (!params.purchase) {
          defer.reject("No purchase present");
          return defer.promise;
        }
        data = {};
        if (params.booking) {
          data.booking = params.booking.getPostData();
        }
        data.booking_id = data.booking.id;
        params.purchase.$put('book_waitlist_item', {}, data).then((function(_this) {
          return function(purchase) {
            purchase = new BBModel.Purchase.Total(purchase);
            return defer.resolve(purchase);
          };
        })(this), (function(_this) {
          return function(err) {
            return defer.reject(err);
          };
        })(this));
        return defer.promise;
      },
      deleteAll: function(purchase) {
        var defer;
        defer = $q.defer();
        if (!purchase) {
          defer.reject("No purchase present");
          return defer.promise;
        }
        purchase.$del('self').then(function(purchase) {
          purchase = new BBModel.Purchase.Total(purchase);
          return defer.resolve(purchase);
        }, (function(_this) {
          return function(err) {
            return defer.reject(err);
          };
        })(this));
        return defer.promise;
      },
      delete_item: function(params) {
        var defer, uri;
        defer = $q.defer();
        uri = params.api_url + "/api/v1/purchases/" + params.long_id + "/purchase_item/" + params.purchase_item_id;
        halClient.$del(uri, {}).then(function(purchase) {
          purchase = new BBModel.Purchase.Total(purchase);
          return defer.resolve(purchase);
        }, function(err) {
          return defer.reject(err);
        });
        return defer.promise;
      }
    };
  });

}).call(this);
