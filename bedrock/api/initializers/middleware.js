var OAuth = require('oauth');
var crypto = require('crypto');
var salt = "asdjkafhjewiovnjksdv" // in production, you will want to change this, and probably have a unique salt for each user.
var request = require('request');

exports.middleware = function(api, next) {
  
  // Simple Authentication Middleware
  var authPreProcessor = function(connection, actionTemplate, next) {
    if (actionTemplate.authenticated !== true) {
      api.log("No authorization needed for action '" + actionTemplate.name + "'", 'info', {connectionId: connection.id});
      next(connection, true);
      return;
    }
    var headers = connection.rawConnection.req.headers;
    var apiKeyHash = headers['x-bedrock-api-key-hash'] || "undefined";
    var clientId = headers['x-bedrock-client-id'] || "undefined";
    var token = headers['x-bedrock-token'] || "undefined";
    if (apiKeyHash === "undefined") {
      connection.rawConnection.responseHttpCode = 401;
      connection.error = api.config.errors.missingHeaders(["x-bedrock-api-key-hash"]);
      next(connection, false);
      return;
    }
    if (clientId === "undefined") {
      connection.rawConnection.responseHttpCode = 401;
      connection.error = api.config.errors.missingHeaders(["x-bedrock-client-id"]);
      next(connection, false);
      return;
    }
    if (token === "undefined") {
      connection.rawConnection.responseHttpCode = 401;
      connection.error = api.config.errors.missingHeaders(["x-bedrock-token"]);
      next(connection, false);
      return;
    }
    var tokenCacheKey = "token::" + apiKeyHash;
    api.cache.load(tokenCacheKey, function(err, resp, expireTimestamp, createdAt, readAt) {
      if (!err) {
        api.log("Found token in cache, validating it now.", 'info', {connectionId: connection.id});
        var now = (new Date()).getTime();
        if (token !== resp.token || expireTimestamp < now) {
          api.log("Token expired or invalid.", 'error', {connectionId: connection.id});
          connection.rawConnection.responseHttpCode = 401;
          connection.error = api.config.errors.invalidToken();
          next(connection, false);
          return;
        }
        next(connection, true);
      } else {
        api.log("Error while trying to validate token from cache.", 'error', {err: err, connectionId: connection.id});
        connection.rawConnection.responseHttpCode = 401;
        connection.error = api.config.errors.invalidToken();
        next(connection, false);
      }
    });
  };

  // Simple Authentication Middleware
  var intlPreProcessor = function(connection, actionTemplate, next) {
    if (!actionTemplate.intlSupport) {
      next(connection, true);
      return;
    }
    var lang = connection.params.lang ? connection.params.lang : "en";
    if (!actionTemplate.providers) {
      next(connection, true);
      return;
    }
    if (!isValidLang(connection, actionTemplate, next, lang)) {
      connection.error = api.config.errors.unsupportedParamValue(["lang"]);
      next(connection, false);
      return;
    }
    next(connection, true);
  };

  var cachePreProcessor = function(connection, actionTemplate, next) {
    if (actionTemplate.useCache !== true) {
      api.log("No caching needed for action '" + actionTemplate.name + "'", 'info', {key: key, connectionId: connection.id});
      next(connection, true);
      return;
    }
    var key = actionTemplate.cacheKey ? actionTemplate.cacheKey(api, connection, next) : null;
    if (key == null) {
      api.log("Null cache key, ignoring cache load...", 'info', {key: key, connectionId: connection.id});
      next(connection, true);
      return;
    }

    api.log("Checking if data exists in cache", 'info', {key: key, connectionId: connection.id});
    api.cache.load(key, function(err, resp, expireTimestamp, createdAt, readAt) {
      if (!err && resp && resp != null) {
        api.log("Found in cache", 'debug', {key: key, expireTimestamp: expireTimestamp, createdAt: createdAt, readAt: readAt, connectionId: connection.id});
        connection.response.meta = {
          cache: {
            expiresAt: expireTimestamp,
            createdAt: createdAt,
            readAt: readAt
          },
          hashChanged: true
        };

        // Check to see if data-hash is passed in, 
        // if the data-hash matches don't send the entire payload again, 
        // instead simply notify the client that the data is unchanged and that the client has the latest updated copy of the data 
        var headers = connection.rawConnection.req.headers;
        var dataHash = headers['x-bedrock-data-hash'] || "undefined";
        if (dataHash !== "undefined" && dataHash.length > 0 && resp.hash === dataHash) {
          connection.response.meta.hashChanged = false;
          next(connection, false);
          return;
        } else {
          // Return entire cached payload 
          connection.response.data = resp;
          next(connection, false);
        }
      } else {
        api.log("Not found in cache", 'debug', {key: key, err: err, resp: resp, expireTimestamp: expireTimestamp, createdAt: createdAt, readAt: readAt, connectionId: connection.id});
        next(connection, true);    
      }
    });
  };

  var cachePostProcessor = function(connection, actionTemplate, toRender, next) {
    if (actionTemplate.useCache !== true) {
      api.log("No caching needed for action '" + actionTemplate.name + "'", 'info', {key: key, connectionId: connection.id});
      next(connection, toRender);
      return;
    } 
    if (connection.error) {
      api.log("Error occurred, no need to update cache.'" + actionTemplate.name + "'", 'info', {key: key, connectionId: connection.id});
      next(connection, toRender);
      return;
    }
    
    var key = actionTemplate.cacheKey ? actionTemplate.cacheKey(api, connection, next) : null;
    var value = connection.response.data;
    var expiryMs = actionTemplate.cacheExpiryMs ? actionTemplate.cacheExpiryMs : api.config.redis.cacheExpiryMs;
    api.log("Checking if cache needs to be updated", 'info', {key: key, connectionId: connection.id});
    
    api.cache.load(key, function(err, resp, expireTimestamp, createdAt, readAt) {
      var now = (new Date()).getTime();
      if (resp != null && expireTimestamp > now) {
        // Found in cache, cache is valid.
        var cacheValidSec = Math.round((expireTimestamp - now)/(1000));
        api.log("Already in cache and cache is valid for " + cacheValidSec + " more sec. No need to update cache yet.", 'info', {key: key, expireTimestamp: expireTimestamp, now: now, connectionId: connection.id});
        next(connection, toRender);
      } else {
        // Not found in cache or cache expired. Update cache with new value
        api.log("Not found in cache or cache expired. Updating cache with new value.", 'info', {key: key, connectionId: connection.id});
        var data = JSON.stringify(value);
        var hashAlgorithm = crypto.createHash('md5');
        hashAlgorithm.update(data);
        var hash = hashAlgorithm.digest('hex');
        value.hash = hash;
        api.log("Adding to cache...", 'info', {key: key, connectionId: connection.id});
        api.cache.save(key, value, expiryMs, function(err, resp) {
          api.log("Added to cache...", 'info', {key: key, value: value, expiryMs: expiryMs, err: err, resp: resp, connectionId: connection.id});
          connection.response.meta = {
            cache: {
              expiresAt: now + expiryMs,
              createdAt: now,
              readAt: null
            }
          };
          next(connection, toRender);
        });
      }
    });
    
  };

  var oAuthPreProcessor = function(connection, actionTemplate, next) {
    if (actionTemplate.useOAuth !== true) {
      api.log("No oAuth token needed for action '" + actionTemplate.name + "'", 'info', {connectionId: connection.id});
      next(connection, true);
      return;
    }
    var bypassOAuth = connection.params.bypassOAuth || false;
    if (bypassOAuth) {
      api.log("Bypassing oAuth, client doesn't want to use oAuth for action '" + actionTemplate.name + "'", 'info', {connectionId: connection.id});
      next(connection, true);
      return;
    }
    var provider = connection.params.provider ? connection.params.provider : actionTemplate.providers.default;
    if (actionTemplate.providers.sources.indexOf(provider) == -1) {
      api.log("Invalid provider supplied: '" + provider + "', defaulting to provider '" + actionTemplate.providers.default + "' for action " + actionTemplate.name + "'", 'warning', {connectionId: connection.id});
      connection.error = api.config.errors.unsupportedProvider([provider]);
      next(connection, true);
      return null;
    } 
    var oAuthVersion = api.config.thirdparty[provider].oAuthVersion;
    if (oAuthVersion == "1.0A" || oAuthVersion == "1") {
      oAuth1PreProcessor(connection, actionTemplate, next);
    } else if (oAuthVersion == "2") {
      oAuth2PreProcessor(connection, actionTemplate, next);
    } else {
      connection.error = api.config.errors.invalidOAuthVersionForProvider([provider]);
      next(connection, true);
      return null;
    }
  };

  var oAuth1PreProcessor = function(connection, actionTemplate, next) {
    var provider = connection.params.provider ? connection.params.provider : actionTemplate.providers.default;
    var OAuth1 = OAuth.OAuth1;
    var consumerKey = api.config.thirdparty[provider].oAuthConsumerKey;
    var consumerSecret = api.config.thirdparty[provider].oAuthConsumerSecret;
    var baseSite = api.config.thirdparty[provider].oAuthBaseSite;
    var authorizePath = api.config.thirdparty[provider].oAuthAuthorizePath;
    var accessTokenPath = api.config.thirdparty[provider].oAuthAccessTokenPath;
    var requestTokenPath = api.config.thirdparty[provider].oAuthRequestTokenPath;
    var signatureMethod = api.config.thirdparty[provider].oAuthSignatureMethod;
    var nativeCallback = api.config.thirdparty[provider].oAuthNativeCallback;
    var oAuthVersion = api.config.thirdparty[provider].oAuthVersion;
    api.log("Fetching oAuth1 token for action '" + actionTemplate.name + "'", 'info', {action: actionTemplate.name, provider: provider, url: baseSite + accessTokenPath, connectionId: connection.id});
    // OAuth.OAuth(requestUrl, accessUrl, consumerKey, consumerSecret, version, authorize_callback, signatureMethod, nonceSize, customHeaders)
    var oauth1 = new OAuth.OAuth(baseSite + requestTokenPath, baseSite + accessTokenPath, consumerKey, consumerSecret,
      oAuthVersion, nativeCallback, signatureMethod
    );

    var access_token = connection.params.oauth_access_token || "undefined";
    if (access_token == "undefined") {
      // No access token, fetch a new one 
      oauth1.getOAuthRequestToken({}, function(err, oauth_token, oauth_token_secret, results) {
        if (err) {
          connection.error = api.config.errors.providerError();
          connection.error.provider = err;
          next(connection, true);
        }
        api.log("getOAuth1RequestToken '", 'info', {action: actionTemplate.name, provider: provider, err: err, oauth_token: oauth_token, oauth_token_secret: oauth_token_secret, results: results, connectionId: connection.id});
        var oauth_verifier = connection.params.oauth_verifier || "undefined";
        if (oauth_verifier == "undefined") {
          // No verifier found 
          connection.response.data = {
            oauth: {
              oauth_authorize_url: baseSite + authorizePath + "?oauth_token=" + oauth_token,
              oauth_version: oAuthVersion
            }
          }
          next(connection, false);
          return;
        } else {
          var oauth_token = connection.params.oauth_token || "undefined";
          oauth1.getOAuthAccessToken(oauth_token, oauth_token_secret, oauth_verifier,  
            function(err2, oauth_token2, oauth_token_secret2, results2) {
              console.log("GOT Access token", err2, oauth_token2, oauth_token_secret2, results2);
              if (err2) {
                connection.error = api.config.errors.providerError();
                connection.error.provider = err2;
                next(connection, true);
              } else {
                connection.response.oauth = {
                  oauth_access_token: oauth_token2, 
                  oauth_results: results2
                };
                var obj = {
                  secret: oauth_token_secret2,
                  results: results2
                };
                api.cache.save("twitter::" + oauth_token2, obj, null, function(err, resp) {
                  next(connection, true);
                });
              }
            }
          );
        }
      });
    } else {
      // Access token available, use it
      api.log("USING existing Access token", 'info', {access_token: access_token, connectionId: connection.id});
      connection.response.oauth = {
        oauth_access_token: access_token
      };
      next(connection, true);
    }
    
  };

  var oAuth2PreProcessor = function(connection, actionTemplate, next) {
    var provider = connection.params.provider ? connection.params.provider : actionTemplate.providers.default;
    var OAuth2 = OAuth.OAuth2;
    var consumerKey = api.config.thirdparty[provider].oAuthConsumerKey;
    var consumerSecret = api.config.thirdparty[provider].oAuthConsumerSecret;
    var baseSite = api.config.thirdparty[provider].oAuthBaseSite;
    var authorizePath = api.config.thirdparty[provider].oAuthAuthorizePath;
    var accessTokenPath = api.config.thirdparty[provider].oAuthAccessTokenPath;
    var oauth2 = new OAuth2(consumerKey, consumerSecret, baseSite, authorizePath, accessTokenPath, null);
    var redirect_uri = api.config.thirdparty[provider].oAuthRedirectUri;
    var oAuthVersion = api.config.thirdparty[provider].oAuthVersion;
    var access_token = connection.params.oauth_access_token || "undefined";
    if (access_token == "undefined") {
      // No access token, fetch a new one 
      var providerObj = actionTemplate.providers[provider].provider;
      var params = providerObj.getOAuthParams(api);
      params.redirect_uri = redirect_uri;
      api.log("Fetching oAuth2 token for action '" + actionTemplate.name + "'", 'info', {action: actionTemplate.name, provider: provider, url: baseSite + accessTokenPath, connectionId: connection.id});
      var code = connection.params.code || "undefined";
      if (code == "undefined") {
        // No code found redirect user to auth url
        api.log("No code found redirect user to auth url", 'info', {action: actionTemplate.name, provider: provider, url: baseSite + accessTokenPath, connectionId: connection.id});
        connection.response.data = {
          oauth: {
            oauth_authorize_url: oauth2.getAuthorizeUrl(params),
            oauth_version: oAuthVersion
          }
        }
        next(connection, false);
      } else {
        oauth2.getOAuthAccessToken(code, params, 
          function (e, access_token, refresh_token, results) {
            console.log("------Error", e);
            if (e) {
              connection.error = api.config.errors.providerError();
              connection.error.provider = e;
              next(connection, true); 
            } else {
              api.log("GOT Access token", 'info', {e: e, access_token: access_token, refresh_token: refresh_token, results: results, connectionId: connection.id});
              connection.response.oauth = {
                oauth_access_token: access_token,
                oauth_version: oAuthVersion
              };
              next(connection, true);
            }
          }
        );
      }
    } else {
      // Access token available, use it
      api.log("USING existing Access token", 'info', {oauth_access_token: access_token, connectionId: connection.id});
      connection.response.oauth = {
        oauth_access_token: access_token,
        oauth_version: oAuthVersion
      };
      next(connection, true);
    }    
  };

  var isValidLang = function(connection, actionTemplate, next, lang) {
    var supportedLangs = actionTemplate.supportedLangs ? actionTemplate.supportedLangs(api, connection, next) : [];
    return supportedLangs.indexOf(lang) >= 0;
  };

  // /////////////////////
  // ADD ALL PREPROCESSORS 
  // a preProcessor to check auth credentials
  api.actions.addPreProcessor(authPreProcessor);

  // a preProcessor to check intl params
  api.actions.addPreProcessor(intlPreProcessor);

  // a preProcessor for oAuth
  api.actions.addPreProcessor(oAuthPreProcessor);
  // a preProcessor to check if data exists in cache 
  api.actions.addPreProcessor(cachePreProcessor);
  
  // //////////////////////
  // ADD ALL POSTPROCESSORS 
  // a postProcessor to put response data in cache 
  api.actions.addPostProcessor(cachePostProcessor);


  next();

};
