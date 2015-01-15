var 
  Q = require('q')
  , inrixProvider = require('../providers/inrix')
  ;

var action = {};

/////////////////////////////////////////////////////////////////////
// metadata
action.name = 'commute';
action.description = 'Commute/route information from point A (lat_src, lon_src) to point B (lat_dest, lon_dest). Optionally specify provider using query params. Supported providers are \'inrix\'';
action.inputs = {
  'required' : ['lat_src', 'lon_src', 'lat_dest', 'lon_dest'],
  'optional' : ['provider']
};
action.blockedConnectionTypes = [];
action.outputExample = {
  "data": {
    "src": {
        "lat": "37.4292",
        "lon": "-122.1381"
    },
    "dest": {
        "lat": "39",
        "lon": "-120"
    },
    "uncongestedTravelTimeMinutes": "230",
    "travelTimeMinutes": "257",
    "abnormalityMinutes": "14",
    "averageSpeedMph": "52",
    "totalDistanceMiles": "220.4",
    "hash": "19b37775da1e3c28f9e3b448bb836df9"
  }
};
action.authenticated = true;
action.useCache = true;
action.cacheExpiryMs = 15 * 60000; // 15 minutes
action.defaultParams = {lat_src: 37.392574, lon_src: -121.936403, lat_dest: 37, lon_dest: -122};
action.pingable = true;
action.intlSupport = false;

action.providers = {
  sources: ['inrix'],
  default: 'inrix',

  // Implementation for inrix
  inrix: inrixProvider.provider.commute
};

/////////////////////////////////////////////////////////////////////
// functional
action.run = function(api, connection, next) {
  var provider = connection.params.provider || this.providers.default;
  if (this.providers.sources.indexOf(provider) == -1) {
    api.log("Invalid provider supplied: '" + provider + "', defaulting to provider '" + this.providers.default + "' for action " + action.name + "'", 'warning', {});
    provider = this.providers.default;
  } 
  this.providers[provider](api, connection, next);
};

action.cacheKey = function(api, connection, next) {
  var lat_src = Math.round(connection.params.lat_src * 1000)/1000;
  var lon_src = Math.round(connection.params.lon_src * 1000)/1000;
  var lat_dest = Math.round(connection.params.lat_dest * 1000)/1000;
  var lon_dest = Math.round(connection.params.lon_dest * 1000)/1000;
  var keys = [action.name, lat_src, lon_src, lat_dest, lon_dest];
  return keys.join('::');
};

/////////////////////////////////////////////////////////////////////
// exports
exports.action = action;
