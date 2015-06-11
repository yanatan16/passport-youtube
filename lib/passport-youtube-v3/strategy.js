/**
 * Module dependencies.
 */
var util = require('util')
  , OAuth2Strategy = require('passport-oauth').OAuth2Strategy
  , InternalOAuthError = require('passport-oauth').InternalOAuthError;


/**
 * `Strategy` constructor.
 *
 * Youtube authentication strategy authenticates requests using the OAuth 2.0 protocol.
 *
 * @param {Object} options
 * @param {Function} verify
 * @api public
 */
function Strategy(options, verify) {
  options = options || {};
  options.authorizationURL = options.authorizationURL || 'https://accounts.google.com/o/oauth2/auth';
  options.tokenURL = options.tokenURL || 'https://accounts.google.com/o/oauth2/token';
  options.scope = options.scope || ['https://www.googleapis.com/auth/youtube.readonly'];

  OAuth2Strategy.call(this, options, verify);
  this.name = 'youtube';
  this._profileURL = options.profileURL || 'https://www.googleapis.com/youtube/v3/channels?part=snippet&mine=true';
}

/**
 * Inherit from `OAuth2Strategy`.
 */
util.inherits(Strategy, OAuth2Strategy);

/**
 * Retrieve user profile from Youtube.
 *
 * This function constructs a normalized profile, with the following properties:
 *
 *   - `provider`         always set to `youtube`
 *   - `id`               the user's Google Plus user ID
 *   - `username`         the user's Youtube username
 *   - `displayName`      the user's full name
 *   - `name.familyName`  the user's last name
 *   - `name.givenName`   the user's first name
 *
 * @param {String} accessToken
 * @param {Function} done
 * @api protected
 */
Strategy.prototype.userProfile = function(accessToken, done) {
  var url = this._profileURL;

  this._oauth2.getProtectedResource(url, accessToken, function (err, body, res) {

    if (err) { return done(new InternalOAuthError('failed to fetch user profile', err)); }

    try {
      var json = JSON.parse(body);

      var youtubeProfile = json.items && json.items.length && json.items[0];

      var profile = { provider: 'youtube' };

      if (youtubeProfile) {
        profile.id = youtubeProfile.id;
        profile.displayName = youtubeProfile.snippet.title;
      }

      profile._raw = body;
      profile._json = json;

      done(null, profile);
    } catch(e) {
      done(e);
    }
  });
}

Strategy.prototype._convertProfileFields = function(profileFields) {
  var map = {
    'id':          'id',
    'username':    'username',
    'displayName': 'name',
    'name':       ['last_name', 'first_name']
  };

  var fields = [];

  profileFields.forEach(function(f) {
    if (typeof map[f] === 'undefined') return;

    if (Array.isArray(map[f])) {
      Array.prototype.push.apply(fields, map[f]);
    } else {
      fields.push(map[f]);
    }
  });

  return fields.join(',');
}


/**
 * Return extra Google-specific parameters to be included in the authorization
 * request.
 *
 * @param {Object} options
 * @return {Object}
 * @api protected
 */
Strategy.prototype.authorizationParams = function (options) {
    var params = {};
    if (options.accessType) {
        params['access_type'] = options.accessType;
    }
    if (options.approvalPrompt) {
        params['approval_prompt'] = options.approvalPrompt;
    }
    if (options.prompt) {
        // This parameter is undocumented in Google's official documentation.
        // However, it was detailed by Breno de Medeiros (who works at Google) in
        // this Stack Overflow answer:
        //  http://stackoverflow.com/questions/14384354/force-google-account-chooser/14393492#14393492
        params['prompt'] = options.prompt;
    }
    if (options.loginHint) {
        // This parameter is derived from OpenID Connect, and supported by Google's
        // OAuth 2.0 endpoint.
        //   https://github.com/jaredhanson/passport-google-oauth/pull/8
        //   https://bitbucket.org/openid/connect/commits/970a95b83add
        params['login_hint'] = options.loginHint;
    }
    if (options.userID) {
        // Undocumented, but supported by Google's OAuth 2.0 endpoint.  Appears to
        // be equivalent to `login_hint`.
        params['user_id'] = options.userID;
    }
    if (options.hostedDomain || options.hd) {
        // This parameter is derived from Google's OAuth 1.0 endpoint, and (although
        // undocumented) is supported by Google's OAuth 2.0 endpoint was well.
        //   https://developers.google.com/accounts/docs/OAuth_ref
        params['hd'] = options.hostedDomain || options.hd;
    }
    if (options.display) {
        // Specify what kind of display consent screen to display to users.
        //   https://developers.google.com/accounts/docs/OpenIDConnect#authenticationuriparameters
        params['display'] = options.display;
    }
    if (options.requestVisibleActions) {
        // Space separated list of allowed app actions
        // as documented at:
        //  https://developers.google.com/+/web/app-activities/#writing_an_app_activity_using_the_google_apis_client_libraries
        //  https://developers.google.com/+/api/moment-types/
        params['request_visible_actions'] = options.requestVisibleActions;
    }
    if (options.openIDRealm) {
        // This parameter is needed when migrating users from Google's OpenID 2.0 to OAuth 2.0
        //   https://developers.google.com/accounts/docs/OpenID?hl=ja#adjust-uri
        params['openid.realm'] = options.openIDRealm;
    }
    return params;
}


/**
 * Expose `Strategy`.
 */
module.exports = Strategy;
