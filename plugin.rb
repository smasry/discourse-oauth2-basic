# name: discourse-oauth2-basic
# about: Generic OAuth2 Plugin
# version: 0.2
# authors: Robin Ward, Samer Masry
# url: https://github.com/smasry/discourse-oauth2-basic.git

require_dependency 'auth/oauth2_authenticator.rb'
enabled_site_setting :oauth2_enabled

class ::OmniAuth::Strategies::Oauth2Basic < ::OmniAuth::Strategies::OAuth2
  option :name, "oauth2_basic"
  info do
    {
      id: access_token['id']
    }
  end
end

class OAuth2BasicAuthenticator < ::Auth::OAuth2Authenticator
  def register_middleware(omniauth)
    omniauth.provider :oauth2_basic,
                      name: 'oauth2_basic',
                      setup: lambda {|env|
                        opts = env['omniauth.strategy'].options
                        opts[:client_id] = SiteSetting.oauth2_client_id
                        opts[:client_secret] = SiteSetting.oauth2_client_secret
                        opts[:provider_ignores_state] = true

                        subdomain = CGI::parse(env['REQUEST_URI'])['subdomain'].first
                        token_url = SiteSetting.oauth2_token_url
                        token_url = SiteSetting.oauth2_token_url.gsub('app', subdomain) if subdomain
                        opts[:client_options] = {
                          authorize_url: SiteSetting.oauth2_authorize_url,
                          token_url: token_url
                        }
                        opts[:authorize_options] = SiteSetting.oauth2_authorize_options.split("|").map(&:to_sym)
                        opts[:token_params][:redirect_uri] = SiteSetting.oauth2_redirect_uri unless SiteSetting.oauth2_redirect_uri.blank?

                        if SiteSetting.oauth2_send_auth_header?
                          opts[:token_params] = {headers: {'Authorization' => basic_auth_header }}
                        end
                      }
  end

  def basic_auth_header
    "Basic " + Base64.strict_encode64("#{SiteSetting.oauth2_client_id}:#{SiteSetting.oauth2_client_secret}")
  end

  def walk_path(fragment, segments)
    first_seg = segments[0]
    return if first_seg.blank? || fragment.blank?
    return nil unless fragment.is_a?(Hash)
    deref = fragment[first_seg] || fragment[first_seg.to_sym]

    return (deref.blank? || segments.size == 1) ? deref : walk_path(deref, segments[1..-1])
  end

  def json_walk(result, user_json, prop)
    path = SiteSetting.send("oauth2_json_#{prop}_path")
    if path.present?
      segments = path.split('.')
      val = walk_path(user_json, segments)
      result[prop] = val if val.present?
    end
  end

  def log(info)
    Rails.logger.warn("OAuth2 Debugging: #{info}") if SiteSetting.oauth2_debug_auth
  end

  def fetch_user_details(auth_result, token, id)
    user_json_url = SiteSetting.oauth2_user_json_url.sub(':token', token.to_s).sub(':id', id.to_s)

    log("user_json_url: #{user_json_url}")

    response = Excon.get(
      user_json_url,
      headers: {
        "Authorization" => "Bearer #{token}",
        'Accept' => SiteSetting.oauth2_token_accept
      }
    )

    status = response.status

    if status != 200
      auth_result.failed = true

      if status == 401
        auth_result.failed_reason = JSON.parse(response.body)['error']['message']
      else
        auth_result.failed_reason = "Unkown Error occured"
      end
    end

    return auth_result if auth_result.failed?

    user_json = JSON.parse(response.body)

    log("user_json: #{user_json}")

    result = {}
    if user_json.present?
      json_walk(result, user_json, :user_id)
      json_walk(result, user_json, :username)
      json_walk(result, user_json, :name)
      json_walk(result, user_json, :email)
    end
    result
  end

  def after_authenticate(auth)
    log("after_authenticate response: \n\ncreds: #{auth['credentials'].to_hash}\ninfo: #{auth['info'].to_hash}\nextra: #{auth['extra'].to_hash}")

    result = Auth::Result.new
    token = auth['credentials']['token']
    user_details = fetch_user_details(result, token, auth['info'][:id])

    return result if result.failed?

    user_md5_hash = Digest::MD5.hexdigest(user_details[:email])

    result.name = user_details[:name]
    result.username = username_suggestion(user_details[:name])
    result.email = user_details[:email]
    result.email_valid = result.email.present? && SiteSetting.oauth2_email_verified?

    current_info = ::PluginStore.get("oauth2_basic", "oauth2_basic_user_#{user_md5_hash}")
    if current_info
      result.user = User.where(id: current_info[:user_id]).first
    elsif SiteSetting.oauth2_email_verified?
      result.user = User.find_by_email(result.email)
      if result.user && user_details[:email]
        ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{user_md5_hash}", {user_id: result.user.id})
      end
    end

    result.extra_data = { oauth2_basic_user_email_hash: user_md5_hash }
    result
  end

  def after_create_account(user, auth)
    ::PluginStore.set("oauth2_basic", "oauth2_basic_user_#{auth[:extra_data][:oauth2_basic_user_email_hash]}", {user_id: user.id })
  end

  def username_suggestion(name)
    prefix = name.camelcase.gsub(/[^A-Za-z]/, '')
    return prefix unless User.exists?(username: prefix)

    4.times do
      username = "#{prefix}#{rand(1000)}"
      return username unless User.exists?(username: username)
    end
    return ''
  end
end

auth_provider title_setting: "oauth2_button_title",
              enabled_setting: "oauth2_enabled",
              authenticator: OAuth2BasicAuthenticator.new('oauth2_basic'),
              message: "OAuth2"

register_css <<CSS

  button.btn-social.oauth2_basic {
    background-color: #6d6d6d;
  }

CSS
