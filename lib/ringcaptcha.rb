require 'open-uri'
require 'net/http'
require 'json'
require 'ostruct'

module RingCaptcha
  class RingCaptchaRequestError < StandardError; end

  class RingCaptchaResponse
    extend Forwardable

    attr_reader :response

    def initialize(response)
      @json = JSON.parse(response.body)
      @datas = OpenStruct.new(as_json)
      @response = response

      self.class::PUBLIC_METHODS.each do |m|
        self.class.def_delegators :@datas, m
      end
    end

    def valid?
      status == "SUCCESS"
    end

    def as_json
      @json.select{ |k,v| self.class::PUBLIC_METHODS.include?(k.to_sym) }
    end
  end

  class RingCaptchaValidation < RingCaptchaResponse
    PUBLIC_METHODS = [:status, :message, :id, :phone, :token, :country, :service, :attempt, :pcp, :retry_in, :expires_in, :reason].freeze
  end

  class RingCaptchaVerification < RingCaptchaResponse
    PUBLIC_METHODS = [:status, :message, :id, :phone, :dialog_code, :country, :service, :geolocation, :referer].freeze
  end

  class RingCaptchaMessage < RingCaptchaResponse
    PUBLIC_METHODS = [:status, :message, :id, :phone, :message_count, :reason].freeze
  end

  class RingCaptcha
    AVAILABLE_SERVICES = [:sms, :voice].freeze

    @@rc_server     = 'api.ringcaptcha.com'
    @@user_agent    = 'ringcaptcha-ruby/1.0'

    attr_reader   :message
    attr_accessor :secure

    def initialize(app_key, secret_key)
      @app_key = app_key
      @secret_key = secret_key
      @retry_attempts = 0
      @secure = true
    end

    def secure?
      @secure
    end

    def secure=(new_value)
      @secure = new_value
    end

    def send_pin_code(phone_number, service = :sms)
      raise ArgumentError, "undefined service `#{service}', availables are: #{AVAILABLE_SERVICES.inspect}" unless AVAILABLE_SERVICES.include?(service.to_sym)
      #TODO Check parameters
      data = { secret_key: @secret_key, phone: phone_number }

      begin
        response = api_rest_call("#{@app_key}/code/#{service}", data)
      rescue => e
        @message = e.message
      end

      return RingCaptchaValidation.new(response)
    end

    def validate_pin_code(pin_code, token)
      #TODO Check parameters
      data = { secret_key: @secret_key, token: token, code: pin_code }

      begin
        response = api_rest_call("#{@app_key}/verify", data)
      rescue => e
        @message = e.message
      end

      return RingCaptchaVerification.new(response)
    end

    def send_message(phone_number, message)
      #TODO Check parameters
      data = { secret_key: @secret_key, phone: phone_number, message: message }

      begin
        response = api_rest_call("#{@app_key}/sms", data)
      rescue => e
        @message = e.message
      end

      return RingCaptchaMessage.new(response)
    end

    private

    def sanitize_data(data)
      data.each do |key,value|
        data[key] = URI::encode(value).strip unless key == :message
      end
    end

    def api_rest_call(resource, data, port = 80)
      protocol = @secure ? "https://" : "http://"
      host = @@rc_server 
      port = @secure == true ? 443 : port
      sanitize_data(data)

      uri = URI.parse("#{protocol}#{host}:#{port}/#{resource}")
      https = Net::HTTP.new(uri.host, uri.port)
      https.use_ssl = @secure
      req = Net::HTTP::Post.new(uri.path, initheader = {'User-Agent' => @@user_agent})
      req.set_form_data(data)
      res = https.request(req)

      case res
      when Net::HTTPSuccess, Net::HTTPRedirection
        res
      else
        raise RingCaptchaRequestError, 'ERROR_PROCESING_REQUEST'
      end

    end
  end
end
