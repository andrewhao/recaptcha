require 'json'

module Recaptcha
  module Verify
    # Your private API can be specified in the +options+ hash or preferably
    # using the Configuration.
    def verify_recaptcha(options = {})
      puts "Enter verify: #{options}"
      options = {:model => options} unless options.is_a? Hash
      return true if Recaptcha::Verify.skip?(options[:env])

      model = options[:model]
      attribute = options[:attribute] || :base
      recaptcha_response = options[:response] || params['g-recaptcha-response'].to_s

      puts '**'
      puts model
      puts attribute
      puts recaptcha_response
      puts '**'

      begin
        verified = if recaptcha_response.empty?
          puts "rre"
          false
        else
          puts "not rre"
          vvac = recaptcha_verify_via_api_call(request, recaptcha_response, options)
          puts "vvac: #{vvac}"
          vvac
        end

        if verified
          puts "verified"
          flash.delete(:recaptcha_error) if recaptcha_flash_supported? && !model
          puts 'almost done'
          true
        else
          puts "notverified"
          recaptcha_error(
            model,
            attribute,
            options[:message],
            "recaptcha.errors.verification_failed",
            "reCAPTCHA verification failed, please try again."
          )
          false
        end
      rescue Timeout::Error
        if Recaptcha.configuration.handle_timeouts_gracefully
          recaptcha_error(
            model,
            attribute,
            options[:message],
            "recaptcha.errors.recaptcha_unreachable",
            "Oops, we failed to validate your reCAPTCHA response. Please try again."
          )
          false
        else
          raise RecaptchaError, "Recaptcha unreachable."
        end
      rescue StandardError => e
        raise RecaptchaError, e.message, e.backtrace
      end
    end

    def verify_recaptcha!(options = {})
      verify_recaptcha(options) or raise VerifyError
    end

    private

    def recaptcha_verify_via_api_call(request, recaptcha_response, options)
      private_key = options[:private_key] || Recaptcha.configuration.private_key!
      remote_ip = (request.respond_to?(:remote_ip) && request.remote_ip) || (env && env['REMOTE_ADDR'])

      verify_hash = {
        "secret"    => private_key,
        "remoteip"  => remote_ip.to_s,
        "response"  => recaptcha_response
      }

      reply = JSON.parse(Recaptcha.get(verify_hash, options))
      puts "reply: #{reply}"
      pt1 = reply['success'].to_s == "true"
      pt2 = recaptcha_hostname_valid?(reply['hostname'], options[:hostname])
      puts "reply is true: #{pt1}"
      puts "hostname valid: #{pt2}"
      pt1 && pt2
    end

    def recaptcha_hostname_valid?(hostname, validation)
      puts "recaptcha_hostname_valid:"
      puts hostname
      puts validation
      case validation
      when nil, FalseClass then true
      when String then validation == hostname
      else validation.call(hostname)
      end
    end

    def recaptcha_error(model, attribute, message, key, default)
      message = message || Recaptcha.i18n(key, default)
      puts "[recaptcha_error]: #{message}"
      if model
        model.errors.add attribute, message
      else
        flash[:recaptcha_error] = message if recaptcha_flash_supported?
      end
    end

    def recaptcha_flash_supported?
      request.respond_to?(:format) && request.format == :html && respond_to?(:flash)
    end

    def self.skip?(env)
      env ||= ENV['RACK_ENV'] || ENV['RAILS_ENV'] || (Rails.env if defined? Rails.env)
      Recaptcha.configuration.skip_verify_env.include? env
    end
  end
end
