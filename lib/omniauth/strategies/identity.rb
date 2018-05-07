module OmniAuth
  module Strategies
    # The identity strategy allows you to provide simple internal
    # user authentication using the same process flow that you
    # use for external OmniAuth providers.
    class Identity
      include OmniAuth::Strategy

      option :fields, [:login]
      option :on_login, nil
      option :on_registration, nil
      option :on_failed_registration, nil
      option :locate_conditions, lambda{|req| Rails.logger.debug [:locate_conditions, model, req['login']]; {model.auth_key => req['login']} }

      def request_phase
        if options[:on_login]
          options[:on_login].call(self.env)
        else
          OmniAuth::Form.build(
            :title => (options[:title] || "Sign in"),
            :url => registration_path
          ) do |f|
            f.text_field 'Login', 'login'
          end.to_response
        end
      end

      def callback_phase
        Rails.logger.debug [:callback_phase, identity, session['omniauth.env']]
        return fail!(:invalid_credentials) unless identity
        super
      end

      def other_phase
        if on_registration_path?
          if request.get?
            registration_form
          elsif request.post?
            registration_phase
          end
        else
          call_app!
        end
      end

      def registration_form
        if options[:on_registration]
          options[:on_registration].call(self.env)
        else
          OmniAuth::Form.build(
            :title => (options[:title] || "Confirm"),
            :url => callback_path
            ) do |f|
            f.text_field 'Password', 'password'
          end.to_response
        end
      end

      def registration_phase
        attributes = (options[:fields] + []).inject({}){|h,k| h[k] = request[k.to_s]; h}
        attributes[:password] = '123'
        @identity = model.create(attributes)
        Rails.logger.debug [:registration_phase, @identity]
        if @identity.persisted?
          env['PATH_INFO'] = callback_path
          callback_phase
        else
          if options[:on_failed_registration]
            self.env['omniauth.identity'] = @identity
            options[:on_failed_registration].call(self.env)
          else
            registration_form
          end
        end
      end

      uid{ identity.uid }
      info{ identity.info }

      def registration_path
        options[:registration_path] || "#{path_prefix}/#{name}/register"
      end

      def on_registration_path?
        on_path?(registration_path)
      end

      def identity
        if options.locate_conditions.is_a? Proc
          Rails.logger.debug [:request, request.params, options]
          conditions = instance_exec(request, &options.locate_conditions)
          conditions.to_hash
        else
          conditions = options.locate_conditions.to_hash
        end
        Rails.logger.debug [:identity, conditions, request['password']]
        @identity ||= model.authenticate(conditions, request['password'])
      end

      def model
        options[:model] || ::Identity
      end
    end
  end
end
