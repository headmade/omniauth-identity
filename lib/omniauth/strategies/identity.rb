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
        request_form
      end

      def request_form
        if options[:on_login]
          options[:on_login].call(self.env)
        else
          OmniAuth::Form.build(
            title: option_title(:request_phase),
            url: confirmation_path,
          ) do |f|
            f.text_field option_title(:login), 'login'
            f.button option_title(:sign_in)
          end.to_response
        end
      end

      def option_title(key)
        options[[key,:title].join('_').to_sym] || key.to_s.humanize
      end

      def callback_phase
        Rails.logger.debug [:callback_phase, identity, session['omniauth.env']]
        return fail!(:invalid_credentials) unless identity
        super
      end

      def other_phase
        if on_confirmation_path?
          if request.post?
            confirmation_phase
          end
        elsif on_registration_path?
          if request.post?
            registration_phase
          end
        else
          call_app!
        end
      end

      def confirmation_form(args={})
        if options[:on_confirmation]
          options[:on_confirmation].call(self.env)
        else
          OmniAuth::Form.build(
            :title => option_title(:confirmation_phase),
            :url => registration_path,
            ) do |f|
              f.text_field option_title(:password), 'password'
              f.label_field args[:error], option_title(:confirmation_error) if args[:error]
              f.button option_title(:confirm)
          end.to_response
        end
      end

      def confirmation_phase
        login = request['login']
        return request_form unless login

        attributes = {
          login: login,
        }

        Rails.logger.debug [:confirmation_phase, login, attributes, model]

        @identity = model.create(attributes)
        Rails.logger.debug [:confirmation_phase, @identity]

        if @identity.persisted?
          session['omniauth.identity_id'] = @identity.id
          confirmation_form
        end
      end

      def registration_phase
        @identity = model.find(session['omniauth.identity_id'])
        if @identity.authenticate(request['password'])
          session['omniauth.identity_id'] = nil
          env['PATH_INFO'] = callback_path
          callback_phase
        else
          if options[:on_failed_registration]
            self.env['omniauth.identity'] = @identity
            options[:on_failed_registration].call(self.env)
          else
            confirmation_form(error: 'Неверный код авторизации')
          end
        end
      end

      uid{ identity.uid }
      info{ identity.info }

      def confirmation_path
        options[:confirmation_path] || "#{path_prefix}/#{name}/confirm"
      end
      def on_confirmation_path?
        on_path?(confirmation_path)
      end
      def registration_path
        options[:registration_path] || "#{path_prefix}/#{name}/register"
      end
      def on_registration_path?
        on_path?(registration_path)
      end

      def identity
        Rails.logger.debug [:identity, request['password'], session['omniauth.identity']]
        conditions = {id: session['omniauth.identity']}
        @identity ||= model.authenticate(conditions, request['password'])
      end

      def model
        options[:model] || ::Identity
      end
    end
  end
end
