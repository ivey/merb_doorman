module Merb
  module Plugins
    module Doorman
      
      def included(base)
        base.class_eval do
          before :_doorman_check_acl
        end
      end
      
      
      def _doorman_list
        @_doorman_list ||= [:all]
      end
      
      def _doorman_default
        @_doorman_default ||= :allow
      end

      def deny(*args,&block)
        _add_acl(:deny,args,block)
      end

      def allow(*args,&block)
        _add_acl(:allow,args,block)
      end
      
      protected
      def _add_acl(type,args,block)
        if args == :all
          _doorman_default = type
          return true
        end
        if _valid_acl(args)
          _doorman_list << [type,args]
        elsif block && block.arity == 1
          _doorman_list << [type,block]
        else
          raise "merb_doorman: invalid ACL entry #{args.inspect}"
        end
      end
      
      def _valid_acl(args)
        args = args.is_a?(Array) ? args.first : args
        if args.is_a?(Symbol)
          return true
        elsif args.is_a?(Hash)
          return false if args.size > 1
          return false unless args.keys.first.in? [:host, :user, :user_agent, :time]
          return true
        end
      end
      
      def _check_acl(acl)
        type,command = acl
        match = if command.is_a?(Proc)
          command.call(self)
        elsif command.is_a?(Hash)
          _check_acl_hash(command)
        end
        if type == :deny
          return !match
        else
          return match
        end
      end
      
      def _doorman_check_acl
        allowed = false
        _doorman_list.each do |acl|
          if _check_acl(acl)
            allowed = true
          else
            throw :halt, "ACL failed: #{acl}"
          end
        end
        if _doorman_default == :deny && !allowed
          throw :halt, "ACL failed: deny :all"
        end
      end
      
      def _check_acl_hash(hash)
        rule = hash.keys.first
        value = hash.values.first
        case rule.to_s
        when :host
          request.host =~ Regexp.new(value)
        when :user
          _doorman_user_block.call(self)
        when :time
          false #not implemented
        when :user_agent 
          request.user_agent =~ Regexp.new(value)
        else
          false
        end
      end
      
      def _doorman_user_block
        Merb::Plugins.config[:merb_doorman][:current_user_block]
      end
    end
  end
end


if defined?(Merb::Plugins)
  Merb::Plugins.config[:merb_doorman] = {
    :current_user_block => proc {|c| c.current_user.login }
  }
  Merb::Controller.send(:include, Merb::Plugins::Doorman)
end